import sqlite3
from pathlib import Path
from uuid import uuid4

from alembic import command
from alembic.config import Config
from digital_forensics.settings import get_settings
import pytest


def test_migrations_match_models_and_forensic_records_are_append_only(
    monkeypatch, tmp_path: Path
) -> None:
    database_path = (tmp_path / "migration-test.db").as_posix()
    monkeypatch.setenv("DIGITAL_FORENSICS_DATABASE_URL", f"sqlite:///{database_path}")
    get_settings.cache_clear()
    alembic_config = Config(str(Path(__file__).parents[1] / "alembic.ini"))

    try:
        command.upgrade(alembic_config, "head")
        command.check(alembic_config)

        evidence_id = str(uuid4())
        actor_id = str(uuid4())
        case_id = str(uuid4())
        finding_id = str(uuid4())
        report_id = str(uuid4())
        timestamp = "2026-01-01T00:00:00+00:00"
        inserts = {
            "acquisition_records": (
                "INSERT INTO acquisition_records "
                "(id, evidence_id, acquired_by, acquisition_method, source_description, "
                "acquired_at, recorded_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (str(uuid4()), evidence_id, actor_id, "manual", "test", timestamp, timestamp),
            ),
            "hash_verifications": (
                "INSERT INTO hash_verifications "
                "(id, evidence_id, checked_by, submitted_sha256, matched, checked_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (str(uuid4()), evidence_id, actor_id, "a" * 64, 1, timestamp),
            ),
            "custody_events": (
                "INSERT INTO custody_events "
                "(id, evidence_id, sequence, actor_id, event_type, notes, details, "
                "previous_hash, event_hash, recorded_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    str(uuid4()),
                    evidence_id,
                    1,
                    actor_id,
                    "registered",
                    None,
                    "{}",
                    None,
                    "b" * 64,
                    timestamp,
                ),
            ),
            "case_ai_summaries": (
                "INSERT INTO case_ai_summaries "
                "(id, case_id, requested_by, provider, model_name, prompt_version, "
                "summary, summary_source_record_ids, key_points, source_snapshot, "
                "review_status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    str(uuid4()),
                    case_id,
                    actor_id,
                    "ollama",
                    "test-model",
                    "case-summary-v1",
                    "Synthetic summary",
                    '["source-id"]',
                    "[]",
                    "{}",
                    "unreviewed",
                    timestamp,
                ),
            ),
            "case_findings": (
                "INSERT INTO case_findings "
                "(id, case_id, created_by, title, narrative, source_record_ids, "
                "source_snapshot, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    finding_id,
                    case_id,
                    actor_id,
                    "Test finding",
                    "Synthetic finding",
                    '["source-id"]',
                    '{"sources":[]}',
                    timestamp,
                ),
            ),
            "finding_review_decisions": (
                "INSERT INTO finding_review_decisions "
                "(id, finding_id, reviewer_id, decision, notes, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (str(uuid4()), finding_id, actor_id, "approved", None, timestamp),
            ),
            "case_reports": (
                "INSERT INTO case_reports "
                "(id, case_id, created_by, title, body, finding_ids, source_snapshot, "
                "created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    report_id,
                    case_id,
                    actor_id,
                    "Test report",
                    "Synthetic report",
                    f'["{finding_id}"]',
                    "{}",
                    timestamp,
                ),
            ),
            "report_review_decisions": (
                "INSERT INTO report_review_decisions "
                "(id, report_id, reviewer_id, decision, notes, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (str(uuid4()), report_id, actor_id, "approved", None, timestamp),
            ),
            "audit_events": (
                "INSERT INTO audit_events "
                "(id, case_id, actor_id, action, target_type, target_id, metadata_json, "
                "occurred_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    str(uuid4()),
                    case_id,
                    actor_id,
                    "finding.created",
                    "finding",
                    finding_id,
                    "{}",
                    timestamp,
                ),
            ),
        }
        with sqlite3.connect(database_path) as connection:
            for table, (insert_sql, values) in inserts.items():
                connection.execute(insert_sql, values)
                connection.commit()
                for mutation in (
                    f"UPDATE {table} SET id = id",
                    f"DELETE FROM {table}",
                ):
                    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
                        connection.execute(mutation)
                    connection.rollback()
    finally:
        get_settings.cache_clear()
