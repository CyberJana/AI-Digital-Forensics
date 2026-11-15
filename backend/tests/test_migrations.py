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
