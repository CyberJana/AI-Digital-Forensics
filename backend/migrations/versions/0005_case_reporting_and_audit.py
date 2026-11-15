"""Add immutable findings, reports, review decisions, and audit events.

Revision ID: 0005_case_reporting_and_audit
Revises: 0004_case_ai_summaries
"""
from typing import Sequence

from alembic import op
import sqlalchemy as sa

revision: str = "0005_case_reporting_and_audit"
down_revision: str | None = "0004_case_ai_summaries"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

APPEND_ONLY_TABLES = (
    "case_findings",
    "finding_review_decisions",
    "case_reports",
    "report_review_decisions",
    "audit_events",
)


def upgrade() -> None:
    op.create_table(
        "case_findings",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("case_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("created_by", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("title", sa.String(length=200), nullable=False),
        sa.Column("narrative", sa.Text(), nullable=False),
        sa.Column("source_record_ids", sa.JSON(), nullable=False),
        sa.Column("source_snapshot", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["case_id"], ["cases.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["created_by"], ["users.id"]),
    )
    op.create_index(
        "ix_case_findings_case_created_at",
        "case_findings",
        ["case_id", "created_at"],
    )

    op.create_table(
        "finding_review_decisions",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("finding_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("reviewer_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("decision", sa.String(length=16), nullable=False),
        sa.Column("notes", sa.String(length=2000), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "decision IN ('approved', 'rejected')",
            name="ck_finding_review_decision",
        ),
        sa.ForeignKeyConstraint(
            ["finding_id"], ["case_findings.id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(["reviewer_id"], ["users.id"]),
    )
    op.create_index(
        "ix_finding_review_decisions_finding_created_at",
        "finding_review_decisions",
        ["finding_id", "created_at"],
    )

    op.create_table(
        "case_reports",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("case_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("created_by", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("title", sa.String(length=200), nullable=False),
        sa.Column("body", sa.Text(), nullable=False),
        sa.Column("finding_ids", sa.JSON(), nullable=False),
        sa.Column("source_snapshot", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["case_id"], ["cases.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["created_by"], ["users.id"]),
    )
    op.create_index(
        "ix_case_reports_case_created_at",
        "case_reports",
        ["case_id", "created_at"],
    )

    op.create_table(
        "report_review_decisions",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("report_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("reviewer_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("decision", sa.String(length=16), nullable=False),
        sa.Column("notes", sa.String(length=2000), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "decision IN ('approved', 'rejected')",
            name="ck_report_review_decision",
        ),
        sa.ForeignKeyConstraint(
            ["report_id"], ["case_reports.id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(["reviewer_id"], ["users.id"]),
    )
    op.create_index(
        "ix_report_review_decisions_report_created_at",
        "report_review_decisions",
        ["report_id", "created_at"],
    )

    op.create_table(
        "audit_events",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("case_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("actor_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("action", sa.String(length=100), nullable=False),
        sa.Column("target_type", sa.String(length=64), nullable=False),
        sa.Column("target_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("metadata_json", sa.JSON(), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["case_id"], ["cases.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["actor_id"], ["users.id"]),
    )
    op.create_index(
        "ix_audit_events_case_occurred_at",
        "audit_events",
        ["case_id", "occurred_at"],
    )
    _create_append_only_triggers()


def downgrade() -> None:
    _drop_append_only_triggers()
    op.drop_index("ix_audit_events_case_occurred_at", table_name="audit_events")
    op.drop_table("audit_events")
    op.drop_index(
        "ix_report_review_decisions_report_created_at",
        table_name="report_review_decisions",
    )
    op.drop_table("report_review_decisions")
    op.drop_index("ix_case_reports_case_created_at", table_name="case_reports")
    op.drop_table("case_reports")
    op.drop_index(
        "ix_finding_review_decisions_finding_created_at",
        table_name="finding_review_decisions",
    )
    op.drop_table("finding_review_decisions")
    op.drop_index("ix_case_findings_case_created_at", table_name="case_findings")
    op.drop_table("case_findings")


def _create_append_only_triggers() -> None:
    dialect = op.get_bind().dialect.name
    if dialect == "postgresql":
        for table in APPEND_ONLY_TABLES:
            op.execute(
                f"""
                CREATE TRIGGER {table}_append_only
                BEFORE UPDATE OR DELETE ON {table}
                FOR EACH ROW EXECUTE FUNCTION prevent_forensic_record_mutation()
                """
            )
    elif dialect == "sqlite":
        for table in APPEND_ONLY_TABLES:
            op.execute(
                f"""
                CREATE TRIGGER {table}_no_update
                BEFORE UPDATE ON {table}
                BEGIN
                    SELECT RAISE(ABORT, 'forensic records are append-only');
                END
                """
            )
            op.execute(
                f"""
                CREATE TRIGGER {table}_no_delete
                BEFORE DELETE ON {table}
                BEGIN
                    SELECT RAISE(ABORT, 'forensic records are append-only');
                END
                """
            )


def _drop_append_only_triggers() -> None:
    dialect = op.get_bind().dialect.name
    if dialect == "postgresql":
        for table in APPEND_ONLY_TABLES:
            op.execute(f"DROP TRIGGER {table}_append_only ON {table}")
    elif dialect == "sqlite":
        for table in APPEND_ONLY_TABLES:
            op.execute(f"DROP TRIGGER {table}_no_delete")
            op.execute(f"DROP TRIGGER {table}_no_update")
