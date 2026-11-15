"""Add immutable, provenance-backed case AI summaries.

Revision ID: 0004_case_ai_summaries
Revises: 0003_processing_jobs
"""
from typing import Sequence

from alembic import op
import sqlalchemy as sa

revision: str = "0004_case_ai_summaries"
down_revision: str | None = "0003_processing_jobs"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "case_ai_summaries",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("case_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("requested_by", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("provider", sa.String(length=32), nullable=False),
        sa.Column("model_name", sa.String(length=200), nullable=False),
        sa.Column("prompt_version", sa.String(length=64), nullable=False),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("summary_source_record_ids", sa.JSON(), nullable=False),
        sa.Column("key_points", sa.JSON(), nullable=False),
        sa.Column("source_snapshot", sa.JSON(), nullable=False),
        sa.Column("review_status", sa.String(length=16), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "review_status = 'unreviewed'",
            name="ck_case_ai_summary_unreviewed",
        ),
        sa.ForeignKeyConstraint(["case_id"], ["cases.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["requested_by"], ["users.id"]),
    )
    op.create_index(
        "ix_case_ai_summaries_case_created_at",
        "case_ai_summaries",
        ["case_id", "created_at"],
    )
    _create_append_only_triggers()


def downgrade() -> None:
    _drop_append_only_triggers()
    op.drop_index(
        "ix_case_ai_summaries_case_created_at",
        table_name="case_ai_summaries",
    )
    op.drop_table("case_ai_summaries")


def _create_append_only_triggers() -> None:
    dialect = op.get_bind().dialect.name
    if dialect == "postgresql":
        op.execute(
            """
            CREATE TRIGGER case_ai_summaries_append_only
            BEFORE UPDATE OR DELETE ON case_ai_summaries
            FOR EACH ROW EXECUTE FUNCTION prevent_forensic_record_mutation()
            """
        )
    elif dialect == "sqlite":
        op.execute(
            """
            CREATE TRIGGER case_ai_summaries_no_update
            BEFORE UPDATE ON case_ai_summaries
            BEGIN
                SELECT RAISE(ABORT, 'forensic records are append-only');
            END
            """
        )
        op.execute(
            """
            CREATE TRIGGER case_ai_summaries_no_delete
            BEFORE DELETE ON case_ai_summaries
            BEGIN
                SELECT RAISE(ABORT, 'forensic records are append-only');
            END
            """
        )


def _drop_append_only_triggers() -> None:
    dialect = op.get_bind().dialect.name
    if dialect == "postgresql":
        op.execute(
            "DROP TRIGGER case_ai_summaries_append_only ON case_ai_summaries"
        )
    elif dialect == "sqlite":
        op.execute("DROP TRIGGER case_ai_summaries_no_delete")
        op.execute("DROP TRIGGER case_ai_summaries_no_update")
