"""Add cases, evidence metadata, acquisitions, and custody history.

Revision ID: 0002_cases_evidence_custody
Revises: 0001_identity_and_organizations
"""
from typing import Sequence

from alembic import op
import sqlalchemy as sa

revision: str = "0002_cases_evidence_custody"
down_revision: str | None = "0001_identity_and_organizations"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

APPEND_ONLY_TABLES = ("acquisition_records", "hash_verifications", "custody_events")


def upgrade() -> None:
    op.create_table(
        "cases",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("organization_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("case_number", sa.String(length=64), nullable=False),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("description", sa.String(length=4000), nullable=True),
        sa.Column("status", sa.String(length=6), nullable=False),
        sa.Column("created_by", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("closed_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint("status IN ('open', 'closed')", name="case_status"),
        sa.ForeignKeyConstraint(
            ["organization_id"], ["organizations.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(["created_by"], ["users.id"]),
        sa.UniqueConstraint("organization_id", "case_number", name="uq_case_org_number"),
    )
    op.create_index("ix_cases_organization_id", "cases", ["organization_id"])
    op.create_index("ix_cases_created_by", "cases", ["created_by"])

    op.create_table(
        "case_assignments",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("case_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("user_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("role", sa.String(length=8), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "role IN ('owner', 'examiner', 'reviewer', 'viewer')",
            name="case_role",
        ),
        sa.ForeignKeyConstraint(["case_id"], ["cases.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.UniqueConstraint("case_id", "user_id", name="uq_case_assignment_case_user"),
    )
    op.create_index("ix_case_assignments_case_id", "case_assignments", ["case_id"])
    op.create_index("ix_case_assignments_user_id", "case_assignments", ["user_id"])

    op.create_table(
        "evidence_items",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("case_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("evidence_number", sa.String(length=64), nullable=False),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("description", sa.String(length=4000), nullable=True),
        sa.Column("size_bytes", sa.Integer(), nullable=False),
        sa.Column("media_type", sa.String(length=255), nullable=True),
        sa.Column("original_sha256", sa.String(length=64), nullable=False),
        sa.Column("registered_by", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("size_bytes >= 0", name="ck_evidence_size_nonnegative"),
        sa.ForeignKeyConstraint(["case_id"], ["cases.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["registered_by"], ["users.id"]),
        sa.UniqueConstraint("case_id", "evidence_number", name="uq_evidence_case_number"),
    )
    op.create_index("ix_evidence_items_case_id", "evidence_items", ["case_id"])

    op.create_table(
        "acquisition_records",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("evidence_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("acquired_by", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("acquisition_method", sa.String(length=100), nullable=False),
        sa.Column("source_description", sa.String(length=1000), nullable=False),
        sa.Column("acquired_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("recorded_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["evidence_id"], ["evidence_items.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["acquired_by"], ["users.id"]),
    )
    op.create_index("ix_acquisition_records_evidence_id", "acquisition_records", ["evidence_id"])

    op.create_table(
        "hash_verifications",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("evidence_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("checked_by", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("submitted_sha256", sa.String(length=64), nullable=False),
        sa.Column("matched", sa.Boolean(), nullable=False),
        sa.Column("checked_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["evidence_id"], ["evidence_items.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["checked_by"], ["users.id"]),
    )
    op.create_index("ix_hash_verifications_evidence_id", "hash_verifications", ["evidence_id"])

    op.create_table(
        "custody_events",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("evidence_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("sequence", sa.Integer(), nullable=False),
        sa.Column("actor_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("event_type", sa.String(length=32), nullable=False),
        sa.Column("notes", sa.String(length=2000), nullable=True),
        sa.Column("details", sa.JSON(), nullable=False),
        sa.Column("previous_hash", sa.String(length=64), nullable=True),
        sa.Column("event_hash", sa.String(length=64), nullable=False),
        sa.Column("recorded_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("sequence > 0", name="ck_custody_sequence_positive"),
        sa.ForeignKeyConstraint(["evidence_id"], ["evidence_items.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["actor_id"], ["users.id"]),
        sa.UniqueConstraint(
            "evidence_id", "sequence", name="uq_custody_event_evidence_sequence"
        ),
    )
    op.create_index("ix_custody_events_evidence_id", "custody_events", ["evidence_id"])

    _create_append_only_triggers()


def downgrade() -> None:
    _drop_append_only_triggers()
    op.drop_index("ix_custody_events_evidence_id", table_name="custody_events")
    op.drop_table("custody_events")
    op.drop_index("ix_hash_verifications_evidence_id", table_name="hash_verifications")
    op.drop_table("hash_verifications")
    op.drop_index("ix_acquisition_records_evidence_id", table_name="acquisition_records")
    op.drop_table("acquisition_records")
    op.drop_index("ix_evidence_items_case_id", table_name="evidence_items")
    op.drop_table("evidence_items")
    op.drop_index("ix_case_assignments_user_id", table_name="case_assignments")
    op.drop_index("ix_case_assignments_case_id", table_name="case_assignments")
    op.drop_table("case_assignments")
    op.drop_index("ix_cases_created_by", table_name="cases")
    op.drop_index("ix_cases_organization_id", table_name="cases")
    op.drop_table("cases")


def _create_append_only_triggers() -> None:
    dialect = op.get_bind().dialect.name
    if dialect == "postgresql":
        op.execute(
            """
            CREATE FUNCTION prevent_forensic_record_mutation() RETURNS trigger AS $$
            BEGIN
                RAISE EXCEPTION 'forensic records are append-only';
            END;
            $$ LANGUAGE plpgsql
            """
        )
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
        op.execute("DROP FUNCTION prevent_forensic_record_mutation()")
    elif dialect == "sqlite":
        for table in APPEND_ONLY_TABLES:
            op.execute(f"DROP TRIGGER {table}_no_delete")
            op.execute(f"DROP TRIGGER {table}_no_update")
