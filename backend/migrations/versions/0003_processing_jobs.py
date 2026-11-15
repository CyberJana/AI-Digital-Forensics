"""Add database-backed processing jobs.

Revision ID: 0003_processing_jobs
Revises: 0002_cases_evidence_custody
"""
from typing import Sequence

from alembic import op
import sqlalchemy as sa

revision: str = "0003_processing_jobs"
down_revision: str | None = "0002_cases_evidence_custody"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "processing_jobs",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("case_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("evidence_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("requested_by", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("adapter_name", sa.String(length=100), nullable=False),
        sa.Column("adapter_version", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=9), nullable=False),
        sa.Column("parameters", sa.JSON(), nullable=False),
        sa.Column("result", sa.JSON(), nullable=True),
        sa.Column("error_code", sa.String(length=100), nullable=True),
        sa.Column("attempt_count", sa.Integer(), nullable=False),
        sa.Column("max_attempts", sa.Integer(), nullable=False),
        sa.Column("worker_id", sa.String(length=200), nullable=True),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "attempt_count >= 0 AND attempt_count <= max_attempts",
            name="ck_processing_job_attempt_range",
        ),
        sa.CheckConstraint(
            "max_attempts > 0",
            name="ck_processing_job_max_attempts_positive",
        ),
        sa.CheckConstraint(
            "status IN ('queued', 'running', 'succeeded', 'failed', 'cancelled')",
            name="processing_job_status",
        ),
        sa.ForeignKeyConstraint(["case_id"], ["cases.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(
            ["evidence_id"], ["evidence_items.id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(["requested_by"], ["users.id"]),
    )
    op.create_index("ix_processing_jobs_case_id", "processing_jobs", ["case_id"])
    op.create_index("ix_processing_jobs_evidence_id", "processing_jobs", ["evidence_id"])
    op.create_index(
        "ix_processing_jobs_status_created_at",
        "processing_jobs",
        ["status", "created_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_processing_jobs_status_created_at", table_name="processing_jobs")
    op.drop_index("ix_processing_jobs_evidence_id", table_name="processing_jobs")
    op.drop_index("ix_processing_jobs_case_id", table_name="processing_jobs")
    op.drop_table("processing_jobs")
