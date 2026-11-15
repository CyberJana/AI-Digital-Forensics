"""Add client-side encrypted object-storage metadata to evidence.

Revision ID: 0006_encrypted_evidence_storage
Revises: 0005_case_reporting_and_audit
"""
from typing import Sequence

from alembic import op
import sqlalchemy as sa

revision: str = "0006_encrypted_evidence_storage"
down_revision: str | None = "0005_case_reporting_and_audit"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("evidence_items") as batch_op:
        batch_op.add_column(sa.Column("storage_object_key", sa.String(length=1024)))
        batch_op.add_column(sa.Column("storage_version_id", sa.String(length=1024)))
        batch_op.add_column(sa.Column("encrypted_data_key", sa.Text()))
        batch_op.add_column(sa.Column("encryption_nonce", sa.String(length=32)))
        batch_op.add_column(sa.Column("encryption_tag", sa.String(length=32)))
        batch_op.create_unique_constraint(
            "uq_evidence_storage_object_key",
            ["storage_object_key"],
        )
        batch_op.create_check_constraint(
            "ck_evidence_storage_encryption_metadata",
            "(storage_object_key IS NULL AND encrypted_data_key IS NULL "
            "AND encryption_nonce IS NULL AND encryption_tag IS NULL) OR "
            "(storage_object_key IS NOT NULL AND encrypted_data_key IS NOT NULL "
            "AND encryption_nonce IS NOT NULL AND encryption_tag IS NOT NULL)",
        )


def downgrade() -> None:
    with op.batch_alter_table("evidence_items") as batch_op:
        batch_op.drop_constraint(
            "ck_evidence_storage_encryption_metadata",
            type_="check",
        )
        batch_op.drop_constraint(
            "uq_evidence_storage_object_key",
            type_="unique",
        )
        batch_op.drop_column("encryption_tag")
        batch_op.drop_column("encryption_nonce")
        batch_op.drop_column("encrypted_data_key")
        batch_op.drop_column("storage_version_id")
        batch_op.drop_column("storage_object_key")
