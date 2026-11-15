from uuid import UUID

from sqlalchemy.orm import Session

from digital_forensics.models import AuditEvent


def record_case_audit(
    db: Session,
    *,
    case_id: UUID,
    actor_id: UUID,
    action: str,
    target_type: str,
    target_id: UUID,
    metadata: dict[str, object] | None = None,
) -> None:
    db.add(
        AuditEvent(
            case_id=case_id,
            actor_id=actor_id,
            action=action,
            target_type=target_type,
            target_id=target_id,
            metadata_json=metadata or {},
        )
    )
