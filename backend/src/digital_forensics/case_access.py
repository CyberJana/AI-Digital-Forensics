from dataclasses import dataclass
from uuid import UUID

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from digital_forensics.models import (
    CaseAssignment,
    CaseRole,
    InvestigationCase,
    Membership,
    MembershipRole,
    Organization,
)


@dataclass(frozen=True)
class CaseAccess:
    case: InvestigationCase
    organization_role: MembershipRole
    case_role: CaseRole | None


def get_case_access(db: Session, user_id: UUID, case_id: UUID) -> CaseAccess:
    investigation_case = db.scalar(
        select(InvestigationCase)
        .join(Organization, Organization.id == InvestigationCase.organization_id)
        .where(
            InvestigationCase.id == case_id,
            Organization.is_active.is_(True),
        )
    )
    if investigation_case is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found")

    organization_membership = db.scalar(
        select(Membership).where(
            Membership.organization_id == investigation_case.organization_id,
            Membership.user_id == user_id,
        )
    )
    if organization_membership is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found")

    case_assignment = db.scalar(
        select(CaseAssignment).where(
            CaseAssignment.case_id == case_id,
            CaseAssignment.user_id == user_id,
        )
    )
    if organization_membership.role not in {MembershipRole.OWNER, MembershipRole.ADMIN}:
        if case_assignment is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found")

    return CaseAccess(
        case=investigation_case,
        organization_role=organization_membership.role,
        case_role=case_assignment.role if case_assignment is not None else None,
    )


def require_case_roles(access: CaseAccess, allowed: set[CaseRole]) -> None:
    if access.organization_role in {MembershipRole.OWNER, MembershipRole.ADMIN}:
        return
    if access.case_role not in allowed:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient case role")
