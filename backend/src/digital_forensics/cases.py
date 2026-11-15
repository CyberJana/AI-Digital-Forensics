from datetime import UTC, datetime
from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Response, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from digital_forensics.case_access import CaseAccess, get_case_access, require_case_roles
from digital_forensics.database import get_db_session
from digital_forensics.identity import AuthenticatedUser, get_authenticated_user, require_csrf
from digital_forensics.models import (
    CaseAssignment,
    CaseRole,
    CaseStatus,
    InvestigationCase,
    Membership,
    MembershipRole,
    Organization,
    User,
    utc_now,
)

router = APIRouter(tags=["cases"])
DatabaseSession = Annotated[Session, Depends(get_db_session)]
CurrentUser = Annotated[AuthenticatedUser, Depends(get_authenticated_user)]
CsrfProtected = Annotated[None, Depends(require_csrf)]


class CreateCaseRequest(BaseModel):
    case_number: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9._-]+$")
    name: str = Field(min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=4000)


class UpdateCaseRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str | None = Field(default=None, min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=4000)
    status: CaseStatus | None = None


class AddCaseMemberRequest(BaseModel):
    user_id: UUID
    role: Literal["examiner", "reviewer", "viewer"]


class UpdateCaseMemberRequest(BaseModel):
    role: CaseRole


def _case_response(investigation_case: InvestigationCase) -> dict[str, object]:
    return {
        "id": investigation_case.id,
        "organization_id": investigation_case.organization_id,
        "case_number": investigation_case.case_number,
        "name": investigation_case.name,
        "description": investigation_case.description,
        "status": investigation_case.status.value,
        "created_by": investigation_case.created_by,
        "created_at": investigation_case.created_at,
        "updated_at": investigation_case.updated_at,
        "closed_at": investigation_case.closed_at,
    }


def _member_response(assignment: CaseAssignment, user: User) -> dict[str, object]:
    return {
        "user_id": user.id,
        "display_name": user.display_name,
        "email": user.email,
        "role": assignment.role.value,
        "assigned_at": assignment.created_at,
    }


def _require_case_management_role(access: CaseAccess) -> None:
    require_case_roles(access, {CaseRole.OWNER})


def _require_open_case(access: CaseAccess) -> None:
    if access.case.status == CaseStatus.CLOSED:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Closed cases are read-only")


def _lock_case(db: Session, case_id: UUID) -> None:
    db.scalar(
        select(InvestigationCase.id)
        .where(InvestigationCase.id == case_id)
        .with_for_update()
    )


@router.post(
    "/organizations/{organization_id}/cases",
    status_code=status.HTTP_201_CREATED,
)
def create_case(
    organization_id: UUID,
    payload: CreateCaseRequest,
    db: DatabaseSession,
    current: CurrentUser,
    _: CsrfProtected,
) -> dict[str, object]:
    organization_membership = db.scalar(
        select(Membership)
        .join(Organization, Organization.id == Membership.organization_id)
        .where(
            Membership.organization_id == organization_id,
            Membership.user_id == current.user.id,
            Organization.is_active.is_(True),
        )
    )
    if organization_membership is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Organization not found")
    if organization_membership.role not in {
        MembershipRole.OWNER,
        MembershipRole.ADMIN,
        MembershipRole.EXAMINER,
    }:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient role")

    existing_case = db.scalar(
        select(InvestigationCase).where(
            InvestigationCase.organization_id == organization_id,
            InvestigationCase.case_number == payload.case_number,
        )
    )
    if existing_case is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Case number already exists in this organization",
        )

    investigation_case = InvestigationCase(
        organization_id=organization_id,
        case_number=payload.case_number,
        name=payload.name,
        description=payload.description,
        created_by=current.user.id,
    )
    db.add(investigation_case)
    db.flush()
    db.add(
        CaseAssignment(
            case_id=investigation_case.id,
            user_id=current.user.id,
            role=CaseRole.OWNER,
        )
    )
    db.commit()
    db.refresh(investigation_case)
    return _case_response(investigation_case)


@router.get("/organizations/{organization_id}/cases")
def list_cases(
    organization_id: UUID,
    db: DatabaseSession,
    current: CurrentUser,
) -> list[dict[str, object]]:
    organization_membership = db.scalar(
        select(Membership)
        .join(Organization, Organization.id == Membership.organization_id)
        .where(
            Membership.organization_id == organization_id,
            Membership.user_id == current.user.id,
            Organization.is_active.is_(True),
        )
    )
    if organization_membership is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Organization not found")

    query = select(InvestigationCase).where(
        InvestigationCase.organization_id == organization_id
    )
    if organization_membership.role not in {MembershipRole.OWNER, MembershipRole.ADMIN}:
        assigned_case_ids = select(CaseAssignment.case_id).where(
            CaseAssignment.user_id == current.user.id
        )
        query = query.where(InvestigationCase.id.in_(assigned_case_ids))
    cases = db.scalars(query.order_by(InvestigationCase.created_at.desc())).all()
    return [_case_response(investigation_case) for investigation_case in cases]


@router.get("/cases/{case_id}")
def get_case(
    case_id: UUID,
    db: DatabaseSession,
    current: CurrentUser,
) -> dict[str, object]:
    access = get_case_access(db, current.user.id, case_id)
    return _case_response(access.case)


@router.patch("/cases/{case_id}")
def update_case(
    case_id: UUID,
    payload: UpdateCaseRequest,
    db: DatabaseSession,
    current: CurrentUser,
    _: CsrfProtected,
) -> dict[str, object]:
    access = get_case_access(db, current.user.id, case_id)
    _require_case_management_role(access)
    updates = payload.model_dump(exclude_unset=True)
    if not updates:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="At least one case field must be provided",
        )
    if access.case.status == CaseStatus.CLOSED and updates != {"status": CaseStatus.OPEN}:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Closed cases are read-only")
    if "name" in updates:
        if updates["name"] is None:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Case name cannot be null",
            )
        access.case.name = updates["name"]
    if "description" in updates:
        access.case.description = updates["description"]
    if "status" in updates:
        if updates["status"] is None:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Case status cannot be null",
            )
        access.case.status = updates["status"]
        access.case.closed_at = utc_now() if updates["status"] == CaseStatus.CLOSED else None
    access.case.updated_at = utc_now()
    db.commit()
    db.refresh(access.case)
    return _case_response(access.case)


@router.get("/cases/{case_id}/members")
def list_case_members(
    case_id: UUID,
    db: DatabaseSession,
    current: CurrentUser,
) -> list[dict[str, object]]:
    get_case_access(db, current.user.id, case_id)
    rows = db.execute(
        select(CaseAssignment, User)
        .join(User, User.id == CaseAssignment.user_id)
        .where(CaseAssignment.case_id == case_id, User.is_active.is_(True))
        .order_by(User.display_name, User.id)
    ).all()
    return [_member_response(assignment, user) for assignment, user in rows]


@router.post(
    "/cases/{case_id}/members",
    status_code=status.HTTP_201_CREATED,
)
def add_case_member(
    case_id: UUID,
    payload: AddCaseMemberRequest,
    db: DatabaseSession,
    current: CurrentUser,
    _: CsrfProtected,
) -> dict[str, object]:
    access = get_case_access(db, current.user.id, case_id)
    _require_case_management_role(access)
    _require_open_case(access)

    organization_membership = db.scalar(
        select(Membership).where(
            Membership.organization_id == access.case.organization_id,
            Membership.user_id == payload.user_id,
        )
    )
    if organization_membership is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User is not an organization member",
        )
    user = db.get(User, payload.user_id)
    if user is None or not user.is_active:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    if _get_assignment(db, case_id, user.id) is not None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="User is already assigned")

    assignment = CaseAssignment(
        case_id=case_id,
        user_id=user.id,
        role=CaseRole(payload.role),
    )
    db.add(assignment)
    db.commit()
    db.refresh(assignment)
    return _member_response(assignment, user)


@router.patch("/cases/{case_id}/members/{user_id}")
def update_case_member(
    case_id: UUID,
    user_id: UUID,
    payload: UpdateCaseMemberRequest,
    db: DatabaseSession,
    current: CurrentUser,
    _: CsrfProtected,
) -> dict[str, object]:
    access = get_case_access(db, current.user.id, case_id)
    _require_case_management_role(access)
    _require_open_case(access)
    assignment = _get_assignment(db, case_id, user_id)
    if assignment is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Assignment not found")
    if assignment.role == CaseRole.OWNER and payload.role != CaseRole.OWNER:
        _lock_case(db, case_id)
        owner_count = db.scalar(
            select(func.count())
            .select_from(CaseAssignment)
            .where(
                CaseAssignment.case_id == case_id,
                CaseAssignment.role == CaseRole.OWNER,
            )
        )
        if owner_count is not None and owner_count <= 1:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="A case must retain at least one owner",
            )

    assignment.role = payload.role
    db.commit()
    db.refresh(assignment)
    return _member_response(assignment, assignment.user)


@router.delete(
    "/cases/{case_id}/members/{user_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
def remove_case_member(
    case_id: UUID,
    user_id: UUID,
    db: DatabaseSession,
    current: CurrentUser,
    _: CsrfProtected,
) -> Response:
    access = get_case_access(db, current.user.id, case_id)
    _require_case_management_role(access)
    _require_open_case(access)
    assignment = _get_assignment(db, case_id, user_id)
    if assignment is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Assignment not found")
    if assignment.role == CaseRole.OWNER:
        _lock_case(db, case_id)
        owner_count = db.scalar(
            select(func.count())
            .select_from(CaseAssignment)
            .where(
                CaseAssignment.case_id == case_id,
                CaseAssignment.role == CaseRole.OWNER,
            )
        )
        if owner_count is not None and owner_count <= 1:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="A case must retain at least one owner",
            )

    db.delete(assignment)
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


def _get_assignment(db: Session, case_id: UUID, user_id: UUID) -> CaseAssignment | None:
    return db.scalar(
        select(CaseAssignment).where(
            CaseAssignment.case_id == case_id,
            CaseAssignment.user_id == user_id,
        )
    )
