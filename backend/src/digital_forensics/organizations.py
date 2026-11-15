from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Response, status
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from digital_forensics.database import get_db_session
from digital_forensics.identity import AuthenticatedUser, get_authenticated_user, require_csrf
from digital_forensics.models import Membership, MembershipRole, Organization, User

router = APIRouter(prefix="/organizations", tags=["organizations"])
DatabaseSession = Annotated[Session, Depends(get_db_session)]
CurrentUser = Annotated[AuthenticatedUser, Depends(get_authenticated_user)]
CsrfProtected = Annotated[None, Depends(require_csrf)]


class AddMemberRequest(BaseModel):
    user_id: UUID
    role: Literal["admin", "examiner", "reviewer", "viewer"]


class UpdateMemberRoleRequest(BaseModel):
    role: MembershipRole


def _require_membership(db: Session, user_id: UUID, organization_id: UUID) -> Membership:
    membership = db.scalar(
        select(Membership)
        .join(Organization, Organization.id == Membership.organization_id)
        .where(
            Membership.user_id == user_id,
            Membership.organization_id == organization_id,
            Organization.is_active.is_(True),
        )
    )
    if membership is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Organization not found")
    return membership


def _member_response(membership: Membership, user: User) -> dict[str, object]:
    return {
        "user_id": user.id,
        "email": user.email,
        "display_name": user.display_name,
        "role": membership.role.value,
        "joined_at": membership.created_at,
    }


@router.get("")
def list_organizations(db: DatabaseSession, current: CurrentUser) -> list[dict[str, object]]:
    rows = db.execute(
        select(Organization, Membership.role)
        .join(Membership, Membership.organization_id == Organization.id)
        .where(Membership.user_id == current.user.id, Organization.is_active.is_(True))
        .order_by(Organization.name)
    ).all()
    return [
        {
            "id": organization.id,
            "name": organization.name,
            "slug": organization.slug,
            "role": role.value,
        }
        for organization, role in rows
    ]


@router.get("/{organization_id}/members")
def list_members(
    organization_id: UUID, db: DatabaseSession, current: CurrentUser
) -> list[dict[str, object]]:
    _require_membership(db, current.user.id, organization_id)
    rows = db.execute(
        select(Membership, User)
        .join(User, User.id == Membership.user_id)
        .where(
            Membership.organization_id == organization_id,
            User.is_active.is_(True),
        )
        .order_by(User.display_name, User.id)
    ).all()
    return [_member_response(membership, user) for membership, user in rows]


@router.post(
    "/{organization_id}/members",
    status_code=status.HTTP_201_CREATED,
)
def add_member(
    organization_id: UUID,
    payload: AddMemberRequest,
    db: DatabaseSession,
    current: CurrentUser,
    _: CsrfProtected,
) -> dict[str, object]:
    acting_membership = _require_membership(db, current.user.id, organization_id)
    if acting_membership.role not in {MembershipRole.OWNER, MembershipRole.ADMIN}:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient role")
    if (
        payload.role == MembershipRole.ADMIN.value
        and acting_membership.role != MembershipRole.OWNER
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only organization owners can assign admin roles",
        )

    user = db.get(User, payload.user_id)
    if user is None or not user.is_active:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    if _require_existing_membership(db, organization_id, user.id) is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="User is already an organization member",
        )

    membership = Membership(
        organization_id=organization_id,
        user_id=user.id,
        role=MembershipRole(payload.role),
    )
    db.add(membership)
    db.commit()
    db.refresh(membership)
    return _member_response(membership, user)


@router.delete(
    "/{organization_id}/members/{user_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
def remove_member(
    organization_id: UUID,
    user_id: UUID,
    db: DatabaseSession,
    current: CurrentUser,
    _: CsrfProtected,
) -> Response:
    acting_membership = _require_membership(db, current.user.id, organization_id)
    if acting_membership.role != MembershipRole.OWNER:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Owner role required")

    target = _require_existing_membership(db, organization_id, user_id)
    if target is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    if target.role == MembershipRole.OWNER:
        _lock_organization(db, organization_id)
        owner_count = db.scalar(
            select(func.count())
            .select_from(Membership)
            .where(
                Membership.organization_id == organization_id,
                Membership.role == MembershipRole.OWNER,
            )
        )
        if owner_count is not None and owner_count <= 1:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="An organization must retain at least one owner",
            )

    db.delete(target)
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.patch("/{organization_id}/members/{user_id}")
def update_member_role(
    organization_id: UUID,
    user_id: UUID,
    payload: UpdateMemberRoleRequest,
    db: DatabaseSession,
    current: CurrentUser,
    _: CsrfProtected,
) -> dict[str, object]:
    acting_membership = _require_membership(db, current.user.id, organization_id)
    if acting_membership.role != MembershipRole.OWNER:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Owner role required")

    target = _require_existing_membership(db, organization_id, user_id)
    if target is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    if target.role == MembershipRole.OWNER and payload.role != MembershipRole.OWNER:
        _lock_organization(db, organization_id)
        owner_count = db.scalar(
            select(func.count())
            .select_from(Membership)
            .where(
                Membership.organization_id == organization_id,
                Membership.role == MembershipRole.OWNER,
            )
        )
        if owner_count is not None and owner_count <= 1:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="An organization must retain at least one owner",
            )

    target.role = payload.role
    db.commit()
    db.refresh(target)
    return _member_response(target, target.user)


def _require_existing_membership(
    db: Session, organization_id: UUID, user_id: UUID
) -> Membership | None:
    return db.scalar(
        select(Membership).where(
            Membership.organization_id == organization_id,
            Membership.user_id == user_id,
        )
    )


def _lock_organization(db: Session, organization_id: UUID) -> None:
    db.scalar(
        select(Organization.id)
        .where(Organization.id == organization_id)
        .with_for_update()
    )
