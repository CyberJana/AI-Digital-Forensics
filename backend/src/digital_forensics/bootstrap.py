import argparse
from uuid import UUID

from pydantic import BaseModel, Field
from sqlalchemy import select

from digital_forensics.database import create_database_engine, create_session_factory
from digital_forensics.models import Membership, MembershipRole, Organization, User
from digital_forensics.settings import get_settings


class OrganizationBootstrap(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    slug: str = Field(
        min_length=1,
        max_length=63,
        pattern=r"^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$",
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Create an organization and assign an existing OIDC user as owner."
    )
    parser.add_argument("--name", required=True)
    parser.add_argument("--slug", required=True)
    parser.add_argument("--owner-user-id", required=True, type=UUID)
    args = parser.parse_args()

    settings = get_settings()
    if settings.database_url is None:
        raise SystemExit("DIGITAL_FORENSICS_DATABASE_URL must be set")

    organization_data = OrganizationBootstrap(name=args.name, slug=args.slug)
    engine = create_database_engine(settings.database_url.get_secret_value())
    session_factory = create_session_factory(engine)
    try:
        with session_factory() as db:
            owner = db.get(User, args.owner_user_id)
            if owner is None or not owner.is_active:
                raise SystemExit("The owner user must authenticate through OIDC before bootstrapping")
            existing = db.scalar(
                select(Organization).where(Organization.slug == organization_data.slug)
            )
            if existing is not None:
                raise SystemExit("An organization with that slug already exists")

            organization = Organization(
                name=organization_data.name,
                slug=organization_data.slug,
            )
            db.add(organization)
            db.flush()
            db.add(
                Membership(
                    organization_id=organization.id,
                    user_id=owner.id,
                    role=MembershipRole.OWNER,
                )
            )
            db.commit()
            print(f"Created organization {organization.slug} ({organization.id})")
    finally:
        engine.dispose()
