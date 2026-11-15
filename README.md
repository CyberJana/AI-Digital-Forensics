# AI Digital Forensics

Foundation for a hybrid local-lab and cloud digital forensics investigation platform. The project is being implemented in controlled milestones; Phase 2 adds the PostgreSQL data model and OIDC-backed identity and organization access controls.

## Repository layout

- `backend/` — Python API package and tests.
- `frontend/` — Next.js dashboard.
- `backend/migrations/` — Alembic database migrations.
- `docs/ARCHITECTURE.md` — proposed architecture, dependencies, deployment strategy, roadmap, and risks.

## Development

### Backend

Requires Python 3.12 or newer.

```powershell
cd backend
python -m pip install -e ".[dev]"
python -m uvicorn digital_forensics.main:app --reload
```

The API health endpoint is `http://127.0.0.1:8000/health`; OpenAPI documentation is at `http://127.0.0.1:8000/docs`.

Run backend tests from `backend/`:

```powershell
python -m pytest
```

### Database and OIDC

Phase 2 requires PostgreSQL and an OIDC identity provider for interactive authentication. Copy `.env.example` to `.env`, configure `DIGITAL_FORENSICS_DATABASE_URL` and the OIDC issuer/client credentials, and generate a random `DIGITAL_FORENSICS_SESSION_SIGNING_KEY` with:

```powershell
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

Register `http://localhost:8000/auth/callback` as the OIDC redirect URI for local development. Run migrations from `backend/`:

```powershell
python -m alembic -c alembic.ini upgrade head
```

After a user completes OIDC sign-in at `http://localhost:8000/auth/login`, use the user ID returned by `/auth/me` to create the initial organization owner:

```powershell
digital-forensics-bootstrap --name "Example Organization" --slug example-organization --owner-user-id <user-id>
```

Users are provisioned from validated OIDC subject claims; only verified email claims are stored, and identities are never merged by email. Organization members must first authenticate; an owner or admin can add an existing user by ID. Owners can transfer ownership and cannot remove or demote the last owner. The identity provider must enforce MFA for production; the application does not currently verify provider-specific MFA assurance claims.

The API currently exposes `/auth/login`, `/auth/callback`, `/auth/me`, `/auth/csrf`, `/auth/logout`, `/organizations`, and organization member list/add/update/remove routes. The frontend is not yet wired to these endpoints. Keep the frontend and API on the same site so the `SameSite=Lax` session cookies are sent; CORS is restricted to the configured frontend origin.

### Frontend

Requires Node.js 20.9 or newer and npm.

```powershell
cd frontend
npm install
npm run dev
```

The dashboard is available at `http://localhost:3000`. The UI is currently a foundation shell and does not yet connect to the API.

## Scope and limitations

Evidence processing, case management, SAML integration, frontend sign-in, invitations, and deployment are not implemented yet. OIDC requires a configured identity provider and PostgreSQL database. MFA depends on identity-provider policy and must be verified before production use. Do not use this foundation with real evidence or for production investigations. See the architecture and roadmap in `docs/ARCHITECTURE.md`.
