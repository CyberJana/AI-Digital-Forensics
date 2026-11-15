# AI Digital Forensics

Foundation for a hybrid local-lab and cloud digital forensics investigation platform. The project is being implemented in controlled milestones; Phases 1–4 provide the API foundation, OIDC-backed identity and organization access controls, case/evidence metadata, and an initial processing framework.

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

### Cases and evidence metadata

Phase 3 adds organization-scoped cases, case assignments, evidence metadata, acquisition records, examiner-submitted SHA-256 comparisons, and hash-linked custody events. Case access requires organization membership and, except for organization owners/admins, an explicit case assignment. Only case owners/examiners and organization owners/admins can register evidence or append verification/custody records; closed cases are read-only until reopened by a case owner or organization owner/admin.

The API provides case create/list/get/update and assignment routes under `/organizations/{organization_id}/cases` and `/cases/{case_id}`, plus evidence registration/list/get, acquisition listing, hash-verification, and custody-event list/append/verification routes under `/cases/{case_id}/evidence` and `/evidence/{evidence_id}`.

The local utility reads regular files without modifying them and prints JSON with a SHA-256 digest and byte count:

```powershell
digital-forensics-hash "C:\evidence\image.E01"
```

Evidence registration accepts metadata and a digest; the API does not receive or independently hash the source file. Evidence binaries are not stored. Hash comparisons therefore record the examiner-submitted digest and must not be interpreted as independent server verification. Acquisition, hash-verification, and custody rows are protected from ordinary updates/deletes by SQLite/PostgreSQL triggers, and custody events are linked by a verifiable hash chain; privileged database access can still bypass database controls.

### Processing framework

Phase 4 adds case-scoped processing jobs, a database-backed queue, a separate worker process, lease recovery with bounded retries, and an adapter contract. Submit the initial `custody-chain-verification` adapter at `/cases/{case_id}/processing-jobs`; it verifies custody metadata only. No forensic parser or evidence-binary processing is included. Start `digital-forensics-worker` in a separate process using the same database configuration as the API. Apply migrations before starting either process.

The local utility creates and verifies a distinct read-only working copy without modifying the source:

```powershell
digital-forensics-copy "C:\evidence\image.E01" "C:\case-work\image-copy.E01"
```

The destination directory must exist, and the destination file must not already exist. The utility reports the local working-copy path and its SHA-256 digest; file paths are not accepted by the processing API or stored in job records. The worker runs in a separate process from the API, but this is not an OS-level sandbox. Do not run parsers on real evidence until worker resource isolation, encrypted storage, and key management are designed and validated.

### Frontend

Requires Node.js 20.9 or newer and npm.

```powershell
cd frontend
npm install
npm run dev
```

The dashboard is available at `http://localhost:3000`. The UI is currently a foundation shell and does not yet connect to the API.

## Scope and limitations

Encrypted evidence storage, forensic tool integrations, SAML integration, frontend sign-in, invitations, and deployment are not implemented yet. OIDC requires a configured identity provider and PostgreSQL database. MFA depends on identity-provider policy and must be verified before production use. Do not use this foundation with real evidence or for production investigations. See the architecture and roadmap in `docs/ARCHITECTURE.md`.
