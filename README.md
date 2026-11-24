# AI Digital Forensics

Foundation for a hybrid local-lab and cloud digital forensics investigation platform. The repository includes an initial API and dashboard, OIDC-backed identity and organization access controls, case/evidence metadata, a processing framework, a case timeline, local AI summaries, and case reporting. Forensic parser execution remains disabled pending an approved OS-level sandbox. Container and CI configurations are initial readiness work; neither staging nor production has been deployed or validated.

## Repository layout

- `backend/` — Python API package and tests.
- `frontend/` — Next.js dashboard.
- `backend/migrations/` — Alembic database migrations.
- `docs/ARCHITECTURE.md` — proposed architecture, dependencies, deployment strategy, roadmap, and risks.
- `docs/OPERATIONS.md` — release gates, startup order, backup/restore expectations, and incident procedures.

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

The API currently exposes `/auth/login`, `/auth/callback`, `/auth/me`, `/auth/csrf`, `/auth/logout`, `/organizations`, and organization member list/add/update/remove routes. The frontend uses the session and CSRF endpoints and displays assigned cases, evidence, their acquisition/custody timeline, and saved AI summaries. Keep the frontend and API on the same site so the `SameSite=Lax` session cookies are sent; CORS is restricted to the configured frontend origin.

### Cases and evidence metadata

Phase 3 adds organization-scoped cases, case assignments, evidence metadata, acquisition records, examiner-submitted SHA-256 comparisons, and hash-linked custody events. Case access requires organization membership and, except for organization owners/admins, an explicit case assignment. Only case owners/examiners and organization owners/admins can register evidence or append verification/custody records; closed cases are read-only until reopened by a case owner or organization owner/admin.

The API provides case create/list/get/update and assignment routes under `/organizations/{organization_id}/cases` and `/cases/{case_id}`, plus evidence registration/list/get, acquisition listing, hash-verification, and custody-event list/append/verification routes under `/cases/{case_id}/evidence` and `/evidence/{evidence_id}`. Phase 6 adds the read-only `/cases/{case_id}/timeline` endpoint, which chronologically combines acquisition and custody records and reports per-evidence custody-chain verification.

The local utility reads regular files without modifying them and prints JSON with a SHA-256 digest and byte count:

```powershell
digital-forensics-hash "C:\evidence\image.E01"
```

Evidence can be uploaded through the case dashboard or `POST /cases/{case_id}/evidence/upload` when S3-compatible storage and Vault Transit are configured. The API computes SHA-256 over the uploaded bytes, encrypts each file with a unique AES-256-GCM data key, and wraps that key with the configured Vault Transit key. The object store receives ciphertext only. `GET /evidence/{evidence_id}/binary` requires case access, verifies the decrypted file against the stored digest before streaming, and records the download request in the case audit log. Staging and production require this configuration and a Vault Agent token file; development can remain metadata-only. Configure S3 bucket versioning, private access, retention, lifecycle, backups, and encrypted API scratch storage before use. The initial uploader supports objects up to the S3 multipart limit of 10,000 parts at 64 MiB per part (about 625 GiB).

Set `DIGITAL_FORENSICS_EVIDENCE_S3_BUCKET`, optionally `DIGITAL_FORENSICS_EVIDENCE_S3_ENDPOINT_URL` and `DIGITAL_FORENSICS_EVIDENCE_S3_REGION`, and configure `DIGITAL_FORENSICS_VAULT_ADDR`, `DIGITAL_FORENSICS_VAULT_TRANSIT_KEY`, and either `DIGITAL_FORENSICS_VAULT_TOKEN` for local development or `DIGITAL_FORENSICS_VAULT_TOKEN_FILE` for staging/production. Static S3 credentials are optional when the runtime has an approved workload identity; otherwise set the paired S3 access-key variables. Compose does not provision S3 or Vault. The Vault policy should permit only encrypt/decrypt operations on the configured Transit key. Uploads pass through the API framework's temporary-file handling, so the host must provide encrypted scratch storage and a request-size limit before accepting real evidence.

Metadata-only registration accepts an examiner-submitted digest and does not independently verify a source file. Use the upload endpoint when the application is authorized to ingest a binary; it hashes the actual upload. Hash comparisons on metadata-only records remain examiner-submitted and must not be interpreted as independent server verification. Acquisition, hash-verification, and custody rows are protected from ordinary updates/deletes by SQLite/PostgreSQL triggers, and custody events are linked by a verifiable hash chain; privileged database access can still bypass database controls.

### Processing framework

Phase 4 adds case-scoped processing jobs, a database-backed queue, a separate worker process, lease recovery with bounded retries, and an adapter contract. Submit the initial `custody-chain-verification` adapter at `/cases/{case_id}/processing-jobs`; it verifies custody metadata only. No forensic parser or evidence-binary processing is included. Start `digital-forensics-worker` in a separate process using the same database configuration as the API. Apply migrations before starting either process.

The local utility creates and verifies a distinct read-only working copy without modifying the source:

```powershell
digital-forensics-copy "C:\evidence\image.E01" "C:\case-work\image-copy.E01"
```

The destination directory must exist, and the destination file must not already exist. The utility reports the local working-copy path and its SHA-256 digest; file paths are not accepted by the processing API or stored in job records. The worker runs in a separate process from the API, but this is not an OS-level sandbox. Do not run parsers on real evidence until worker resource isolation, encrypted storage, and key management are designed and validated.

The Phase 5 ExifTool adapter records the tool version, upstream license/source references, extracted metadata, and working-copy digest. It is disabled by default, and the API refuses ExifTool jobs. The optional broker client is enabled only by explicit worker configuration; it sends a read-only file descriptor and expected digest to a separate Linux broker, which verifies and stages the bytes before launching a fixed command in a rootless gVisor (`runsc`) Podman container. The broker uses a pinned image, a peer-UID-checked Unix socket, no network, a read-only root filesystem and input, a non-root identity, and bounded time, memory, CPU, PID, input, and output. It does not expose a runtime socket or general command API to the worker. No broker or `runsc` host validation has been performed here; do not enable the integration or process real evidence until the host configuration and containment are independently validated. The upstream README describes ExifTool as redistributable under either the Perl Artistic License or GPL; review the applicable terms before any distribution.

The worker's local-copy lookup uses `DIGITAL_FORENSICS_WORKING_COPY_ROOT`; copies are expected as direct-child files named `<evidence-id>.working-copy` and are checked against the registered SHA-256 digest. `DIGITAL_FORENSICS_EXIFTOOL_SANDBOX_ENABLED` defaults to `false`; opting in also requires an absolute `DIGITAL_FORENSICS_EXIFTOOL_BROKER_SOCKET_PATH` and a configured working-copy root. The current API still refuses ExifTool jobs, and the standard Compose worker has no broker socket mount. The broker is a separate Linux service account configured with `digital-forensics-exiftool-broker`; it requires a preloaded digest-pinned image and rootless Podman configured to use gVisor `runsc`. Mount only the broker socket into the dedicated worker, never into the API, and do not give either service an OCI/Docker runtime socket. The broker's staging filesystem must be encrypted, private, and quota-limited. Host setup, filesystem quotas for broker staging, gVisor behavior, runtime resource enforcement, and cleanup must be independently validated before any activation. The sandbox image must contain `/usr/bin/exiftool`; the executable is not bundled with the application.

### Local AI summaries

Phase 7 adds `POST /cases/{case_id}/ai-summaries` for a source-cited summary of case and timeline metadata. Configure `DIGITAL_FORENSICS_OLLAMA_MODEL` and run Ollama locally; the endpoint is disabled when no model is configured. The Ollama URL must use a loopback IP, and requests contain only case metadata, never evidence binaries. Generated summaries and their exact source snapshot, model name, and prompt version are immutable and remain marked `unreviewed`. Provider calls are mocked in tests, and live Ollama behavior has not been validated.

### Frontend

Requires Node.js 20.9 or newer and npm.

```powershell
cd frontend
npm install
npm run dev
```

The dashboard is available at `http://localhost:3000`.

The case overview reads the API at `http://localhost:8000` by default. To use a different API origin, set `NEXT_PUBLIC_API_BASE_URL` when building/running the frontend and configure the backend's `DIGITAL_FORENSICS_FRONTEND_ORIGIN` to match the browser origin. Sign in through the configured OIDC provider. The Management section provides role-gated case and access management; evidence details expose acquisition records, append-only custody events, examiner-submitted digest comparisons, custody-chain verification, and processing-job status/results with queued-job cancellation. Only the custody-chain verification adapter is offered; ExifTool remains unavailable until independent sandbox validation. Examiners can request a local AI summary when Ollama is configured; generated summaries remain prominently marked **unreviewed** and their citations link to source records. Case-scoped search covers case/evidence metadata, timeline records, findings, reports, and AI summaries. Examiners can create immutable, source-cited findings and report drafts; assigned reviewers can append approval/rejection decisions, and the audit view shows case-changing user actions. Reports and findings retain source snapshots, and review decisions do not edit the original artifact.

### Local container integration

Docker Compose v2 is required. Copy `.env.example` to `.env`, set a URL-safe `POSTGRES_PASSWORD`, and set `DIGITAL_FORENSICS_SESSION_SIGNING_KEY` to a fresh value from `python -c "import secrets; print(secrets.token_urlsafe(48))"`. Configure OIDC values if you want to test sign-in, then run `docker compose up --build`. The API and frontend publish only on loopback; the worker is on an internal database-only network and has a read-only filesystem, dropped capabilities, and resource limits. Ollama is not included or configured, and ExifTool remains disabled. This Compose setup is for synthetic local data, not a production sandbox: database storage is not encrypted, image tags and npm dependency resolution are not locked, and no service was deployed or validated in this environment.

## Scope and limitations

Evidence upload and client-side envelope encryption are implemented but have not been validated against a live S3-compatible service or Vault cluster. Forensic parser execution remains disabled pending independent Linux broker/gVisor validation. SAML integration, invitations, PostgreSQL production validation, locked dependency builds, deployed staging, and production deployment are not complete. OIDC requires a configured identity provider and PostgreSQL database. MFA depends on identity-provider policy and must be verified before production use. Audit records cover user-initiated case mutations in this milestone; they do not replace infrastructure logs or privileged-database tamper detection. Do not use this foundation with real evidence or for production investigations. See `docs/ARCHITECTURE.md` for the roadmap and `docs/OPERATIONS.md` for release gates and operational readiness.
