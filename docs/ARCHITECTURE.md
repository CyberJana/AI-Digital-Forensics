# Architecture and implementation plan

## System architecture

The target is a provider-neutral hybrid platform. A local forensic lab remains the authority for original evidence, acquisition, working copies, hash verification, and sensitive processing. A separately deployable central application manages identities, case metadata, approved processing, search, and reports. The local lab synchronizes only authenticated, explicitly permitted data; evidence and AI inputs remain local unless a case-level authorization and security review allow otherwise.

The application is organized as a modular backend API, a browser dashboard, and separately isolated processing workers. PostgreSQL stores transactional metadata, authorization relationships, custody events, and audit records. Encrypted object storage holds evidence and large raw outputs. OpenSearch indexes derived artifacts, and pgvector supports approved retrieval workloads. Redis and Celery are planned for bounded background jobs. Forensic adapters run only in controlled workers against verified working copies; they preserve raw output and record tool, parser, and execution provenance. Local Ollama is the default inference path, behind an AI provider interface that requires explicit authorization for any cloud provider.

Data flow, once those milestones are implemented:

1. Register an acquisition and record metadata and an initial SHA-256 digest; keep the original read-only.
2. Create and verify a controlled working copy before analysis.
3. Execute a validated adapter in an isolated worker and retain raw output, logs, exit status, and provenance.
4. Normalize derived artifacts into case-scoped records and indexes with access checks.
5. Present AI output as unapproved analysis with source links; an authorized human reviews findings and reports.
6. Append custody and audit events for consequential operations.

These are architectural requirements, not claims that these controls are implemented in the current foundation.

## Dependency baseline

These are target compatibility lines, not a resolved lockfile. Resolve and test exact patch versions before each milestone is deployed; do not infer compatibility solely from these ranges.

| Area | Target |
| --- | --- |
| Backend runtime | Python 3.12+ |
| API | FastAPI 0.x, Pydantic 2.x, pydantic-settings 2.x, Uvicorn 0.x |
| Persistence and migrations | SQLAlchemy 2.x, Alembic 1.x, psycopg 3.x |
| Authentication | Authlib 1.x, generic OIDC authorization-code flow, signed state cookie, opaque server-side sessions |
| Backend tests | pytest 8.x, HTTPX 0.x, SQLite for isolated tests |
| Frontend runtime | Node.js 20.9+ |
| Frontend | Next.js 16.x, React 19.x, TypeScript 5.x |
| Styling | Tailwind CSS 4.x |
| Data services (later milestone) | PostgreSQL 17.x, OpenSearch 2.x, Redis 7.x |
| Background processing (later milestone) | Celery 5.x |
| Local AI and retrieval (later milestone) | Ollama, LlamaIndex, pgvector; validate model and extension versions against selected hardware and database |

Phases 1–3 declare bounded dependency ranges in `backend/pyproject.toml` and `frontend/package.json`; no dependency lockfiles have been generated. Backend tests and migration compatibility have been checked with Python 3.15 and SQLite. PostgreSQL and an external identity provider are not configured in this environment, and there is no Node.js or Docker on `PATH`, so production database, live OIDC, and frontend compatibility remain unverified.

## Deployment strategy

- **Development:** local API and dashboard first. Later add Docker Compose services for PostgreSQL, Redis, OpenSearch, and local Ollama using synthetic data only.
- **Staging:** separate, production-like configuration and storage with test accounts and synthetic datasets. Exercise integration, authorization, security, and recovery before release.
- **Production:** provider-neutral design; select a provider only after approval. Use private networking, TLS, managed secrets, encrypted storage, least privilege, backups, monitoring, and an explicit release approval gate.
- **Local lab:** isolate forensic workers from public-facing services, restrict egress, encrypt storage, enforce resource limits, and keep originals read-only.
- Never expose database, queue, search, or worker ports publicly. Do not provision paid infrastructure or deploy without explicit approval.

Cloud-specific architecture and pricing should be compared only after the system owner chooses a target provider. Cloud failure must not silently switch evidence processing to an unapproved remote path.

## Milestones

1. **Foundation (complete):** repository structure, API and dashboard skeleton, configuration, logging baseline, and tests.
2. **Database and authentication (complete):** PostgreSQL migrations, OIDC identity integration, organizations, memberships, role checks, and authorization tests. The initial implementation is OIDC-only; SAML remains future work.
3. **Cases and evidence (implemented; production use blocked on storage design):** case management and assignments, evidence metadata and acquisition records, local read-only SHA-256 hashing, examiner-submitted hash comparisons, and append-only hash-linked custody events. Evidence binaries are not stored or uploaded.
4. **Processing framework:** job lifecycle, isolated workers, adapter contracts, verified working copies, and recovery behavior.
5. **Tool integrations:** implement and validate individual adapters with licensing and provenance checks.
6. **Analysis modules:** add domain-specific analysis incrementally; mark each module by actual implementation and test status.
7. **AI investigation:** local inference, retrieval, provider authorization, grounding, and human review.
8. **Dashboard and reporting:** case-scoped search, timeline, findings, report provenance, and audit views.
9. **Security and quality:** threat modeling, authorization and tenant tests, dependency/container checks, and performance tests.
10. **Containerization:** service images, Compose environments, health checks, and worker isolation.
11. **Staging:** deploy only to an approved staging environment and execute acceptance tests.
12. **Production:** deploy only with explicit approval, release controls, and verified rollback.
13. **Operations:** backup and restore tests, recovery objectives approved by the owner, monitoring, and incident procedures.

Stop after each milestone for user review and approval before beginning the next one.

## Risk assessment

| Risk | Impact | Required mitigation |
| --- | --- | --- |
| Accidental modification or loss of original evidence | Invalidates investigation | Read-only originals, verified working copies, before/after hashes, and tested recovery procedures |
| Cross-case or cross-tenant access | Exposure and evidentiary integrity failure | Deny-by-default authorization at every data access boundary; automated negative tests |
| Identity-provider MFA misconfiguration | Unauthorized access despite centralized sign-in | Require provider-enforced MFA and verify the provider's assurance claims before production release |
| Unapproved evidence transfer to cloud AI | Disclosure of sensitive evidence | Local inference by default; explicit case-level authorization, data classification, and audit before remote processing |
| Untrusted evidence or parser output | Worker compromise or misleading artifacts | Isolated, constrained workers; format validation; retained raw output and tool provenance |
| AI-generated unsupported claims | Incorrect investigative conclusions | Grounded source references, explicit uncertainty, and mandatory examiner review |
| Supply-chain or runtime incompatibility | Build failure or exploitable dependency | Resolve exact versions, maintain lockfiles, scan dependencies and images, and test supported runtimes |
| Premature production deployment | Loss, exposure, or service outage | No paid provisioning or production release without approval; staging, backups, and tested rollback first |
| Incomplete operational recovery | Irrecoverable data or audit history | Encrypted backups, integrity checks, restoration exercises, and owner-approved recovery objectives |

## Phase 1 status

The initial API and dashboard scaffolds, configuration baseline, and focused health endpoint test are in place. The frontend build cannot be verified on the current machine because Node.js is unavailable, and Docker-based services have not been added. No forensic or production feature is represented as complete.

## Phase 2 status

The backend now defines organizations, users, external OIDC identities, memberships, and revocable server-side sessions. Authenticated API requests are scoped to active memberships; organization management enforces owner/admin roles and CSRF tokens. OIDC configuration remains external in development; staging and production settings require a database and OIDC configuration. Database migration, auth-session, and authorization tests run against SQLite. Live PostgreSQL and identity-provider behavior remain unverified. MFA is delegated to the identity provider and is not yet checked against provider-specific assurance claims, so production authentication is not yet ready for release.

## Phase 3 status

Cases are scoped to organizations and assignments, while owner/admin case overrides are limited to organization members. Evidence registration stores metadata, acquisition details, and an examiner-reported initial SHA-256 digest; the local `digital-forensics-hash` utility hashes regular files in chunks and checks file identity, size, and modification time before and after reading. The API does not access the source file or validate that the submitted digest came from that utility. It records digest comparisons, not independent source verification.

Custody events are append-only under ordinary database operations, linked by sequence and SHA-256 hashes, and verified by a read endpoint. Acquisition, hash-verification, and custody rows have SQLite and PostgreSQL mutation-blocking triggers. These controls do not protect against privileged database operators who can alter data or disable triggers. Evidence binaries, encrypted storage, key management, live PostgreSQL behavior, and production readiness remain out of scope; Phase 4 must not begin until the user approves the next milestone.
