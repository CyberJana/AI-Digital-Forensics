# Architecture and implementation plan

## System architecture

The target is a provider-neutral hybrid platform. A local forensic lab remains the authority for original evidence, acquisition, working copies, hash verification, and sensitive processing. A separately deployable central application manages identities, case metadata, approved processing, search, and reports. The local lab synchronizes only authenticated, explicitly permitted data; evidence and AI inputs remain local unless a case-level authorization and security review allow otherwise.

The application is organized as a modular backend API, a browser dashboard, and separately isolated processing workers. PostgreSQL stores transactional metadata, authorization relationships, custody events, and audit records. Encrypted object storage holds evidence and large raw outputs. OpenSearch indexes derived artifacts, and pgvector supports approved retrieval workloads. Phase 4 starts with a database-backed job queue and a separate worker process; Redis and Celery remain potential scale-out options for a later milestone. The current process boundary is not an OS-level sandbox. Forensic adapters must eventually run in constrained workers against verified working copies and preserve raw output and tool/parser/execution provenance. Local Ollama is the default inference path, behind an AI provider interface that requires explicit authorization for any cloud provider.

Data flow, once those milestones are implemented:

1. Register an acquisition and record metadata and a SHA-256 digest; keep the local original read-only. When an authorized case requires central storage, encrypt the uploaded bytes client-side before writing ciphertext to the object store.
2. Create and verify a controlled local working copy before analysis.
3. Execute a validated adapter in a constrained worker and retain raw output, logs, exit status, and provenance.
4. Normalize derived artifacts into case-scoped records and indexes with access checks.
5. Present AI output as unapproved analysis with source links; an authorized human reviews findings and reports.
6. Append custody and audit events for consequential operations.

The storage upload and client-side encryption path is implemented as an initial integration; provider policy, scratch storage, retention, backup/recovery, and live service behavior remain unvalidated.

## Dependency baseline

These are target compatibility lines, not a resolved lockfile. Resolve and test exact patch versions before each milestone is deployed; do not infer compatibility solely from these ranges.

| Area | Target |
| --- | --- |
| Backend runtime | Python 3.12+ |
| API and encrypted storage | FastAPI 0.x, Pydantic 2.x, pydantic-settings 2.x, Uvicorn 0.x, Boto3, HTTPX, Cryptography |
| Persistence and migrations | SQLAlchemy 2.x, Alembic 1.x, psycopg 3.x |
| Authentication | Authlib 1.x, generic OIDC authorization-code flow, signed state cookie, opaque server-side sessions |
| Backend tests | pytest 8.x, HTTPX 0.x, SQLite for isolated tests |
| Frontend runtime | Node.js 20.9+ |
| Frontend | Next.js 16.x, React 19.x, TypeScript 5.x |
| Styling | Tailwind CSS 4.x |
| Data services (later milestone) | PostgreSQL 17.x, OpenSearch 2.x, Redis 7.x |
| Background processing (later milestone) | Celery 5.x |
| Local AI and retrieval (later milestone) | Ollama, LlamaIndex, pgvector; validate model and extension versions against selected hardware and database |

Phases 1–4 declare dependency ranges in `backend/pyproject.toml` and `frontend/package.json`; hashed Python locks are generated for Python 3.12, and npm uses a committed lockfile. CI and container builds install from those locks, and Docker base images are pinned by manifest digest. Backend tests and migration compatibility have also been checked with Python 3.15 and SQLite. PostgreSQL and an external identity provider are not configured in this environment, so production database and live OIDC behavior remain unverified.

Phase 4 uses the relational database for job claims and lease recovery, so it adds no Redis/Celery dependencies. The worker and API must use the same migrated database. Production concurrency and row-lock behavior still require verification on PostgreSQL.

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
3. **Cases and evidence (initial implementation):** case management and assignments, evidence metadata and acquisition records, local read-only SHA-256 hashing, examiner-submitted hash comparisons, append-only hash-linked custody events, and optional S3-compatible uploads encrypted with per-object AES-256-GCM data keys wrapped by Vault Transit. Live object storage, Vault, key-rotation/recovery, encrypted temporary storage, and retention/backup controls still require validation.
4. **Processing framework (initial implementation):** case-scoped job lifecycle, database queue, separate worker process, adapter contract, verified local working copies, and lease-based recovery. OS-level worker sandboxing and actual forensic adapters remain future work.
5. **Tool integrations (initial scaffold):** implement an ExifTool metadata adapter and provenance contract; keep execution disabled pending approved OS-level sandboxing and review of applicable license terms.
6. **Analysis modules (initial implementation):** provide a read-only case timeline from acquisition and custody metadata, with custody-chain verification; add domain-specific analysis incrementally and mark each module by actual implementation and test status.
7. **AI investigation (initial implementation):** generate source-cited case summaries from stored case/timeline metadata through local Ollama; keep outputs as immutable, unreviewed records with source and prompt provenance.
8. **Dashboard and reporting (initial implementation):** case-scoped search, timeline, immutable findings and report drafts, append-only review decisions, source provenance, and audit views.
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

## Trust boundaries and threat model

The original evidence file and any working copy are untrusted, potentially hostile inputs. OIDC claims, user-submitted case/evidence metadata, and AI output are also untrusted. Case/organization authorization is enforced in API handlers; the browser's role checks only control presentation and are never an authorization boundary. Every route returning case data must perform the same case-access check, and every state-changing route must require CSRF protection.

The application accepts evidence binaries only when S3-compatible storage and Vault Transit are configured. It hashes incoming bytes, encrypts them with a per-object AES-256-GCM key, wraps each key with Vault Transit, and verifies the plaintext digest before download. This does not protect plaintext held temporarily by the web framework or operating-system scratch storage; production needs encrypted scratch volumes, request-size controls, private/versioned buckets, tested backups, and Vault key recovery. Forensic parsers remain disabled; the separate worker is not yet isolated by an OS/container policy. Local AI receives case and timeline metadata only, uses a loopback endpoint, validates source citations, and persists output as unreviewed. Finding/report snapshots and review decisions are append-only under ordinary database operations. Case audit events cover user-triggered mutations, but are not hash-chained or protected from privileged database modification; access-download requests are logged, while other read and infrastructure events are not included.

Production threats still requiring mitigation and validation include compromised identity-provider configuration or session secrets; cross-tenant authorization regressions; malicious files exploiting a future parser; privileged database tampering; credential or connection-string exposure; unbounded database/search workloads; dependency or image compromise; and incomplete backup/restore. Do not treat application-level append-only triggers as tamper-proof evidence storage or deploy until the outstanding isolation, key-management, PostgreSQL, monitoring, recovery, and independent security-review gates are complete.

## Phase 1 status

The initial API and dashboard scaffolds, configuration baseline, and focused health endpoint test are in place. The frontend build cannot be verified on the current machine because Node.js is unavailable, and Docker-based services have not been added. No forensic or production feature is represented as complete.

## Phase 2 status

The backend now defines organizations, users, external OIDC identities, memberships, and revocable server-side sessions. Authenticated API requests are scoped to active memberships; organization management enforces owner/admin roles and CSRF tokens. OIDC configuration remains external in development; staging and production settings require a database and OIDC configuration. Database migration, auth-session, and authorization tests run against SQLite. Live PostgreSQL and identity-provider behavior remain unverified. MFA is delegated to the identity provider and is not yet checked against provider-specific assurance claims, so production authentication is not yet ready for release.

## Phase 3 status

Cases are scoped to organizations and assignments, while owner/admin case overrides are limited to organization members. Evidence registration stores metadata, acquisition details, and an examiner-reported initial SHA-256 digest; the local `digital-forensics-hash` utility hashes regular files in chunks and checks file identity, size, and modification time before and after reading. The API does not access the source file or validate that the submitted digest came from that utility. It records digest comparisons, not independent source verification.

Custody events are append-only under ordinary database operations, linked by sequence and SHA-256 hashes, and verified by a read endpoint. Acquisition, hash-verification, and custody rows have SQLite and PostgreSQL mutation-blocking triggers. These controls do not protect against privileged database operators who can alter data or disable triggers. Optional evidence upload uses S3-compatible storage and Vault Transit envelope encryption; live service integration, encrypted scratch storage, key rotation/recovery, object retention, backups, PostgreSQL behavior, and production readiness remain unverified.

## Phase 4 status

Processing jobs are case/evidence scoped and restricted to case owners/examiners and organization owners/admins. A database-backed queue claims jobs with row locks and conditional updates, records bounded attempts, and requeues expired worker leases until the configured attempt limit is reached. The worker runs separately from the API and persists bounded JSON results or non-sensitive error codes. Its initial adapter verifies custody-chain metadata; it does not read evidence binaries. A local command creates a hash-verified read-only working copy without modifying the source.

This is an initial process boundary, not a security sandbox: worker CPU, memory, filesystem access, and egress are not constrained at the OS/container level. Long-running adapters, parser execution, and result/artifact storage remain unimplemented. PostgreSQL locking behavior, encrypted evidence storage, key rotation/recovery, and production recovery must be exercised before deployment.

## Phase 5 status

The ExifTool metadata adapter has a JSON-based command contract, output validation, source-path field removal, a verified-working-copy digest, and tool version/license/source provenance. The API rejects this adapter while it is disabled, the worker independently refuses to run disabled adapters, and the metadata collector requires a sandbox runner that has not been implemented. The executable is not bundled and has not been run in this environment. ExifTool's upstream README states that it may be redistributed under either the Perl Artistic License or GPL; the applicable license and distribution obligations still require review. No OS-level sandbox exists, so enabling the adapter or running it on evidence is explicitly blocked until sandbox isolation is approved and validated.

## Phase 6 status

The initial analysis module exposes a read-only case timeline that merges acquisition events by their acquired time and custody events by their recorded time. The response includes source-record identifiers, evidence and actor references, acquisition details, and a per-evidence custody-chain verification summary. It reads stored database metadata only; evidence binaries and parser output are not processed.

## Phase 7 status

The initial AI feature creates source-cited summaries from case and timeline metadata using a loopback-only Ollama endpoint. It rejects model citations that do not refer to supplied records and stores the model name, prompt version, exact source snapshot, and unreviewed output in an append-only table. No model is selected by default, cloud providers are not supported, and live Ollama behavior is unverified. Reviewer decisions, retrieval over unstructured documents, and evidence-file inputs remain future work.

## Phase 8 status

The dashboard provides organization and case selection, a chronologically ordered acquisition/custody timeline, custody-chain state, and explicitly unreviewed AI summaries with source links. Case-scoped search covers case and evidence metadata, timeline records, findings, reports, and AI summaries. Examiners can create immutable, source-cited findings and reports; reviewers append decisions rather than changing the originals. Reports snapshot their included findings and citations. Case-changing user actions are written to an append-only, case-scoped audit log in the same database transaction. Search is backed by the relational database and is intended for bounded case datasets, not large-scale full-text indexing. No export/PDF format, external search index, or independent audit-log tamper detection is implemented.

## Phase 9 status

The API has negative authorization tests for unassigned users and case-scoped reporting routes, migration tests for append-only records, and configuration checks requiring PostgreSQL, OIDC, secure cookies, and HTTPS origins outside development. GitHub Actions runs backend tests, Bandit, Python dependency audits, frontend lint/build and npm audit, plus backend/frontend container builds; Dependabot checks Python, npm, GitHub Actions, and Docker bases weekly. Pull-request CI installs from the committed lockfiles and validates application images built from digest-pinned bases. No independent security assessment has been completed.

## Phase 10 status

Initial API, worker, and standalone Next.js images and a local Compose topology are defined. The API and frontend publish only on host loopback; the worker has no public port, uses an internal database-only network, a read-only root filesystem, dropped capabilities, no-new-privileges, and resource limits. Compose includes PostgreSQL health checks and a one-shot migration service. Application and Compose database base images are pinned by digest; pull-request CI builds both application images. The worker container is defense in depth, not an approved OS-level forensic sandbox; evidence-file parsing remains disabled. Database encryption, host-level controls, image vulnerability scanning, and independent sandbox validation remain release blockers.
