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
| Backend tests | pytest 8.x, HTTPX 0.x |
| Frontend runtime | Node.js 20.9+ |
| Frontend | Next.js 16.x, React 19.x, TypeScript 5.x |
| Styling | Tailwind CSS 4.x |
| Data services (later milestone) | PostgreSQL 17.x, OpenSearch 2.x, Redis 7.x |
| Background processing (later milestone) | Celery 5.x |
| Local AI and retrieval (later milestone) | Ollama, LlamaIndex, pgvector; validate model and extension versions against selected hardware and database |

Phase 1 declares bounded dependency ranges in `backend/pyproject.toml` and `frontend/package.json`; no dependency lockfiles have been generated. This machine has Python 3.15 but no Node.js or Docker on `PATH`, so compatibility with the documented minimum runtimes and frontend build still needs verification in a supported environment.

## Deployment strategy

- **Development:** local API and dashboard first. Later add Docker Compose services for PostgreSQL, Redis, OpenSearch, and local Ollama using synthetic data only.
- **Staging:** separate, production-like configuration and storage with test accounts and synthetic datasets. Exercise integration, authorization, security, and recovery before release.
- **Production:** provider-neutral design; select a provider only after approval. Use private networking, TLS, managed secrets, encrypted storage, least privilege, backups, monitoring, and an explicit release approval gate.
- **Local lab:** isolate forensic workers from public-facing services, restrict egress, encrypt storage, enforce resource limits, and keep originals read-only.
- Never expose database, queue, search, or worker ports publicly. Do not provision paid infrastructure or deploy without explicit approval.

Cloud-specific architecture and pricing should be compared only after the system owner chooses a target provider. Cloud failure must not silently switch evidence processing to an unapproved remote path.

## Milestones

1. **Foundation (in progress):** repository structure, API and dashboard skeleton, configuration, logging baseline, and tests.
2. **Database and authentication:** PostgreSQL migrations, organizations, identity integration, RBAC, and authorization tests.
3. **Cases and evidence:** case management, evidence registration, acquisition metadata, hashing, and append-only custody events.
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
| Unapproved evidence transfer to cloud AI | Disclosure of sensitive evidence | Local inference by default; explicit case-level authorization, data classification, and audit before remote processing |
| Untrusted evidence or parser output | Worker compromise or misleading artifacts | Isolated, constrained workers; format validation; retained raw output and tool provenance |
| AI-generated unsupported claims | Incorrect investigative conclusions | Grounded source references, explicit uncertainty, and mandatory examiner review |
| Supply-chain or runtime incompatibility | Build failure or exploitable dependency | Resolve exact versions, maintain lockfiles, scan dependencies and images, and test supported runtimes |
| Premature production deployment | Loss, exposure, or service outage | No paid provisioning or production release without approval; staging, backups, and tested rollback first |
| Incomplete operational recovery | Irrecoverable data or audit history | Encrypted backups, integrity checks, restoration exercises, and owner-approved recovery objectives |

## Phase 1 status

The initial API and dashboard scaffolds, configuration baseline, and focused health endpoint test are in place. The frontend build cannot be verified on the current machine because Node.js is unavailable, and Docker-based services have not been added. No forensic, authentication, persistence, or production feature is represented as complete.
