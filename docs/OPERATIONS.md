# Operations readiness gates

This runbook describes work required before any staging or production use. It is not evidence that these controls have been exercised. The local Compose stack is for synthetic data only.

## Release gate

Do not deploy until the system owner has approved the hosting provider, data classification, retention policy, recovery objectives, and incident contacts. The following remain mandatory:

- Validate the initial S3-compatible object store and Vault Transit envelope-encryption integration against approved services. Configure private, versioned buckets, retention, backups, Vault key rotation and recovery, and encrypted API scratch storage. Evidence uploads are limited to 10 GiB per file and one in-progress multipart upload per API process; the request limit allows 128 KiB of multipart overhead. Point each API process's `TMPDIR` at encrypted scratch storage sized for at least one maximum-size request plus operating headroom. The local Compose stack's 64 MiB `/tmp` is only suitable for small synthetic uploads. The application cannot verify that a temporary-storage mount is encrypted.
- Approve and independently validate an OS-level worker sandbox, filesystem policy, egress policy, and resource limits before enabling any parser.
- For the optional ExifTool path, operate the broker under a dedicated unprivileged Linux account with rootless Podman and a locally preloaded digest-pinned image. Configure that user's Podman runtime to use gVisor `runsc`; provision a private broker-owned encrypted staging filesystem with an enforced quota, private home/runtime directories, and a Unix socket owned by the broker and a worker-only group. The broker checks the connecting worker UID and accepts only its fixed ExifTool operations and a read-only input descriptor; it has no database credentials and does not expose a Docker/OCI socket. Mount that socket only into the dedicated worker, never the API, and leave `DIGITAL_FORENSICS_EXIFTOOL_SANDBOX_ENABLED=false` until independent validation is complete. The default Compose topology does not mount or configure this socket, and the API continues to reject ExifTool jobs.
- Install the backend package for the broker account and run `digital-forensics-exiftool-broker` with required `--socket-path`, `--socket-gid`, `--worker-uid`, `--staging-root`, `--sandbox-image`, `--podman-path`, `--home`, and `--runtime-dir` arguments. The image argument must be a preloaded `name@sha256:<64-hex-digest>`; the broker rejects mutable tags. Verify under that account that `podman info` reports rootless operation, cgroup v2 with the systemd manager, and a configured `runsc` runtime before starting the service. In the worker environment, set `DIGITAL_FORENSICS_EXIFTOOL_SANDBOX_ENABLED=true`, the absolute broker socket path visible inside the worker, and the verified working-copy root only after the release gate is signed off. Configure the broker's expected worker UID to the host UID actually observed for the worker process.
- Before any activation, verify the broker's OS identity and socket permissions, rootless Podman and `runsc` selection, pinned image contents, input descriptor/hash behavior, read-only host/container mounts, network and credential isolation, cgroup/resource enforcement, output/time limits, failure cleanup, restart behavior, and staging filesystem quota on the target Linux host. Use synthetic fixtures only. Mock/CI tests are not independent host/runtime validation.
- Configure PostgreSQL over TLS, enforce identity-provider MFA, verify OIDC assurance/configuration, and store secrets in an approved secret manager.
- Keep Python/npm lockfiles and container base-image digests current. CI audits Python/npm dependencies and reports high and critical OS/library vulnerabilities in the application and PostgreSQL images. The local PostgreSQL image rebuilds the upstream `gosu` release from a pinned source commit with a digest-pinned Go toolchain to avoid its vulnerable bundled Go runtime. Review/remediation of findings and scans of any additional production images remain release gates; a passing CI run does not approve an image for production.
- Exercise migrations, authorization and tenant-isolation tests, load/performance limits, backup/restore, and rollback in an approved staging environment.
- Complete an independent threat-model/security review. The application audit table is not tamper-proof and does not replace platform audit logs.

## Startup and migration order

1. Validate environment-specific settings and secret references without printing secret values. In staging/production, use Vault Agent auto-authentication and its renewable token file rather than a static Vault token.
2. Verify PostgreSQL health and connectivity, then take a recoverable backup before a schema change.
3. Run the one-shot Alembic migration service and confirm it exits successfully.
4. Start the API and worker only after migration success; verify `/health` and `/health/ready`.
5. Verify the frontend origin, OIDC callback, TLS, and cookie settings before inviting test users.

The Compose file implements local startup ordering only. Production deployment, rolling upgrades, database HA, secret rotation, and rollback have not been tested. Prefer restoring a verified backup into a new isolated database over running a destructive downgrade against production data.

## Backup and restore

The owner must set recovery point and recovery time objectives before selecting schedules or retention. Use the database provider's encrypted backup mechanism or `pg_dump --format=custom` over an authenticated TLS connection, then encrypt backup artifacts with managed keys before transfer or retention. Keep keys separate from backups and restrict restore access.

For each restore exercise, restore to a new isolated database, verify Alembic revision and critical row counts, verify custody chains and representative source/report snapshots, and record duration and integrity results. Restore encrypted evidence objects and their database metadata together; a database restore without matching object versions or Vault key versions can make evidence unrecoverable. Do not overwrite the production database during a test. No backup automation, object-storage backup, restore test, or recovery objective is currently configured.

## Monitoring and incidents

`/health` is a liveness check; `/health/ready` verifies database connectivity, not S3 or Vault availability. These endpoints are not a monitoring system. Before release, configure authenticated infrastructure monitoring for availability, database capacity/latency, worker queue age/failures, resource limits, object-storage and Vault failures, backup completion, and security-relevant administrative activity. Keep credentials, OIDC/Vault tokens, case narratives, evidence hashes, and AI prompts out of routine logs and alert payloads.

For a suspected compromise or evidence-integrity incident, restrict access and egress using the hosting platform, preserve relevant identity-provider, database, network, and host logs, record the incident timeline, and use the approved incident commander and legal/forensic procedures. Rotate affected credentials through the secret manager after preserving necessary evidence. Do not modify or delete case records to conceal or repair an incident; maintain the original state and record approved corrective actions as new events.

## Readiness status

No staging or production deployment has been performed. Docker, frontend build tools, PostgreSQL, OIDC, S3-compatible storage, Vault Transit, and an external monitoring/backup platform were unavailable or unconfigured in the implementation environment. Readiness is therefore incomplete pending the release gates above.
