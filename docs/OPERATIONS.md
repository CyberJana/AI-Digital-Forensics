# Operations readiness gates

This runbook describes work required before any staging or production use. It is not evidence that these controls have been exercised. The local Compose stack is for synthetic data only.

## Release gate

Do not deploy until the system owner has approved the hosting provider, data classification, retention policy, recovery objectives, and incident contacts. The following remain mandatory:

- Validate the initial S3-compatible object store and Vault Transit envelope-encryption integration against approved services. Configure private, versioned buckets, retention, backups, Vault key rotation and recovery, and encrypted API scratch storage. Evidence uploads are limited to 10 GiB per file and one in-progress multipart upload per API process; the request limit allows 128 KiB of multipart overhead. Point each API process's `TMPDIR` at encrypted scratch storage sized for at least one maximum-size request plus operating headroom. The local Compose stack's 64 MiB `/tmp` is only suitable for small synthetic uploads. The application cannot verify that a temporary-storage mount is encrypted.
- Approve and independently validate an OS-level worker sandbox, filesystem policy, egress policy, and resource limits before enabling any parser.
- Configure PostgreSQL over TLS, enforce identity-provider MFA, verify OIDC assurance/configuration, and store secrets in an approved secret manager.
- Keep Python/npm lockfiles and container base-image digests current. CI audits Python/npm dependencies and scans the application and PostgreSQL images for high and critical OS/library vulnerabilities. Review/remediation of findings and scans of any additional production images remain release gates.
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
