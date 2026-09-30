# ADR-008: Configured infrastructure providers behind MCP

## Decision

Keep the six narrow MCP capabilities and ToolGateway grant/tenant enforcement.
A provider router resolves trusted durable inventory into Kubernetes, AWS EC2/SSM,
Terraform, GitHub or durable simulator backends. Requests cannot choose credentials,
commands, namespaces or repositories. Existing target bindings are immutable through
inventory registration. Credentials stay outside persisted inventory/checkpoints.

Kubernetes applies one pinned container image with concurrency tests and a run
annotation. AWS invokes reviewed configured SSM documents for one instance/package.
Terraform applies a saved artifact bound by SHA-256, with exactly one known update.
GitHub opens a draft one-file PR and waits for human merge before reporting success.
Each provider records a receipt and provider-specific snapshot. Acknowledged results
can resume verification; unknown submissions require remote proof or escalation.
Terraform/GitHub do not pretend to have generic automatic rollback.

## Validation and limits

Provider tests exercise the complete MCP workflow through protocol sessions with
fake external APIs. They verify scoped target calls, rejection of drift/unsafe plans,
rollback snapshots, receipt reconciliation, and PR waiting/recovery. These are not
live account integration tests. PostgreSQL has a separate real-service CI job.
Operators supply scoped credentials, installed Terraform, SSM documents and trusted
inventory. Kubernetes rollback acknowledges desired-image restoration; independent
rollback health verification remains an operational check. OIDC, queue workers,
telemetry and production deployment certification are separate milestones.
