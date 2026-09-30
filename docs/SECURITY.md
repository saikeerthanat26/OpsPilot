# Security model

The enterprise V0.5 path enforces trusted host ownership, capability roles, environment
scope and durable approval grants at ToolGateway. MCP arguments are strict and cannot
supply identity or approval credentials. Grants are opaque, short-lived, hash-stored,
run/plan/executor-bound and reserved atomically for each mutation. SQLite host leases
and operation reservations prevent duplicate and concurrent execution.

All `/v2` API endpoints require a server-resolved bearer identity. Tenant-filtered run
lookups prevent access to another team's runs; only scoped approvers may approve.
The resolver has no default credentials. It is intended for local demonstration and
must be replaced with OIDC plus TLS and managed secret handling for remote deployment.

Failed or uncertain execution is escalated and blocked from automatic replay. Durable
records do not provide exactly-once external effects or automatic crash recovery.
Simulator inventory remains in process; the legacy `/v1` route is an isolated simulator
example. The standalone stdio server has read-only authority.

See [ADR-006](adr/ADR-006-approval-grants-tenant-isolation.md) for the trust model,
concurrency controls, upgrade behavior and limitations.
