# ADR-007: SQL persistence and checkpoint recovery

## Decision

Use SQLAlchemy for SQLite/PostgreSQL control-plane records and official LangGraph
SqliteSaver/PostgresSaver for execution checkpoints. Preserve the V0.5 table layout
and add inventory, snapshots, receipts, operation results, audit and worker leases.
Alembic records an additive baseline. Startup serializes schema changes; PostgreSQL
advisory locks serialize short approval/ledger transactions across processes.
External calls never hold those locks.

Persist JSON graph inputs/results; inject backend, trace sink, approval credential and
worker identity only at runtime. A five-minute lease and per-node renewal fence
recovery against an active worker. Approver-authorized recovery issues a new scoped
grant and invalidates old grants, resumes pending nodes and reuses proven results.
Uncertain outcomes retain the host lease and escalate. Simulator mutation, snapshot
and receipt commit atomically; external providers cannot offer that atomicity.
Audit writes happen synchronously at each event. Inspect checkpoint and audit API
routes after a crash even if the run payload was not finalized.

## Limits

There is no distributed transaction with external APIs or automatic recovery daemon.
A timeout does not cancel a running SDK thread. Remote proof is required before an
unknown operation can resume. Retained leases require operational reconciliation,
not a force-unlock endpoint. PostgreSQL does not import prior SQLite records; moving
a deployment requires an explicit data migration. This release retains synchronous
request-driven execution and local bearer identity resolution.
