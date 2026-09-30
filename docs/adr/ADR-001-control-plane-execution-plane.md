# ADR-001: Separate reasoning from execution

**Decision:** Agent reasoning and infrastructure execution are separate planes. The model may propose/select a capability; deterministic services authorize and execute it.

**Why:** reduces blast radius, supports least privilege, audit, idempotency, verification and rollback.

**Rejected:** unrestricted shell/tool access from the model.
