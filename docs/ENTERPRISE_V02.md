# OpsPilot V0.2 — Enterprise Control Plane

V0.2 changes the demo from a single synchronous SRE workflow into the beginning of a reusable control plane.

## Added
- Tenant/team boundary on every enterprise run.
- Explicit agent identity and roles.
- Capability registry with mutating/read-only classification and required roles.
- Tool Gateway enforcing identity, roles and approval before mutations.
- Durable SQLite run state so approval is a separate API operation.
- Provider-neutral model routing seam.
- Full agency-chain events: model route, evidence package, policy decision, approval and every tool invocation.
- Async-shaped API: create incident returns 202; inspect run; approve separately; inspect trajectory.
- Failure path still verifies, rolls back and escalates.

## Architecture rule
AI proposes and reasons. Policy authorizes. Narrow deterministic tools execute. Verification decides success. No generic shell capability exists.

## V0.3 target
Replace the in-process capability gateway with real MCP servers and signed capability metadata; add LangGraph durable state/checkpointing, OPA/Rego policy-as-code, OpenTelemetry, and an actual model gateway (local OSS + Bedrock-compatible adapter).
