# ADR-005: MCP capability boundary

Status: Accepted for V0.4 reference implementation

V0.5 adds durable approval validation and tenant ownership enforcement; see
[ADR-006](ADR-006-approval-grants-tenant-isolation.md). The limits below describe V0.4.

## Decision

Enterprise LangGraph nodes use `MCPToolGateway` for every infrastructure capability,
including the planner's health and patch metadata reads. The MCP server exposes six
allowlisted tools with strict Pydantic-generated JSON schemas, structured results,
and sanitized error codes. ToolGateway enforces role, environment scope and approval
presence on the server before calling InfrastructureTools. MCP annotations describe
tools; they do not authorize them.

Flow: LangGraph → MCP client → MCP server → ToolGateway → InfrastructureTools → simulator.

Identity and approval are injected as trusted server context by the workflow. They
are excluded from tool argument schemas. Callers cannot change roles, tenant identity
or approval by adding arguments. Audit events record MCP calls and gateway decisions
without recording approval credentials.

## Transport and state

The workflow uses actual MCP ClientSession initialization and tools/call over the SDK's
in-memory streams. Each invocation opens and closes a bounded session while sharing the
existing simulator object. This preserves patch/verify/rollback state and is suitable
for this synchronous local reference. The SDK is constrained to its supported v1 API
(`mcp>=1.26,<2`). V2 migration requires updating the client/server integration.

`python -m app.mcp.server` exposes the same contracts over stdio in a separate process.
Its fixed local observer identity can only read. It has its own simulator lifetime;
the workflow does not spawn this process per call. A production adapter should reuse
an authenticated remote session against a durable infrastructure backend.

Calls have a deadline and propagate tool/transport failures. Mutations are never
retried automatically: timeout can mean an unknown execution outcome. Existing graph
failure behavior remains exception propagation; durable reconciliation of uncertain
mutations is a separate reliability milestone.

## Limits and next steps

This is a protocol boundary, not process isolation for the default workflow. Current
approval enforcement checks token presence, as in V0.3; it does not validate a signed,
expiring grant tied to a tenant, run, host, version and rollback scope. Tenant identity
is recorded but the demo inventory has no tenant ownership mapping. The existing HTTP
API also has no authenticated approver identity. Before remote mutations, implement
those authorization checks, authenticated transport, durable operation IDs and
reconciliation. Never accept a caller's identity or approval string as proof of access.

The original V0.1 demo intentionally retains its direct local tools for compatibility.
The enterprise `/v2` workflow uses MCP.
