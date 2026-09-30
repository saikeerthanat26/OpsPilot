# ADR-006: Durable approval grants and tenant isolation

Status: Accepted for V0.5 reference implementation

## Problem

V0.4 checked only whether an approval string was present. Tenant identity was
recorded without inventory ownership enforcement, and two approval requests could
race while a run remained WAITING_APPROVAL. The HTTP approver field was unauthenticated.

## Decision

ToolGateway checks trusted inventory ownership, required role and environment scope
before exposing host data or executing capabilities. The simulator assigns its demo
host to `platform-sre` by default. A different tenant is configured in trusted inventory,
never by copying the incident request's tenant onto the host. Admin roles cannot bypass
ownership or scope checks.

ApprovalStore issues cryptographically random opaque grants with a five-minute default
lifetime. SQLite stores only the token hash plus the tenant, run, complete approved plan,
executor identity and authenticated approver. The approved plan binds the host, package,
source version, target version, CVE and plan ID. Mutations reject expiry, forged tokens,
scope mismatch, altered plans and replay. The patch also checks source-version drift
against the current inventory before dispatch.

An atomic SQLite transaction claims WAITING_APPROVAL → EXECUTING, issues the grant and
leases the tenant/host. A unique operation reservation allows one patch and one rollback
per run. Rollback requires a successful patch belonging to that run. Reservations survive
server recreation because they live outside the MCP session. Grant credentials stay in
trusted server context and are absent from tool schemas, responses and audit events.

Repeated approval of SUCCEEDED or ROLLED_BACK returns the persisted outcome. Approval
of an executing or escalated run conflicts. Concurrent runs cannot mutate a leased host.
Only a successful terminal execution or completed rollback releases the host lease.

## Failures and recovery

A reservation is STARTED before backend dispatch, then SUCCEEDED after return. Backend
exceptions conservatively mark it UNKNOWN. Workflow exceptions persist ESCALATED with
the execution audit and operation states; the lease remains. A process crash may leave
EXECUTING/STARTED. Neither case is retried automatically. This is durable duplicate
suppression, not exactly-once execution against an external infrastructure service.
There is intentionally no force-unlock or automatic reconciliation endpoint in V0.5.
Inventory drift can also retain a lease conservatively even when no patch was attempted.

Grant expiry applies to rollback too. If a long operation outlives its grant, reconciliation
and a fresh recovery authorization are needed; unsafe fallback is not allowed.

## HTTP identity

All `/v2` endpoints require a bearer token resolved using server-configured
`OPSPILOT_API_IDENTITIES`. No built-in identity or credential bypass exists. Claims define
subject, tenant, roles and environment scopes. Run lookup and events are tenant-filtered;
foreign runs return 404. Reads require environment scope; approvals additionally require
an `approver` role. Approver names and agent identity come from the resolved principal,
not request fields. Approval requests now send `{}`; `approver` and `agent_id` body fields
are rejected. Requested tenant must match the principal.

This is a local authenticated reference, not OIDC. Replace the resolver with verified
OIDC/JWT claims and deploy with TLS, managed secrets, access review and rotation before
remote use. Internal Python workflow calls remain a trusted application interface and
must not be exposed as an unauthenticated transport.

## Compatibility and limitations

Schema changes are additive. Existing run records remain readable by their owning
principal, but approval now requires actual host ownership; old arbitrary tenant labels
are not automatically reassigned. Legacy `/v1` operations remain an isolated simulator
example with no shared enterprise backend. The stdio MCP server stays read-only.

Simulator inventory and snapshots remain in process. V0.5 does not persist infrastructure
state across workers or restore a crashed execution. The API creates a simulator per
request, so its durable runs do not represent durable real-world inventory. Remote MCP,
external idempotency keys, reconciliation and durable inventory remain separate milestones.
