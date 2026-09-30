# OpsPilot — Governed Agentic SRE Control Plane

OpsPilot is a production-shaped reference implementation for evolving a successful operations-assistant POC into an enterprise agentic platform. It automates diagnosis and remediation planning while keeping infrastructure execution deterministic, policy-governed, observable, auditable, and reversible.

## Why this exists
A common enterprise evolution is: **chat assistant → useful POC → organizational adoption → production control-plane problem**. The hard part is no longer prompting. It is safe execution, durable workflow state, integration contracts, failure recovery, observability, evaluation, security, and scaling teams without architectural fragmentation.

OpsPilot demonstrates that transition with one end-to-end SRE use case: investigate a degraded production host with a critical vulnerability, gather evidence, retrieve a runbook, create a remediation plan, classify risk, require approval when policy demands it, execute a canary patch through a narrow tool contract, validate health, and automatically roll back on failure.

## Architecture principles
1. **Probabilistic reasoning is separated from deterministic execution.**
2. **The model is never the security boundary.** Authorization and policy are deterministic.
3. **Tools are narrow capabilities, not arbitrary shell access.**
4. **Autonomy is progressive.** Observe → recommend → approval-required → bounded autonomy.
5. **Critical state lives outside the model context.**
6. **Every action is evidence-backed and auditable.**
7. **Failures are first-class:** retry budgets, idempotency, verification, rollback, escalation.
8. **Provider-independent inference:** orchestration is decoupled from the model runtime.

## Quick start — zero cloud credentials
Requires Python 3.11+.

```bash
pip install -r requirements.txt
python demo.py
python demo.py --failure
python -m pytest -q
```

Optional API:
```bash
pip install -r requirements.txt
uvicorn app.api.main:app --reload
```
Then open `/docs`.

## Demo scenario
`prod-api-01` has high CPU and a critical OpenSSL vulnerability. OpsPilot gathers host health, vulnerability and runbook evidence; creates a typed patch plan; evaluates blast radius and production policy; pauses for approval; executes a canary patch; verifies health; and either completes or rolls back.

## Repository map
- `app/domain`: typed contracts and workflow state
- `app/agents`: bounded reasoning responsibilities
- `app/orchestration`: explicit state-machine workflow
- `app/tools`: narrow infrastructure capability contracts
- `app/policy`: deterministic autonomy/risk engine
- `app/execution`: deterministic executor + rollback
- `app/retrieval`: runbook/incident knowledge retrieval
- `app/observability`: structured trace/audit events
- `simulator`: safe local infrastructure simulator
- `evals`: golden SRE scenarios and scoring
- `docs/adr`: architectural decision records
- `kubernetes`, `terraform`: productionization examples

## What makes this different from a chatbot
The interesting output is not prose. It is the **execution trajectory**: evidence → decision → policy → approval → tool invocation → verification → rollback/success. The same control plane can later support Slack, web, API, ServiceNow/Jira, OpenStack, Kubernetes, or cloud interfaces without coupling orchestration to a single channel.

## Production evolution
The enterprise API uses durable SQL storage and LangGraph checkpoints, with a safe simulator by default and opt-in Kubernetes, AWS, Terraform and GitHub providers. PostgreSQL supports shared control-plane state across replicas. Queue-backed workers, OIDC, centralized secrets, telemetry and model routing remain future milestones.

See `ARCHITECTURE.md`, `INTERVIEW_DEFENSE.md`, and `docs/adr/`.

## V0.4 — MCP boundary

Enterprise workflows now send all infrastructure calls through a real MCP session,
including planner reads, approved patching, verification and rollback. The server
validates strict tool arguments and enforces ToolGateway authorization. The default
transport uses in-memory protocol streams so the local simulator remains shared.

Run the separate read-only stdio server from the repository root:

```bash
python -m app.mcp.server
```

Connect an MCP client with command `python` and arguments `-m app.mcp.server`, using
the repository root as its working directory. Stdout is reserved for protocol messages.

```bash
python -m pytest -q
```

See [ADR-005](docs/adr/ADR-005-mcp-capability-boundary.md) for the trust model,
transport choices and remaining production authorization requirements.

## V0.5 — approval security and tenant isolation

Enterprise mutations now require expiring, run/plan/executor-bound approval grants.
ToolGateway enforces host ownership for reads and writes. Durable operation reservations
and host leases suppress duplicate execution; repeated completed approvals return the
saved outcome. Uncertain failures escalate and remain blocked for reconciliation.

All `/v2` routes now require an authenticated local bearer principal. To run the local
API, generate a credential and configure its trusted claims in the same terminal:

```bash
export OPSPILOT_DEMO_TOKEN="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
export OPSPILOT_API_IDENTITIES="$(python -c 'import json, os; print(json.dumps({os.environ["OPSPILOT_DEMO_TOKEN"]: {"subject": "local-oncall", "tenant_id": "platform-sre", "roles": ["observer", "approver"], "environment_scopes": ["production"]}}))')"
uvicorn app.api.main:app --reload
```

The demo host belongs to `platform-sre`. Use the generated token with the Swagger UI's
**Authorize** control, or the `Authorization: Bearer <token>` header. Create an incident
with `{}` at `POST /v2/incidents`, then send `{}` to `POST /v2/runs/<run_id>/approve`.
Approver identity comes from the bearer principal; caller-supplied `approver` or
`agent_id` fields are rejected. Without identity configuration, `/v2` denies access.

Run `python -m pytest -q` and `python -m evals.run_evals` to verify security and both
legacy/enterprise patch and rollback scenarios. Use TLS and replace the local identity
resolver with OIDC before remote deployment. See
[ADR-006](docs/adr/ADR-006-approval-grants-tenant-isolation.md) for recovery and storage limits.


## V0.6 / V0.7 — persistence, recovery and governed providers

V0.6 persists runs, approval grants, operation results, host leases, simulator inventory,
rollback snapshots, backend receipts, audit events and official LangGraph checkpoints.
SQLite supports local use; PostgreSQL supports shared state across API replicas.
V0.7 adds configured Kubernetes, AWS SSM, Terraform and GitHub capabilities behind the
same MCP authorization boundary. These adapters require your own target inventory and
least-privilege credentials; CI uses contract fakes rather than live cloud accounts.

```bash
python -m pip install -r requirements.txt
export OPSPILOT_DATABASE_URL="sqlite:////tmp/opspilot.db"
python -m app.storage.bootstrap
python -m pytest -q
python -m evals.run_evals
uvicorn app.api.main:app --reload
```

Keep the V0.5 bearer identity configuration above. For PostgreSQL, set
`OPSPILOT_DATABASE_URL=postgresql://user:password@host:5432/opspilot` and run bootstrap
before starting the API. URL-encode credentials containing URL delimiters.
Existing V0.5 SQLite files receive additive tables; bootstrap records the Alembic
baseline and initializes checkpoints. Switching URLs does **not** copy your old data.
Back up the database before migrations; automatic downgrade intentionally refuses to
remove operational records.

For a local PostgreSQL deployment, generate an alphanumeric database password and
reuse the bearer identity configuration above:

```bash
export OPSPILOT_DB_PASSWORD="$(python -c 'import secrets; print(secrets.token_hex(24))')"
docker compose up --build -d
```

Compose keeps PostgreSQL data in a named volume. The Kubernetes deployment example
requires an `opspilot-config` Secret containing `OPSPILOT_DATABASE_URL` and
`OPSPILOT_API_IDENTITIES`, pointing both replicas at the same PostgreSQL database.
`/ready` checks database connectivity. Work still executes in the requesting process;
there is no background queue or automatic recovery scheduler.

Inspect `GET /v2/runs/<id>/checkpoint` for the latest status and pending graph nodes.
After a process restart, an authenticated, scoped approver sends `{}` to
`POST /v2/runs/<id>/recover`. A live execution-worker lease blocks recovery; after
an actual worker crash, its lease expires in five minutes. Recovery rotates the grant
and reconciles started/unknown operations before resuming the graph. A proven result
is reused. An unproven mutation remains `ESCALATED`, retains the host lease and returns
409; inspect the external system and audit trail instead of deleting ledger records.
Read events through `GET /v2/runs/<id>/events` after a restart.

Set `OPSPILOT_INVENTORY_FILE` to a trusted JSON file to opt into providers; see
[provider setup](docs/PROVIDERS.md). Ownership/provider bindings cannot be reassigned
by loading another file, and existing payloads are not overwritten on startup.
Treat inventory changes as administrative database changes requiring review.

GitHub creates a draft PR and records `WAITING_EXTERNAL`; a human reviews and merges,
then `/recover` verifies the configured base branch without recreating the PR.
Terraform applies a SHA-256-bound saved plan for exactly one update; failures need a
new reviewed plan instead of automatic rollback. Kubernetes restores the original
image and AWS invokes the configured rollback document when postchecks fail.

CI runs the simulator/security/provider suite, restart evaluations and a separate
real PostgreSQL 16 job. To run PostgreSQL checks locally:

```bash
OPSPILOT_TEST_POSTGRES_URL=postgresql://user:password@localhost:5432/disposable_test_db python -m pytest -q tests/test_postgres.py
```

The integration fixture clears control-plane tables: use a dedicated disposable test
DB. Live cloud permissions, rollout behavior and SSM document implementation must be
validated in your staging environment. See [ADR-007](docs/adr/ADR-007-durable-recovery.md)
and [ADR-008](docs/adr/ADR-008-governed-providers.md).
