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
The local implementation deliberately uses an in-process state store and simulator so anyone can run it. The documented production target replaces those seams with PostgreSQL/durable workflow storage, queue-backed workers, real MCP servers, OIDC/RBAC, secrets management, OpenTelemetry/Prometheus/Grafana, Kubernetes, and provider-independent OSS inference (for example vLLM) or managed fallback.

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
