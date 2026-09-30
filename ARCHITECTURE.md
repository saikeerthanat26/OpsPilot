# Architecture

## Enterprise evolution thesis
The starting point is assumed to be a useful, organically grown operations assistant. The target is not “a bigger bot”; it is an **agentic operations control plane**.

```text
Slack / Web / API / ITSM
          |
     Agent Gateway
(authn, context, rate limits)
          |
  Stateful Orchestrator
          |
  +-------+--------+----------------+
  |                |                |
Diagnostics    Knowledge       Remediation Planner
  |                |                |
  +---------- Evidence -------------+
                   |
             Policy Engine
        (risk + autonomy level)
                   |
             Approval Gate
                   |
              Tool Gateway
          (typed capabilities)
                   |
        Deterministic Executor
                   |
        Canary + Verification
             /           \
         Success        Rollback
```

## Control plane vs execution plane
The control plane interprets intent, gathers context, plans, applies policy and manages workflow state. The execution plane performs known operations through narrow, typed, permission-controlled capabilities. An LLM never receives a generic `execute_shell(command)` capability.

## Progressive autonomy
- L0 Observe: read-only diagnostics.
- L1 Recommend: produce a plan only.
- L2 Approval Required: production mutation, elevated blast radius, or sensitive action.
- L3 Bounded Autonomous: pre-approved low-risk operation with verification and rollback.

Autonomy is a policy decision, not an LLM decision.

## Knowledge strategy
Stable knowledge (runbooks, postmortems, incident summaries) belongs in a retrieval service/vector index. Fast-changing operational truth (metrics, logs, host state, vulnerabilities) stays in systems of record and is queried through tools. This avoids stale operational state being treated as semantic memory.

## Scale seams
API nodes are stateless. Workflow state is externally durable in production. Tool workers can scale independently. Long-running execution is asynchronous. Every mutation is idempotent. Model inference is behind a gateway so OSS/managed runtimes can change without rewriting orchestration.

## Security
Identity should propagate from caller → gateway → policy → tool. Production implementation should use OIDC, RBAC/ABAC, short-lived credentials, secrets manager, network policy, tool allowlists, schema validation and immutable audit. The agent never inherits platform-wide credentials.

## Observability
Traditional metrics: API latency/errors, worker saturation, queue depth, CPU/GPU, dependencies.
Agent metrics: trajectory, model/version, tool selection, arguments, tool latency, retries, state transitions, policy decisions, token/cost, task completion, rollback and escalation.

## Model serving
The model adapter is provider-independent. Local demo can use deterministic planning or an Ollama-compatible endpoint; production can use vLLM/TGI/llama.cpp or a managed provider. Model migration is evaluated against task completion, tool accuracy, policy compliance, latency, throughput and cost—not model benchmark scores alone.
