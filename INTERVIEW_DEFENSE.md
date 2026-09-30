# Interview Defense Guide

## 30-second project explanation
“I built OpsPilot as a reference architecture for the point where an agentic operations POC has proven value and now has to become an enterprise platform. I intentionally focused less on chat and more on the hard production boundaries: durable orchestration, narrow tool contracts, policy-based autonomy, evidence-backed decisions, observability, failure recovery and rollback. The core principle is separating probabilistic reasoning from deterministic infrastructure execution.”

## Why this architecture?
A successful POC proves user value; it does not automatically prove safe scale. Enterprise adoption introduces concurrency, permission boundaries, multiple interfaces, many integrations, long-running workflows, audit requirements, model variability and operational failure modes. The architecture creates explicit seams for each.

## Why not let the LLM execute shell commands?
Because a probabilistic component should not be the authorization or safety boundary. The agent chooses among approved capabilities; deterministic services validate identity, schema, policy and preconditions before execution.

## Why not vectorize all logs?
Logs and host state are high-volume, time-sensitive operational truth. Query them from observability systems with time/service filters. Use semantic retrieval for runbooks, postmortems and summarized historical knowledge. Hybrid retrieval can combine both at reasoning time.

## Why multi-agent?
Multi-agent is not the goal. OpsPilot separates responsibilities only where they have distinct context/tool/policy needs. A simpler workflow should remain single-agent. The orchestrator—not agents—owns state transitions and termination.

## What would change at enterprise scale?
External durable state, queue-backed workers, real MCP/tool services, SSO/OIDC, RBAC/ABAC, secrets manager, immutable audit, HA databases, OpenTelemetry, autoscaling, model-serving benchmarks, canary releases, SLOs and a tool registry/SDK so teams add capabilities consistently.

## What is unique?
Progressive autonomy + evidence packets. The system does not treat autonomy as on/off. Every action gets a risk/autonomy classification based on environment, mutation type, blast radius, rollback and confidence. The plan carries evidence so operators can understand why an action is proposed.

## Leadership framing
“I would not start by rewriting an organically successful system. First I would preserve the workflows that created adoption, instrument them, identify coupling and failure modes, define the target contracts, then migrate incrementally behind stable interfaces. My job as Tech Lead is to make the safe path the easy path for every engineer who adds a new agent or tool.”
