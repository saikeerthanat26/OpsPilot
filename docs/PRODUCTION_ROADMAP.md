# POC → Enterprise roadmap

## Phase 0: Preserve value
Instrument the existing assistant. Identify top workflows, users, integrations, latency, failure modes and manual handoffs. Do not rewrite first.

## Phase 1: Establish boundaries
Extract channel adapter, orchestration, state, model gateway and typed tool contracts. Add trace IDs and audit events. Put mutations behind policy/approval.

## Phase 2: Reliability
Durable workflow state, idempotency, async workers, retry budgets, circuit breakers, canary, verification and rollback. Define SLOs.

## Phase 3: Platform
Tool registry/MCP gateway, SDK/templates, OIDC/RBAC, secrets, evaluation gates, observability standards, Kubernetes autoscaling, model routing and cost controls.

## Phase 4: Organizational scale
Self-service capability onboarding, architecture review/ADRs, policy packs, scorecards, multi-team tenancy, chargeback/showback and roadmap based on operational outcomes.
