# ADR-004: Provider-independent inference

**Decision:** put inference behind a model gateway.

**Why:** enables OSS/on-prem serving and managed fallback, workload-specific model routing, benchmarking, and migration without coupling orchestration to one provider.
