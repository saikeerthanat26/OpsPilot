# Security model
Threat assumptions include prompt injection through retrieved content, over-permissioned tools, confused-deputy actions, poisoned memory, replay/duplicate execution, credential leakage and unsafe autonomous loops.

Controls: identity propagation; deny-by-default tool registry; typed schemas; policy checks outside the LLM; no generic shell tool; approval for production mutation; idempotency keys in production; short-lived credentials; retrieval ACL filtering; output validation; max steps/tool calls; immutable audit; canary + verification + rollback.

The local simulator does not implement enterprise identity or secrets; those are explicit production seams rather than mocked security claims.
