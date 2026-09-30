RUNBOOKS={
"openssl-critical-patch": "For a critical OpenSSL CVE: confirm maintenance window; patch one canary; verify service health and CPU; proceed only if healthy; otherwise rollback and escalate."
}
class KnowledgeService:
    def retrieve(self, query: str):
        # Production seam: hybrid vector/BM25 + metadata ACL filtering + reranking.
        return [{"id":k,"text":v,"score":0.96} for k,v in RUNBOOKS.items() if "patch" in query.lower() or "openssl" in query.lower()]
