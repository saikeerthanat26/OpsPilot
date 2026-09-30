"""Governed file-change PR. Creating a PR is distinct from applying remediation."""
import base64
import hashlib
import os
import re
from urllib.parse import quote
import httpx
from app.mcp.tools.base import Provider


class GitHubProvider(Provider):
    def __init__(self, *args, client=None, **kwargs):
        super().__init__(*args, **kwargs)
        if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", self.spec["repository"]): raise ValueError("invalid repository")
        self.content = self.spec["content"].encode()
        if len(self.content)>65536: raise ValueError("change exceeds 64KiB")
        if blob_sha(self.content) != self.spec["target_version"]: raise PermissionError("target content hash mismatch")
        if client is None:
            token = os.environ["OPSPILOT_GITHUB_TOKEN"]
            client = httpx.Client(base_url="https://api.github.com", headers={"Authorization":f"Bearer {token}","X-GitHub-Api-Version":"2022-11-28"}, timeout=10, follow_redirects=False)
        self.client = client
        self.root = f"/repos/{self.spec['repository']}"
    def request(self, method, path, **kwargs):
        result = self.client.request(method, self.root+path, **kwargs)
        result.raise_for_status()
        return result.json()
    def file(self, ref):
        return self.request("GET", "/contents/"+quote(self.spec["package"],safe="/"), params={"ref":ref})
    def get_host(self):
        version = self.file(self.spec["base_ref"])["sha"]
        receipt = self.inventory.get_receipt(self.run_id, "execute_approved_patch") if self.run_id else None
        pending = False
        if receipt and "pull_number" in receipt.get("result",{}):
            pr = self.request("GET", f"/pulls/{receipt['result']['pull_number']}")
            pending = pr["state"]=="open" and not pr.get("merged",False)
        return self.common(version, version==self.spec["target_version"] and not pending,
                           pending_external=pending, rollback_available=False)
    def patch(self, to_version):
        self.require_run()
        if to_version != self.spec["target_version"]: raise PermissionError("unregistered content")
        branch = f"opspilot/{self.run_id}"
        current = self.file(self.spec["base_ref"])
        base = self.request("GET", "/git/ref/heads/"+quote(self.spec["base_ref"],safe=""))["object"]["sha"]
        self.snapshot({"base_sha":base, "file_sha":current["sha"]})
        self.request("POST", "/git/refs", json={"ref":f"refs/heads/{branch}","sha":base})
        updated = self.request("PUT", "/contents/"+quote(self.spec["package"],safe="/"), json={
            "message":f"OpsPilot approved change {self.run_id}", "content":base64.b64encode(self.content).decode(),
            "sha":current["sha"],"branch":branch})
        if updated["content"]["sha"] != to_version: raise RuntimeError("GitHub content does not match approved plan")
        pr = self.request("POST", "/pulls", json={"title":f"OpsPilot approved remediation {self.run_id}",
            "head":branch,"base":self.spec["base_ref"],"body":"Governed change request; review and merge are separate human actions.","draft":True})
        result={"executed":True,"provider":"github","pull_number":pr["number"],"change_request_url":pr["html_url"],"remediation_applied":False}
        self.receipt("execute_approved_patch", {"status":"SUCCEEDED","result":result})
        return result
    def validate(self): return self.get_host()["health"]=="healthy"
    def rollback(self): raise PermissionError("GitHub changes require a reviewed revert PR")
    def reconcile(self, capability):
        receipt=super().reconcile(capability)
        if receipt or capability!="execute_approved_patch": return receipt
        branch=f"opspilot/{self.run_id}"
        prs=self.request("GET","/pulls",params={"state":"all","head":self.spec["repository"].split('/')[0]+":"+branch,"base":self.spec["base_ref"]})
        if len(prs)!=1 or self.file(branch)["sha"]!=self.spec["target_version"]: return None
        return {"status":"SUCCEEDED","result":{"executed":True,"provider":"github","pull_number":prs[0]["number"],"change_request_url":prs[0]["html_url"],"remediation_applied":False}}


def blob_sha(content): return hashlib.sha1(f"blob {len(content)}\0".encode()+content).hexdigest()
