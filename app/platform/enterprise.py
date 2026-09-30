from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Any
import json, os, sqlite3, uuid

@dataclass(frozen=True)
class AgentIdentity:
    agent_id: str
    tenant_id: str
    roles: tuple[str, ...]
    environment_scopes: tuple[str, ...]

@dataclass(frozen=True)
class Capability:
    name: str
    description: str
    mutating: bool
    risk: str
    required_role: str

class CapabilityRegistry:
    def __init__(self):
        self._caps = {
            "get_host_health": Capability("get_host_health", "Read host health and utilization", False, "low", "observer"),
            "list_vulnerabilities": Capability("list_vulnerabilities", "Read active host vulnerabilities", False, "low", "observer"),
            "get_patch_metadata": Capability("get_patch_metadata", "Read package and patch metadata", False, "low", "observer"),
            "execute_approved_patch": Capability("execute_approved_patch", "Apply an approved package patch", True, "high", "operator"),
            "verify_host_health": Capability("verify_host_health", "Verify post-change health", False, "low", "observer"),
            "rollback_patch": Capability("rollback_patch", "Rollback the most recent patch", True, "high", "operator"),
        }
    def list(self): return [asdict(x) for x in self._caps.values()]
    def get(self, name): return self._caps[name]

class ToolGateway:
    """Capability boundary: tenant ownership, role, environment scope and durable approval grants wrap narrow tools."""
    def __init__(self, tools, registry, trace, *, approvals=None, run_id=None):
        self.tools, self.registry, self.trace = tools, registry, trace
        self.approvals, self.run_id = approvals, run_id
    def invoke(self, identity: AgentIdentity, capability: str, *, approval_token: str|None=None, **kwargs):
        cap = self.registry.get(capability)
        if cap.required_role not in identity.roles and "admin" not in identity.roles:
            self.trace.add("tool.denied", f"agent={identity.agent_id}, capability={capability}, reason=role")
            raise PermissionError(f"agent lacks role {cap.required_role}")
        if self.tools.get_host_tenant(kwargs["host_id"]) != identity.tenant_id:
            self.trace.add("tool.denied", f"agent={identity.agent_id}, capability={capability}, reason=tenant")
            raise PermissionError("host belongs to another tenant")
        environment = self.tools.get_host_health(kwargs["host_id"])["environment"]
        if environment not in identity.environment_scopes:
            self.trace.add("tool.denied", f"agent={identity.agent_id}, capability={capability}, reason=environment")
            raise PermissionError("agent lacks environment scope")
        if cap.mutating:
            try:
                if self.approvals is None:
                    raise PermissionError("approval verifier required")
                self.approvals.reserve(approval_token, self.run_id, identity, capability, kwargs)
            except PermissionError:
                self.trace.add("tool.denied", f"agent={identity.agent_id}, capability={capability}, reason=approval")
                raise
        self.trace.add("tool.invoked", f"agent={identity.agent_id}, tenant={identity.tenant_id}, capability={capability}")
        fn = getattr(self.tools, capability)
        if capability == "execute_approved_patch": kwargs["approval_token"] = approval_token
        try:
            if capability == "execute_approved_patch":
                # Detect inventory drift after the plan was approved.
                record = self.approvals.runs.get(self.run_id)
                metadata = self.tools.get_patch_metadata(kwargs["host_id"])
                approved_plan = record["payload"]["plan"]
                if any(metadata[key] != approved_plan[key] for key in ("package", "from_version", "to_version")):
                    raise PermissionError("host package or version changed since planning")
            result = fn(**kwargs)
        except BaseException:
            if cap.mutating:
                self.approvals.finish(self.run_id, capability, "UNKNOWN")
            raise
        if cap.mutating:
            self.approvals.finish(self.run_id, capability, "SUCCEEDED")
        self.trace.add("tool.completed", f"capability={capability}")
        return result

class ModelRouter:
    """Provider-neutral routing seam. V0.2 uses deterministic planning; providers can be added without changing workflows."""
    def route(self, task: str, sensitivity: str="internal"):
        if sensitivity == "restricted": return {"provider":"local_oss", "model":"policy-approved-local", "reason":"data_boundary"}
        return {"provider":"configurable", "model":"reasoning-default", "reason":"task_policy"}

class DurableRunStore:
    def __init__(self, path: str|None=None):
        self.path = path or os.getenv("OPSPILOT_DB", "/tmp/opspilot.db")
        self._init()
    @staticmethod
    def timestamp(): return datetime.now(timezone.utc).isoformat()
    def _connect(self): return sqlite3.connect(self.path, timeout=15)
    def _init(self):
        with self._connect() as c:
            c.execute("CREATE TABLE IF NOT EXISTS runs (run_id TEXT PRIMARY KEY, tenant_id TEXT, status TEXT, autonomy TEXT, payload TEXT, created_at TEXT, updated_at TEXT)")
    def save(self, run_id, tenant_id, status, autonomy, payload: dict):
        now=datetime.now(timezone.utc).isoformat()
        with self._connect() as c:
            c.execute("INSERT INTO runs VALUES (?,?,?,?,?,?,?) ON CONFLICT(run_id) DO UPDATE SET status=excluded.status, autonomy=excluded.autonomy, payload=excluded.payload, updated_at=excluded.updated_at",(run_id,tenant_id,status,autonomy,json.dumps(payload),now,now))
    def get(self, run_id, tenant_id=None):
        with self._connect() as c: row=c.execute("SELECT run_id,tenant_id,status,autonomy,payload,created_at,updated_at FROM runs WHERE run_id=?",(run_id,)).fetchone()
        if not row or (tenant_id is not None and row[1] != tenant_id): return None
        return {"run_id":row[0],"tenant_id":row[1],"status":row[2],"autonomy":row[3],"payload":json.loads(row[4]),"created_at":row[5],"updated_at":row[6]}
