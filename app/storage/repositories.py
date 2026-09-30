import json
import uuid


class InventoryRepository:
    def __init__(self, runs): self.runs = runs
    def register(self, host_id, tenant_id, provider, payload):
        if payload.get("tenant_id", tenant_id) != tenant_id:
            raise PermissionError("inventory tenant mismatch")
        with self.runs._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            existing = conn.execute("SELECT tenant_id,provider FROM inventory WHERE host_id=?", (host_id,)).fetchone()
            if existing and tuple(existing) != (tenant_id, provider):
                raise PermissionError("inventory ownership/provider cannot be reassigned")
            conn.execute("INSERT INTO inventory VALUES (?,?,?,?) ON CONFLICT(host_id) DO NOTHING",
                         (host_id, tenant_id, provider, json.dumps(payload)))
    def get(self, host_id):
        with self.runs._connect() as conn:
            row = conn.execute("SELECT tenant_id,provider,payload FROM inventory WHERE host_id=?", (host_id,)).fetchone()
        if not row: raise KeyError("unknown host")
        return {"tenant_id": row[0], "provider": row[1], "payload": json.loads(row[2])}
    def snapshot(self, run_id, host_id, payload):
        if not run_id: raise PermissionError("run context required")
        with self.runs._connect() as conn:
            conn.execute("INSERT INTO snapshots VALUES (?,?,?) ON CONFLICT(run_id,host_id) DO NOTHING",
                         (run_id, host_id, json.dumps(payload)))
    def get_snapshot(self, run_id, host_id):
        with self.runs._connect() as conn:
            row = conn.execute("SELECT payload FROM snapshots WHERE run_id=? AND host_id=?", (run_id, host_id)).fetchone()
        if not row: raise PermissionError("this run has no rollback snapshot")
        return json.loads(row[0])
    def receipt(self, run_id, capability, payload):
        with self.runs._connect() as conn:
            conn.execute("INSERT INTO backend_receipts VALUES (?,?,?) ON CONFLICT(run_id,capability) DO UPDATE SET payload=excluded.payload",
                         (run_id, capability, json.dumps(payload)))
    def get_receipt(self, run_id, capability):
        with self.runs._connect() as conn:
            row = conn.execute("SELECT payload FROM backend_receipts WHERE run_id=? AND capability=?", (run_id, capability)).fetchone()
        return json.loads(row[0]) if row else None


class AuditRepository:
    def __init__(self, runs): self.runs = runs
    def append(self, run_id, tenant_id, event):
        with self.runs._connect() as conn:
            conn.execute("INSERT INTO audit_events VALUES (?,?,?,?)", (str(uuid.uuid4()), run_id, tenant_id, json.dumps(event)))
    def list(self, run_id, tenant_id):
        with self.runs._connect() as conn:
            rows = conn.execute("SELECT payload FROM audit_events WHERE run_id=? AND tenant_id=? ORDER BY event_id", (run_id, tenant_id)).fetchall()
        return sorted((json.loads(row[0]) for row in rows), key=lambda e: e["ts"])
