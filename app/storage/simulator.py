"""Durable local backend. Mutation, snapshot and receipt commit in one transaction."""
from copy import deepcopy
import json

from app.storage.repositories import InventoryRepository
from simulator.infrastructure import InfrastructureSimulator


class DurableSimulator:
    def __init__(self, store, *, run_id=None, fail_validation=False):
        self.store, self.run_id = store, run_id
        self.fail_validation = fail_validation
        self.inventory = InventoryRepository(store)
    def seed(self):
        for host_id, host in InfrastructureSimulator().hosts.items():
            self.inventory.register(host_id, host["tenant_id"], "simulator", host)
        return self
    def for_run(self, run_id):
        return DurableSimulator(self.store, run_id=run_id, fail_validation=self.fail_validation)
    def get_host(self, host_id):
        registered = self.inventory.get(host_id)
        if registered["provider"] != "simulator": raise PermissionError("wrong inventory provider")
        return deepcopy(registered["payload"])
    def patch(self, host_id, to_version):
        if not self.run_id: raise PermissionError("run context required")
        with self.store._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute("SELECT payload FROM inventory WHERE host_id=? AND provider='simulator'", (host_id,)).fetchone()
            if not row: raise KeyError("unknown host")
            host = json.loads(row[0])
            conn.execute("INSERT INTO snapshots VALUES (?,?,?) ON CONFLICT(run_id,host_id) DO NOTHING", (self.run_id, host_id, row[0]))
            host.update(version=to_version, vulnerabilities=[], cpu=45,
                        health="unhealthy" if self.fail_validation else "healthy")
            conn.execute("UPDATE inventory SET payload=? WHERE host_id=?", (json.dumps(host), host_id))
            self._receipt(conn, "execute_approved_patch", {"executed": True})
    def _receipt(self, conn, capability, result):
        conn.execute("INSERT INTO backend_receipts VALUES (?,?,?) ON CONFLICT(run_id,capability) DO NOTHING",
                     (self.run_id, capability, json.dumps({"status": "SUCCEEDED", "result": result})))
    def rollback(self, host_id):
        if not self.run_id: raise PermissionError("run context required")
        with self.store._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute("SELECT payload FROM snapshots WHERE run_id=? AND host_id=?", (self.run_id, host_id)).fetchone()
            if not row: raise PermissionError("this run has no rollback snapshot")
            conn.execute("UPDATE inventory SET payload=? WHERE host_id=?", (row[0], host_id))
            self._receipt(conn, "rollback_patch", {"rolled_back": True})
    def validate(self, host_id): return self.get_host(host_id)["health"] == "healthy"
    def reconcile(self, capability): return self.inventory.get_receipt(self.run_id, capability)
