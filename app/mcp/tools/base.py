from app.storage.repositories import InventoryRepository


class Provider:
    def __init__(self, store, host_id, spec, run_id=None):
        self.store, self.host_id, self.spec, self.run_id = store, host_id, spec, run_id
        self.inventory = InventoryRepository(store)
    def require_run(self):
        if not self.run_id: raise PermissionError("trusted run context required")
    def snapshot(self, state):
        self.require_run()
        self.inventory.snapshot(self.run_id, self.host_id, state)
    def receipt(self, capability, payload):
        self.inventory.receipt(self.run_id, capability, payload)
    def reconcile(self, capability):
        return self.inventory.get_receipt(self.run_id, capability)
    def common(self, version, healthy, **extra):
        return {"tenant_id":self.spec["tenant_id"], "environment":self.spec["environment"],
                "cpu":None, "memory":None, "health":"healthy" if healthy else "degraded",
                "package":self.spec["package"], "version":version,
                "target_version":self.spec["target_version"],
                "maintenance_window":self.spec.get("maintenance_window",False),
                "vulnerabilities":self.spec.get("vulnerabilities",[]), **extra}
