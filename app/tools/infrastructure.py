from simulator.infrastructure import InfrastructureSimulator

class InfrastructureTools:
    """Narrow capabilities. Intentionally no generic shell execution."""
    def __init__(self, sim: InfrastructureSimulator): self.sim=sim
    def get_host_tenant(self, host_id): return self.sim.get_host_tenant(host_id) if hasattr(self.sim,"get_host_tenant") else self.sim.get_host(host_id)["tenant_id"]
    def get_host_health(self, host_id):
        h=self.sim.get_host(host_id); return {"cpu":h["cpu"],"memory":h["memory"],"health":h["health"],"environment":h["environment"],"pending_external":h.get("pending_external",False)}
    def list_vulnerabilities(self, host_id): return self.sim.get_host(host_id)["vulnerabilities"]
    def get_patch_metadata(self, host_id):
        h=self.sim.get_host(host_id); return {"package":h["package"],"from_version":h["version"],"to_version":h["target_version"],"maintenance_window":h["maintenance_window"],"rollback_available":h.get("rollback_available",True)}
    def execute_approved_patch(self, host_id, to_version, approval_token):
        if not approval_token: raise PermissionError("approval token required")
        return self.sim.patch(host_id,to_version) or {"executed":True}
    def verify_host_health(self, host_id): return {"healthy":self.sim.validate(host_id), **self.get_host_health(host_id)}
    def rollback_patch(self, host_id): return self.sim.rollback(host_id) or {"rolled_back":True}
