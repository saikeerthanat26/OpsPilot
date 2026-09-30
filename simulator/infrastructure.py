from copy import deepcopy

class InfrastructureSimulator:
    def __init__(self, fail_validation=False):
        self.fail_validation=fail_validation
        self.hosts={"prod-api-01":{"environment":"production","cpu":94,"memory":61,"health":"degraded","package":"openssl","version":"3.1.2","target_version":"3.1.4","vulnerabilities":["CVE-DEMO-2026-001"],"maintenance_window":True}}
        self.snapshots={}
    def get_host(self, host_id):
        if host_id not in self.hosts: raise KeyError(f"unknown host {host_id}")
        return deepcopy(self.hosts[host_id])
    def patch(self, host_id, to_version):
        self.snapshots[host_id]=deepcopy(self.hosts[host_id])
        self.hosts[host_id]["version"]=to_version
        self.hosts[host_id]["vulnerabilities"]=[]
        self.hosts[host_id]["cpu"]=45
        self.hosts[host_id]["health"]="unhealthy" if self.fail_validation else "healthy"
    def rollback(self, host_id):
        self.hosts[host_id]=deepcopy(self.snapshots[host_id])
    def validate(self, host_id): return self.hosts[host_id]["health"] == "healthy"
