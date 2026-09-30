import json
import os
from pathlib import Path
from app.storage.repositories import InventoryRepository
from app.storage.simulator import DurableSimulator


class ProviderRouter:
    def __init__(self, store, *, run_id=None, clients=None):
        self.store, self.run_id, self.clients = store, run_id, clients or {}
        self.inventory = InventoryRepository(store)
        self.fail_validation = False
    def for_run(self, run_id):
        router=ProviderRouter(self.store,run_id=run_id,clients=self.clients)
        router.fail_validation=self.fail_validation
        return router
    def get_host_tenant(self, host_id): return self.inventory.get(host_id)["tenant_id"]
    def provider(self, host_id):
        record=self.inventory.get(host_id)
        kind=record["provider"]
        if kind=="simulator": return DurableSimulator(self.store,run_id=self.run_id,fail_validation=self.fail_validation)
        from app.mcp.tools.kubernetes import KubernetesProvider
        from app.mcp.tools.aws import AWSProvider
        from app.mcp.tools.terraform import TerraformProvider
        from app.mcp.tools.github import GitHubProvider
        classes={"kubernetes":KubernetesProvider,"aws":AWSProvider,"terraform":TerraformProvider,"github":GitHubProvider}
        if kind not in classes: raise PermissionError("unknown configured provider")
        kwargs=self.clients.get(kind,{})
        return classes[kind](self.store,host_id,record["payload"],run_id=self.run_id,**kwargs)
    def get_host(self, host_id):
        provider=self.provider(host_id)
        return provider.get_host(host_id) if isinstance(provider,DurableSimulator) else provider.get_host()
    def patch(self, host_id, version):
        provider=self.provider(host_id)
        return provider.patch(host_id,version) if isinstance(provider,DurableSimulator) else provider.patch(version)
    def rollback(self, host_id):
        provider=self.provider(host_id)
        return provider.rollback(host_id) if isinstance(provider,DurableSimulator) else provider.rollback()
    def validate(self, host_id):
        provider=self.provider(host_id)
        return provider.validate(host_id) if isinstance(provider,DurableSimulator) else provider.validate()
    def reconcile(self, capability):
        record=self.store.get(self.run_id)
        return self.provider(record["payload"]["host_id"]).reconcile(capability)


def configured_backend(store):
    # Safe local default. Loading configured inventory does not execute provider calls.
    DurableSimulator(store).seed()
    config=os.getenv("OPSPILOT_INVENTORY_FILE")
    if config:
        register_inventory(store,json.loads(Path(config).read_text()))
    return ProviderRouter(store)


def register_inventory(store, entries):
    repo=InventoryRepository(store)
    for entry in entries:
        if entry["provider"] not in ("simulator","kubernetes","aws","terraform","github"):
            raise ValueError("unsupported provider")
        spec=entry["spec"]
        if spec["environment"] not in ("production","nonproduction"): raise ValueError("invalid environment")
        if any(key.lower() in ("token","password","secret","access_key") for key in spec):
            raise ValueError("credentials must not be stored in inventory")
        repo.register(entry["host_id"],spec["tenant_id"],entry["provider"],spec)
