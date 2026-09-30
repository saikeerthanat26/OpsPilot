import re
import time
from app.mcp.tools.base import Provider


class KubernetesProvider(Provider):
    def __init__(self, *args, client=None, **kwargs):
        super().__init__(*args, **kwargs)
        if not re.fullmatch(r".+@sha256:[a-f0-9]{64}", self.spec["target_version"]):
            raise ValueError("target Kubernetes image must be pinned by digest")
        if client is None:
            from kubernetes import client as sdk, config
            try: config.load_incluster_config()
            except config.ConfigException: config.load_kube_config()
            settings = sdk.Configuration.get_default_copy()
            settings.retries = 0
            client = sdk.AppsV1Api(sdk.ApiClient(settings))
        self.client = client
    def read(self):
        obj = self.client.read_namespaced_deployment(self.spec["deployment"], self.spec["namespace"], _request_timeout=10)
        if obj.metadata.labels.get("opspilot.io/tenant") != self.spec["tenant_id"]:
            raise PermissionError("deployment tenant label mismatch")
        return obj
    def container(self, obj):
        for index, container in enumerate(obj.spec.template.spec.containers):
            if container.name == self.spec["container"]: return index, container
        raise KeyError("configured container not found")
    @staticmethod
    def ready(obj):
        wanted = obj.spec.replicas or 0
        return wanted > 0 and (obj.status.observed_generation or 0) >= obj.metadata.generation and (obj.status.updated_replicas or 0) == wanted and (obj.status.available_replicas or 0) == wanted
    def get_host(self):
        obj = self.read()
        _, container = self.container(obj)
        return self.common(container.image, self.ready(obj), rollback_available="@sha256:" in container.image)
    def _replace(self, obj, image):
        index, container = self.container(obj)
        annotations = dict(obj.metadata.annotations or {})
        annotations["opspilot.io/run"] = self.run_id
        body = [
            {"op":"test", "path":"/metadata/resourceVersion", "value":obj.metadata.resource_version},
            {"op":"test", "path":f"/spec/template/spec/containers/{index}/image", "value":container.image},
            {"op":"add", "path":"/metadata/annotations", "value":annotations},
            {"op":"replace", "path":f"/spec/template/spec/containers/{index}/image", "value":image},
        ]
        self.client.patch_namespaced_deployment(self.spec["deployment"], self.spec["namespace"], body,
                                                _request_timeout=10)
    def patch(self, to_version):
        self.require_run()
        if to_version != self.spec["target_version"]: raise PermissionError("unregistered image")
        obj = self.read()
        _, container = self.container(obj)
        self.snapshot({"image":container.image})
        self._replace(obj, to_version)
        result = {"executed":True, "provider":"kubernetes"}
        self.receipt("execute_approved_patch", {"status":"SUCCEEDED", "result":result})
        return result
    def validate(self):
        deadline = time.monotonic() + self.spec.get("verification_timeout", 60)
        while True:
            obj = self.read()
            _, container = self.container(obj)
            if container.image == self.spec["target_version"] and self.ready(obj): return True
            if time.monotonic() >= deadline: return False
            time.sleep(1)
    def rollback(self):
        self.require_run()
        previous = self.inventory.get_snapshot(self.run_id, self.host_id)["image"]
        obj = self.read()
        _, container = self.container(obj)
        if container.image != self.spec["target_version"] or (obj.metadata.annotations or {}).get("opspilot.io/run") != self.run_id:
            raise PermissionError("deployment changed outside this run")
        self._replace(obj, previous)
        result = {"rolled_back":True, "provider":"kubernetes"}
        self.receipt("rollback_patch", {"status":"SUCCEEDED", "result":result})
        return result
    def reconcile(self, capability):
        receipt = super().reconcile(capability)
        if receipt: return receipt
        obj = self.read()
        _, container = self.container(obj)
        if (obj.metadata.annotations or {}).get("opspilot.io/run") != self.run_id: return None
        snapshot = self.inventory.get_snapshot(self.run_id, self.host_id)
        expected = self.spec["target_version"] if capability == "execute_approved_patch" else snapshot["image"]
        if container.image != expected: return None
        return {"status":"SUCCEEDED", "result":{("executed" if capability=="execute_approved_patch" else "rolled_back"):True, "provider":"kubernetes"}}
