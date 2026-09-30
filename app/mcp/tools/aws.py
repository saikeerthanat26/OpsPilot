import re
import time
from app.mcp.tools.base import Provider


class AWSProvider(Provider):
    """EC2 + SSM inventory; mutations only invoke configured, narrow SSM documents."""
    def __init__(self, *args, clients=None, **kwargs):
        super().__init__(*args, **kwargs)
        for value in (self.spec["package"], self.spec["target_version"]):
            if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.+:~_-]{0,127}", value): raise ValueError("invalid package/version")
        if not re.fullmatch(r"i-[a-f0-9]{8,17}", self.spec["instance_id"]): raise ValueError("invalid EC2 instance")
        if clients is None:
            import boto3
            from botocore.config import Config
            session = boto3.Session(region_name=self.spec["region"])
            # Disable SDK retries for mutations with uncertain outcomes.
            config = Config(connect_timeout=5, read_timeout=10, retries={"total_max_attempts":1})
            clients = {name:session.client(name, config=config) for name in ("ec2","ssm")}
        self.ec2, self.ssm = clients["ec2"], clients["ssm"]
    def get_host(self):
        instance = self.ec2.describe_instances(InstanceIds=[self.spec["instance_id"]])["Reservations"][0]["Instances"][0]
        tags = {tag["Key"]:tag["Value"] for tag in instance.get("Tags",[])}
        if tags.get("opspilot:tenant") != self.spec["tenant_id"]: raise PermissionError("EC2 tenant tag mismatch")
        entries, token = [], None
        for _ in range(10):
            kwargs={"NextToken":token} if token else {}
            page=self.ssm.list_inventory_entries(InstanceId=self.spec["instance_id"], TypeName="AWS:Application", **kwargs)
            entries.extend(page.get("Entries", []))
            token=page.get("NextToken")
            if not token: break
        if token: raise RuntimeError("SSM inventory pagination exceeded budget")
        versions = [item["Version"] for item in entries if item["Name"] == self.spec["package"]]
        if len(versions) != 1: raise ValueError("package inventory missing or ambiguous")
        checks = self.ec2.describe_instance_status(InstanceIds=[self.spec["instance_id"]], IncludeAllInstances=True).get("InstanceStatuses", [])
        healthy = instance["State"]["Name"] == "running" and len(checks)==1 and all(checks[0].get(key,{}).get("Status")=="ok" for key in ("InstanceStatus","SystemStatus"))
        return self.common(versions[0], healthy)
    def _command(self, capability, version, document):
        self.require_run()
        self.get_host()  # Recheck remote ownership immediately before any mutation.
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.+:~_-]{0,127}", version):
            raise PermissionError("invalid mutation version")
        if document.startswith("AWS-Run") or not document.startswith("OpsPilot-"):
            raise PermissionError("only approved OpsPilot SSM documents may be invoked")
        response = self.ssm.send_command(InstanceIds=[self.spec["instance_id"]], DocumentName=document,
            Parameters={"Package":[self.spec["package"]], "Version":[version]},
            Comment=f"OpsPilot {self.run_id}", TimeoutSeconds=60)
        command_id = response["Command"]["CommandId"]
        self.receipt(capability, {"status":"SUBMITTED", "command_id":command_id})
        deadline = time.monotonic() + self.spec.get("command_timeout", 60)
        while True:
            try:
                result = self.ssm.get_command_invocation(CommandId=command_id, InstanceId=self.spec["instance_id"])
            except self.ssm.exceptions.InvocationDoesNotExist:
                result = {"Status":"Pending"}
            if result["Status"] == "Success":
                completed = {("executed" if capability=="execute_approved_patch" else "rolled_back"):True, "provider":"aws", "command_id":command_id}
                self.receipt(capability, {"status":"SUCCEEDED", "result":completed})
                return completed
            if result["Status"] in ("Cancelled","Failed","TimedOut") or time.monotonic() >= deadline:
                raise RuntimeError("SSM command outcome requires reconciliation")
            time.sleep(1)
    def patch(self, to_version):
        if to_version != self.spec["target_version"]: raise PermissionError("unregistered version")
        self.snapshot({"version":self.get_host()["version"]})
        return self._command("execute_approved_patch", to_version, self.spec["patch_document"])
    def validate(self):
        host = self.get_host()
        return host["health"] == "healthy" and host["version"] == self.spec["target_version"]
    def rollback(self):
        previous = self.inventory.get_snapshot(self.run_id, self.host_id)["version"]
        return self._command("rollback_patch", previous, self.spec["rollback_document"])
    def reconcile(self, capability):
        receipt = super().reconcile(capability)
        if not receipt or receipt.get("status") == "SUCCEEDED": return receipt
        status = self.ssm.get_command_invocation(CommandId=receipt["command_id"], InstanceId=self.spec["instance_id"])["Status"]
        if status != "Success": return None
        return {"status":"SUCCEEDED", "result":{("executed" if capability=="execute_approved_patch" else "rolled_back"):True,"provider":"aws", "command_id":receipt["command_id"]}}
