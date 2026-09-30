"""Apply an immutable, single-resource update plan. Terraform has no generic rollback."""
import hashlib
import json
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory
from app.mcp.tools.base import Provider


class TerraformProvider(Provider):
    def __init__(self, *args, runner=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.directory = Path(self.spec["directory"]).resolve(strict=True)
        self.plan_path = (self.directory / self.spec["plan_file"]).resolve(strict=True)
        if not self.plan_path.is_relative_to(self.directory): raise PermissionError("plan outside configured project")
        self.runner = runner or subprocess.run
    def command(self, args):
        result = self.runner(["terraform", *args], cwd=str(self.directory), shell=False, check=True,
                             capture_output=True, text=True, timeout=120)
        return result.stdout
    def plan(self, path=None):
        path = path or self.plan_path
        if hashlib.sha256(path.read_bytes()).hexdigest() != self.spec["target_version"]:
            raise PermissionError("approved Terraform artifact changed")
        plan = json.loads(self.command(["show","-json",str(path)]))
        changes = [c for c in plan.get("resource_changes",[]) if c["change"]["actions"] != ["no-op"]]
        if len(changes) != 1 or changes[0]["address"] != self.spec["package"] or changes[0]["change"]["actions"] != ["update"]:
            raise PermissionError("Terraform plan must update exactly the configured resource")
        if any_true(changes[0]["change"].get("after_unknown",{})):
            raise PermissionError("unknown planned values prevent deterministic verification")
        return changes[0]
    def state(self): return json.loads(self.command(["show","-json"]))
    def state_hash(self, state):
        return hashlib.sha256(json.dumps(state.get("values",{}),sort_keys=True).encode()).hexdigest()
    def matches(self, state):
        change = self.plan()
        resources = collect_resources(state.get("values",{}).get("root_module",{}))
        match = next((r for r in resources if r["address"]==self.spec["package"]), None)
        return bool(match) and match["values"] == change["change"]["after"]
    def get_host(self):
        state = self.state()
        return self.common(self.state_hash(state), self.matches(state), rollback_available=False)
    def patch(self, to_version):
        self.require_run()
        if to_version != self.spec["target_version"]: raise PermissionError("unregistered Terraform plan")
        # Read once into a private artifact; validate and apply those same bytes.
        # The configured source file can change without changing this invocation.
        approved_bytes = self.plan_path.read_bytes()
        with TemporaryDirectory(prefix=".opspilot-plan-", dir=self.directory) as directory:
            artifact = Path(directory) / "approved.tfplan"
            artifact.write_bytes(approved_bytes)
            artifact.chmod(0o400)
            self.plan(artifact)
            self.snapshot({"state_hash":self.state_hash(self.state())})
            self.command(["apply","-input=false","-no-color",str(artifact)])
        result={"executed":True,"provider":"terraform"}
        self.receipt("execute_approved_patch", {"status":"SUCCEEDED","result":result})
        return result
    def validate(self): return self.matches(self.state())
    def rollback(self): raise PermissionError("Terraform recovery needs a new reviewed plan and approval")


def any_true(value):
    if isinstance(value, dict): return any(any_true(v) for v in value.values())
    if isinstance(value, list): return any(any_true(v) for v in value)
    return value is True


def collect_resources(module):
    return module.get("resources",[]) + [r for child in module.get("child_modules",[]) for r in collect_resources(child)]
