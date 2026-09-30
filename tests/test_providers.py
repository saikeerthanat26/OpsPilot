import base64
from copy import deepcopy
import hashlib
import json
from types import SimpleNamespace as NS

import httpx
import pytest

from app.platform.enterprise import DurableRunStore
from app.orchestration.enterprise_workflow import EnterpriseOpsWorkflow
from app.mcp.tools.kubernetes import KubernetesProvider
from app.mcp.tools.aws import AWSProvider
from app.mcp.tools.terraform import TerraformProvider
from app.mcp.tools.github import GitHubProvider, blob_sha
from app.storage.repositories import InventoryRepository
from app.tools.providers import ProviderRouter, register_inventory

OLD="registry/app@sha256:"+"1"*64
NEW="registry/app@sha256:"+"2"*64


@pytest.fixture
def store(tmp_path): return DurableRunStore(str(tmp_path/"providers.db"))


def kube_spec(): return {"tenant_id":"platform-sre","environment":"production","package":"container-image", "target_version":NEW, "namespace":"apps","deployment":"api","container":"api","verification_timeout":0}


class Kube:
    def __init__(self):
        self.obj=NS(metadata=NS(labels={"opspilot.io/tenant":"platform-sre"}, annotations={},resource_version="1",generation=1),
                    spec=NS(replicas=2,template=NS(spec=NS(containers=[NS(name="api",image=OLD)]))),
                    status=NS(observed_generation=1,updated_replicas=2,available_replicas=2))
        self.calls=[]
    def read_namespaced_deployment(self,name,namespace,**kwargs): return deepcopy(self.obj)
    def patch_namespaced_deployment(self,name,namespace,body,*,_request_timeout):
        assert name=="api" and namespace=="apps"
        assert body[0]=={"op":"test","path":"/metadata/resourceVersion","value":self.obj.metadata.resource_version}
        assert body[1]["value"]==self.obj.spec.template.spec.containers[0].image
        self.calls.append(body)
        self.obj.metadata.annotations=body[2]["value"]
        self.obj.spec.template.spec.containers[0].image=body[3]["value"]
        self.obj.metadata.resource_version=str(int(self.obj.metadata.resource_version)+1)
        self.obj.metadata.generation+=1
        self.obj.status.observed_generation=self.obj.metadata.generation


def test_kubernetes_full_governed_mcp_flow(store):
    kube=Kube()
    register_inventory(store,[{"host_id":"kube-api","provider":"kubernetes","spec":kube_spec()}])
    router=ProviderRouter(store,clients={"kubernetes":{"client":kube}})
    workflow=EnterpriseOpsWorkflow(router,store)
    run=workflow.investigate("platform-sre","kube-api","CVE-TEST")
    result=workflow.approve_and_execute(run["run_id"],"alice",tenant_id="platform-sre")
    assert result["status"]=="SUCCEEDED"
    assert len(kube.calls)==1
    assert result["payload"]["execution_result"]["provider"]=="kubernetes"


def test_kubernetes_rollout_failure_rolls_back_original_image(store):
    kube=Kube(); kube.obj.status.available_replicas=0
    register_inventory(store,[{"host_id":"kube-api","provider":"kubernetes","spec":kube_spec()}])
    workflow=EnterpriseOpsWorkflow(ProviderRouter(store,clients={"kubernetes":{"client":kube}}),store)
    run=workflow.investigate("platform-sre","kube-api","CVE-TEST")
    done=workflow.approve_and_execute(run["run_id"],"alice",tenant_id="platform-sre")
    assert done["status"]=="ROLLED_BACK"
    assert kube.obj.spec.template.spec.containers[0].image==OLD
    assert len(kube.calls)==2


def test_kubernetes_tenant_label_and_external_change_guards(store):
    kube=Kube(); spec=kube_spec()
    provider=KubernetesProvider(store,"kube-api",spec,run_id="run",client=kube)
    kube.obj.metadata.labels["opspilot.io/tenant"]="foreign"
    with pytest.raises(PermissionError): provider.get_host()
    kube.obj.metadata.labels["opspilot.io/tenant"]="platform-sre"
    provider.patch(NEW)
    kube.obj.spec.template.spec.containers[0].image="foreign-image"
    with pytest.raises(PermissionError): provider.rollback()
    assert len(kube.calls)==1


def test_kubernetes_reconciles_atomic_patch_annotation_after_lost_response(store):
    kube=Kube(); provider=KubernetesProvider(store,"kube-api",kube_spec(),run_id="run",client=kube)
    provider.snapshot({"image":OLD})
    provider._replace(kube.read_namespaced_deployment("api","apps"),NEW)
    proof=provider.reconcile("execute_approved_patch")
    assert proof["status"]=="SUCCEEDED"
    assert len(kube.calls)==1


@pytest.mark.parametrize("image",["latest","registry/app:latest","registry/app@sha256:bad"])
def test_kubernetes_requires_immutable_target(store,image):
    spec=kube_spec(); spec["target_version"]=image
    with pytest.raises(ValueError): KubernetesProvider(store,"kube-api",spec,client=Kube())


class AWS:
    def __init__(self):
        self.version="3.1.2"; self.calls=[]; self.tenant="platform-sre"
        self.exceptions=NS(InvocationDoesNotExist=KeyError)
    def describe_instances(self,**kwargs): return {"Reservations":[{"Instances":[{"Tags":[{"Key":"opspilot:tenant","Value":self.tenant}],"State":{"Name":"running"}}]}]}
    def describe_instance_status(self,**kwargs): return {"InstanceStatuses":[{"InstanceStatus":{"Status":"ok"},"SystemStatus":{"Status":"ok"}}]}
    def list_inventory_entries(self,**kwargs): return {"Entries":[{"Name":"openssl","Version":self.version}]}
    def send_command(self,**kwargs):
        self.calls.append(kwargs); self.version=kwargs["Parameters"]["Version"][0]
        return {"Command":{"CommandId":"command-1"}}
    def get_command_invocation(self,**kwargs): return {"Status":"Success"}


def aws_spec(): return {"tenant_id":"platform-sre","environment":"production","package":"openssl","target_version":"3.1.4", "instance_id":"i-12345678","region":"us-east-1","patch_document":"OpsPilot-PatchPackage","rollback_document":"OpsPilot-RollbackPackage"}


def test_aws_full_governed_mcp_flow(store):
    aws=AWS(); spec=aws_spec()
    register_inventory(store,[{"host_id":"aws-api","provider":"aws","spec":spec}])
    workflow=EnterpriseOpsWorkflow(ProviderRouter(store,clients={"aws":{"clients":{"ec2":aws,"ssm":aws}}}),store)
    run=workflow.investigate("platform-sre","aws-api","CVE-TEST")
    done=workflow.approve_and_execute(run["run_id"],"alice",tenant_id="platform-sre")
    assert done["status"]=="SUCCEEDED"
    assert aws.calls[0]["InstanceIds"]==["i-12345678"]
    assert aws.calls[0]["Parameters"]=={"Package":["openssl"],"Version":["3.1.4"]}
    assert aws.calls[0]["DocumentName"]=="OpsPilot-PatchPackage"


def test_aws_rejects_shell_document_and_wrong_tenant(store):
    aws=AWS(); spec=aws_spec(); spec["patch_document"]="AWS-RunShellScript"
    provider=AWSProvider(store,"aws-api",spec,run_id="run",clients={"ec2":aws,"ssm":aws})
    with pytest.raises(PermissionError): provider.patch("3.1.4")
    assert not aws.calls
    aws.tenant="foreign"
    with pytest.raises(PermissionError): provider.get_host()


def test_aws_restart_reconciles_command_receipt_without_resending(store):
    aws=AWS(); provider=AWSProvider(store,"aws-api",aws_spec(),run_id="run",clients={"ec2":aws,"ssm":aws})
    provider.receipt("execute_approved_patch",{"status":"SUBMITTED","command_id":"command-1"})
    assert provider.reconcile("execute_approved_patch")["status"]=="SUCCEEDED"
    assert not aws.calls


class Terraform:
    def __init__(self):
        self.current={"v":"old"}; self.calls=[]
        self.plan={"resource_changes":[{"address":"example.api","change":{"actions":["update"],"after":{"v":"new"},"after_unknown":{}}}]}
    def __call__(self, command, **kwargs):
        assert kwargs["shell"] is False and kwargs["timeout"]==120
        self.calls.append(command)
        if command[1]=="apply": self.current={"v":"new"}; return NS(stdout="")
        if len(command)>3: return NS(stdout=json.dumps(self.plan))
        return NS(stdout=json.dumps({"values":{"root_module":{"resources":[{"address":"example.api","values":self.current}]}}}))


def terraform_spec(tmp_path):
    file=tmp_path/"change.tfplan"; file.write_bytes(b"immutable plan")
    return {"tenant_id":"platform-sre","environment":"production","package":"example.api", "target_version":hashlib.sha256(file.read_bytes()).hexdigest(),"directory":str(tmp_path),"plan_file":file.name}


def test_terraform_apply_and_verification_are_wired_through_mcp(store,tmp_path):
    runner=Terraform(); spec=terraform_spec(tmp_path)
    register_inventory(store,[{"host_id":"terraform-api","provider":"terraform","spec":spec}])
    workflow=EnterpriseOpsWorkflow(ProviderRouter(store,clients={"terraform":{"runner":runner}}),store)
    run=workflow.investigate("platform-sre","terraform-api","CVE-TEST")
    assert run["payload"]["plan"]["rollback_available"] is False
    done=workflow.approve_and_execute(run["run_id"],"alice",tenant_id="platform-sre")
    assert done["status"]=="SUCCEEDED"
    assert sum(c[1]=="apply" for c in runner.calls)==1


@pytest.mark.parametrize("mode",["destroy","multiple","unknown","artifact_changed"])
def test_terraform_rejects_unsafe_or_changed_artifacts(store,tmp_path,mode):
    runner=Terraform(); spec=terraform_spec(tmp_path)
    if mode=="destroy": runner.plan["resource_changes"][0]["change"]["actions"]=["delete"]
    if mode=="multiple": runner.plan["resource_changes"]*=2
    if mode=="unknown": runner.plan["resource_changes"][0]["change"]["after_unknown"]={"v":True}
    if mode=="artifact_changed": (tmp_path/"change.tfplan").write_bytes(b"tampered")
    provider=TerraformProvider(store,"tf",spec,run_id="run",runner=runner)
    with pytest.raises(PermissionError): provider.patch(spec["target_version"])
    assert not any(c[1]=="apply" for c in runner.calls)


class GitHub:
    def __init__(self): self.version="old-sha"; self.merged=False; self.writes=[]
    def __call__(self,request):
        path=request.url.path
        body=json.loads(request.content) if request.content else {}
        if request.method in ("POST","PUT"): self.writes.append((path,body))
        if "/contents/" in path:
            response={"sha":self.version} if request.method=="GET" else {"content":{"sha":blob_sha(base64.b64decode(body["content"]))}}
        elif "/git/ref/" in path: response={"object":{"sha":"base-commit"}}
        elif path.endswith("/git/refs"): response={"ref":body["ref"]}
        elif path.endswith("/pulls") and request.method=="POST": response={"number":1,"html_url":"https://github.com/test/repo/pull/1"}
        elif path.endswith("/pulls/1"): response={"state":"closed" if self.merged else "open","merged":self.merged}
        else: raise AssertionError(path)
        return httpx.Response(200,json=response)


def test_github_waits_for_external_review_and_recovery_checks_merge(store):
    fake=GitHub(); client=httpx.Client(base_url="https://api.github.com",transport=httpx.MockTransport(fake))
    spec={"tenant_id":"platform-sre","environment":"production","package":"config.txt", "target_version":blob_sha(b"new config"),"content":"new config","repository":"test/repo","base_ref":"main"}
    register_inventory(store,[{"host_id":"github-api","provider":"github","spec":spec}])
    workflow=EnterpriseOpsWorkflow(ProviderRouter(store,clients={"github":{"client":client}}),store)
    run=workflow.investigate("platform-sre","github-api","CVE-TEST")
    waiting=workflow.approve_and_execute(run["run_id"],"alice",tenant_id="platform-sre")
    assert waiting["status"]=="WAITING_EXTERNAL"
    assert waiting["payload"]["execution_result"]["remediation_applied"] is False
    fake.version=spec["target_version"]; fake.merged=True
    recovered=workflow.recover(run["run_id"],"alice",tenant_id="platform-sre")
    assert recovered["status"]=="SUCCEEDED"
    assert len(fake.writes)==3


def test_inventory_cannot_reassign_ownership_or_store_credentials(store):
    spec=kube_spec(); entry={"host_id":"kube-api","provider":"kubernetes","spec":spec}
    register_inventory(store,[entry])
    modified=deepcopy(entry); modified["spec"]["tenant_id"]="foreign"
    with pytest.raises(PermissionError): register_inventory(store,[modified])
    modified=deepcopy(entry); modified["spec"]["token"]="secret"
    with pytest.raises(ValueError): register_inventory(store,[modified])
