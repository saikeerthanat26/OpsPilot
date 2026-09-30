import json
import os
import sqlite3
from concurrent.futures import ThreadPoolExecutor

import pytest

from app.orchestration.enterprise_workflow import EnterpriseOpsWorkflow
from app.platform.enterprise import AgentIdentity, CapabilityRegistry, DurableRunStore
from app.mcp.client import MCPToolGateway
from app.observability.tracing import Trace
from app.security.approvals import ApprovalStore, ExecutionConflict
from app.storage.repositories import AuditRepository
from app.storage.simulator import DurableSimulator
from app.tools.infrastructure import InfrastructureTools

TENANT="platform-sre"
HOST="prod-api-01"
CVE="CVE-DEMO-2026-001"
EXECUTOR=AgentIdentity("sre-executor",TENANT,("observer","operator"),("production",))


@pytest.fixture
def durable(tmp_path):
    store=DurableRunStore(str(tmp_path/"durable.db"))
    return store, EnterpriseOpsWorkflow(store=store)


def incident(workflow, fail=False): return workflow.investigate(TENANT,HOST,CVE,inject_failure=fail)


def test_restart_waiting_approval_and_terminal_retry(durable):
    store, original=durable
    record=incident(original)
    restarted=EnterpriseOpsWorkflow(store=DurableRunStore(store.path))
    completed=restarted.approve_and_execute(record["run_id"],"alice",tenant_id=TENANT)
    assert completed["status"]=="SUCCEEDED"
    assert DurableSimulator(DurableRunStore(store.path)).get_host(HOST)["version"]=="3.1.4"
    third=EnterpriseOpsWorkflow(store=DurableRunStore(store.path))
    assert third.approve_and_execute(record["run_id"],"alice",tenant_id=TENANT)==completed


@pytest.mark.parametrize("failure",[False,True])
def test_recover_after_backend_commit_before_operation_ack(durable, failure):
    store, workflow=durable
    record=incident(workflow,failure)
    token=workflow.approvals.claim(record["run_id"],TENANT,"alice")
    workflow.approvals.reserve(token,record["run_id"],EXECUTOR,"execute_approved_patch",{"host_id":HOST,"to_version":"3.1.4"})
    backend=DurableSimulator(store,run_id=record["run_id"],fail_validation=failure)
    backend.patch(HOST,"3.1.4")
    # Simulate process exit before gateway acknowledgement/checkpoint.
    assert workflow.approvals.operations(record["run_id"])["execute_approved_patch"]=="STARTED"
    restarted=EnterpriseOpsWorkflow(store=DurableRunStore(store.path))
    done=restarted.recover(record["run_id"],"recovery-oncall",tenant_id=TENANT)
    assert done["status"]==("ROLLED_BACK" if failure else "SUCCEEDED")
    assert DurableSimulator(store).get_host(HOST)["version"]==("3.1.2" if failure else "3.1.4")
    assert any(e["event"]=="execution.reused" for e in done["payload"]["events"])
    with store._connect() as conn:
        assert conn.execute("SELECT COUNT(*) FROM snapshots WHERE run_id=?",(record["run_id"],)).fetchone()[0]==1


def test_recover_before_patch_starts_with_fresh_approval(durable):
    store, workflow=durable
    record=incident(workflow)
    old=workflow.approvals.claim(record["run_id"],TENANT,"alice",ttl_seconds=1)
    restarted=EnterpriseOpsWorkflow(store=DurableRunStore(store.path))
    assert restarted.recover(record["run_id"],"bob",tenant_id=TENANT)["status"]=="SUCCEEDED"
    with pytest.raises(PermissionError):
        workflow.approvals.reserve(old,record["run_id"],EXECUTOR,"execute_approved_patch",{"host_id":HOST,"to_version":"3.1.4"})


def test_recovery_refuses_unknown_mutation_and_retains_lease(durable):
    store, workflow=durable
    record=incident(workflow)
    token=workflow.approvals.claim(record["run_id"],TENANT,"alice")
    workflow.approvals.reserve(token,record["run_id"],EXECUTOR,"execute_approved_patch",{"host_id":HOST,"to_version":"3.1.4"})
    restarted=EnterpriseOpsWorkflow(store=DurableRunStore(store.path))
    with pytest.raises(ExecutionConflict,match="unresolved"):
        restarted.recover(record["run_id"],"alice",tenant_id=TENANT)
    assert restarted.store.get(record["run_id"])["status"]=="ESCALATED"
    assert DurableSimulator(store).get_host(HOST)["version"]=="3.1.2"
    with store._connect() as conn:
        assert conn.execute("SELECT COUNT(*) FROM host_leases").fetchone()[0]==1


def test_active_worker_cannot_be_stolen(durable):
    _, workflow=durable
    record=incident(workflow)
    workflow.approvals.claim(record["run_id"],TENANT,"alice",worker_owner="active")
    with pytest.raises(ExecutionConflict,match="active"):
        workflow.recover(record["run_id"],"bob",tenant_id=TENANT)


def test_actual_langgraph_checkpoint_contains_no_runtime_credentials(durable):
    store, workflow=durable
    record=incident(workflow)
    done=workflow.approve_and_execute(record["run_id"],"alice",tenant_id=TENANT)
    with store.database.checkpointer() as saver:
        snapshots=list(saver.list({"configurable":{"thread_id":record["run_id"]}}))
    assert len(snapshots)>=6
    for snapshot in snapshots:
        state=snapshot.checkpoint["channel_values"]
        assert not any(key in state for key in ("approval_token","simulator","approvals","trace","worker_owner"))
    assert done["payload"]["approval"]["grant_id"]


def test_resume_checkpoint_at_failed_verification_without_repatch(durable, monkeypatch):
    store, workflow=durable
    record=incident(workflow)
    original=DurableSimulator.validate
    calls=[]
    def lost_connection(self, host_id):
        calls.append(host_id)
        raise RuntimeError("verification transport disconnected")
    monkeypatch.setattr(DurableSimulator,"validate",lost_connection)
    from app.mcp.client import MCPToolError
    with pytest.raises(MCPToolError): workflow.approve_and_execute(record["run_id"],"alice",tenant_id=TENANT)
    monkeypatch.setattr(DurableSimulator,"validate",original)
    done=EnterpriseOpsWorkflow(store=DurableRunStore(store.path)).recover(record["run_id"],"alice",tenant_id=TENANT)
    assert done["status"]=="SUCCEEDED"
    with store._connect() as conn:
        assert conn.execute("SELECT COUNT(*) FROM operations WHERE capability='execute_approved_patch'").fetchone()[0]==1


def test_audit_is_available_after_worker_restart_and_tenant_filtered(durable):
    store, workflow=durable
    record=incident(workflow)
    done=workflow.approve_and_execute(record["run_id"],"alice",tenant_id=TENANT)
    audit=AuditRepository(DurableRunStore(store.path))
    events=audit.list(record["run_id"],TENANT)
    assert any(e["event"]=="tool.completed" for e in events)
    assert not audit.list(record["run_id"],"foreign-tenant")
    assert len(events)>=len(done["payload"]["events"])


def test_existing_v05_schema_migrates_without_losing_runs(tmp_path):
    path=str(tmp_path/"old.db")
    with sqlite3.connect(path) as conn:
        conn.execute("CREATE TABLE runs (run_id TEXT PRIMARY KEY,tenant_id TEXT,status TEXT,autonomy TEXT,payload TEXT,created_at TEXT,updated_at TEXT)")
        conn.execute("INSERT INTO runs VALUES ('old','platform-sre','WAITING_APPROVAL','L2','{}','old','old')")
    store=DurableRunStore(path)
    assert store.get("old")["status"]=="WAITING_APPROVAL"
    assert DurableSimulator(store).seed().get_host(HOST)["tenant_id"]==TENANT


def test_bootstrap_records_migration_and_is_repeatable(tmp_path, monkeypatch):
    path = str(tmp_path / "bootstrap.db")
    monkeypatch.setenv("OPSPILOT_DATABASE_URL", "sqlite:///" + path)
    from app.storage.bootstrap import main
    main()
    DurableSimulator(DurableRunStore(path),run_id="existing").patch(HOST,"3.1.4")
    main()
    with sqlite3.connect(path) as connection:
        assert connection.execute("SELECT version_num FROM alembic_version").fetchone()[0] == "001_control_plane"
    assert DurableSimulator(DurableRunStore(path)).get_host(HOST)["version"] == "3.1.4"


def test_checkpoint_api_reports_pending_verification(durable, monkeypatch):
    store, workflow = durable
    run = incident(workflow)
    def disconnected(self, host_id): raise RuntimeError("disconnected")
    monkeypatch.setattr(DurableSimulator,"validate",disconnected)
    from app.mcp.client import MCPToolError
    with pytest.raises(MCPToolError): workflow.approve_and_execute(run["run_id"],"alice",tenant_id=TENANT)
    from app.api import main as api
    from app.security.identity import Principal
    monkeypatch.setattr(api,"store",store)
    principal=Principal("alice",AgentIdentity("alice",TENANT,("observer","approver"),("production",)))
    snapshot=api.checkpoint(run["run_id"],principal)
    assert snapshot["pending_nodes"] == ["verify_health"]
    assert snapshot["checkpoint_id"]


def test_superseded_worker_cannot_overwrite_recovery_outcome(durable):
    store, workflow = durable
    run = incident(workflow)
    workflow.approvals.claim(run["run_id"],TENANT,"alice",worker_owner="old")
    with store._connect() as connection:
        connection.execute("UPDATE execution_workers SET expires_at=0 WHERE run_id=?",(run["run_id"],))
    done=workflow.recover(run["run_id"],"bob",tenant_id=TENANT)
    assert done["status"] == "SUCCEEDED"
    assert not workflow.approvals.escalate_owned(run["run_id"],TENANT,run["autonomy"],run["payload"],"old")
    with pytest.raises(ExecutionConflict):
        workflow.approvals.complete(run["run_id"],TENANT,"ROLLED_BACK",run["autonomy"],run["payload"],worker_owner="old")
    assert store.get(run["run_id"])["status"] == "SUCCEEDED"
