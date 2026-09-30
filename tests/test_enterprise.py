import os, tempfile
from simulator.infrastructure import InfrastructureSimulator
from app.orchestration.enterprise_workflow import EnterpriseOpsWorkflow
from app.platform.enterprise import DurableRunStore

def wf(fail=False):
    path=tempfile.mktemp(suffix=".db")
    return EnterpriseOpsWorkflow(InfrastructureSimulator(fail, tenant_id="team-a"),DurableRunStore(path))

def test_production_incident_pauses_and_persists():
    w=wf(); r=w.investigate("team-a","prod-api-01","CVE-DEMO-2026-001")
    assert r["status"]=="WAITING_APPROVAL"
    assert w.store.get(r["run_id"])["tenant_id"]=="team-a"
    assert any(e["event"]=="approval.required" for e in r["payload"]["events"])

def test_approval_executes_and_verifies():
    w=wf(); r=w.investigate("team-a","prod-api-01","CVE-DEMO-2026-001")
    done=w.approve_and_execute(r["run_id"],"alice", tenant_id="team-a")
    assert done["status"]=="SUCCEEDED"
    assert any(e["event"]=="tool.invoked" for e in done["payload"]["events"])
    assert any(e["event"]=="mcp.call.completed" for e in done["payload"]["events"])

def test_failed_postcheck_rolls_back():
    w=wf(True); r=w.investigate("team-a","prod-api-01","CVE-DEMO-2026-001",inject_failure=True)
    done=w.approve_and_execute(r["run_id"],"alice", tenant_id="team-a")
    assert done["status"]=="ROLLED_BACK"
    assert any(e["event"]=="incident.escalated" for e in done["payload"]["events"])
