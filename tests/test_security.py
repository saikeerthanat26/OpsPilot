from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import json

import pytest
from fastapi.testclient import TestClient

from app.mcp.client import MCPToolError, MCPToolGateway
from app.observability.tracing import Trace
from app.orchestration.enterprise_workflow import EnterpriseOpsWorkflow
from app.platform.enterprise import AgentIdentity, CapabilityRegistry, DurableRunStore
from app.security.approvals import ApprovalStore, ExecutionConflict
from app.tools.infrastructure import InfrastructureTools
from simulator.infrastructure import InfrastructureSimulator

HOST = "prod-api-01"
CVE = "CVE-DEMO-2026-001"
TENANT = "platform-sre"
EXECUTOR = AgentIdentity("sre-executor", TENANT, ("observer", "operator"), ("production",))


@pytest.fixture
def prepared(tmp_path):
    sim = InfrastructureSimulator()
    store = DurableRunStore(str(tmp_path / "runs.db"))
    workflow = EnterpriseOpsWorkflow(sim, store)
    record = workflow.investigate(TENANT, HOST, CVE)
    return sim, store, workflow, record


def authorized(prepared, clock=None):
    sim, store, _, record = prepared
    approvals = ApprovalStore(store, clock=clock) if clock else ApprovalStore(store)
    token = approvals.claim(record["run_id"], TENANT, "alice")
    client = MCPToolGateway(InfrastructureTools(sim), CapabilityRegistry(), Trace(),
                           approvals=approvals, run_id=record["run_id"])
    return client, token


def patch(client, token, executor=EXECUTOR, host=HOST, version="3.1.4"):
    return client.invoke(executor, "execute_approved_patch", approval_token=token,
                         host_id=host, to_version=version)


@pytest.mark.parametrize("kind", ["forged", "expired", "tenant", "executor", "version", "host", "run", "plan"])
def test_scope_and_expiry_denials_leave_host_unchanged(prepared, kind):
    now = [1000.0]
    client, token = authorized(prepared, lambda: now[0])
    sim, store, _, record = prepared
    agent, host, version = EXECUTOR, HOST, "3.1.4"
    if kind == "forged": token = "approved:alice:forged"
    if kind == "expired": now[0] += 300
    if kind == "tenant": agent = replace(EXECUTOR, tenant_id="team-b", roles=("admin",))
    if kind == "executor": agent = replace(EXECUTOR, agent_id="another-executor")
    if kind == "version": version = "9.9.9"
    if kind == "host":
        sim.hosts["prod-api-02"] = sim.get_host(HOST)
        host = "prod-api-02"
    if kind == "run": client.run_id = "unapproved-run"
    if kind == "plan":
        current = store.get(record["run_id"])
        current["payload"]["plan"]["cve"] = "CVE-TAMPERED"
        store.save(record["run_id"], TENANT, "EXECUTING", current["autonomy"], current["payload"])
    with pytest.raises(MCPToolError, match="permission_denied"):
        patch(client, token, agent, host, version)
    assert not sim.snapshots
    assert sim.get_host(HOST)["version"] == "3.1.2"
    assert not client.approvals.operations(record["run_id"])


def test_tokens_are_hashed_and_audit_does_not_disclose_them(prepared):
    client, token = authorized(prepared)
    sim, store, _, record = prepared
    patch(client, token)
    with store._connect() as conn:
        grants = conn.execute("SELECT * FROM approval_grants").fetchall()
    assert token not in str(grants)
    assert token not in str(client.trace.events)
    assert token not in json.dumps(store.get(record["run_id"]))


def test_replay_denied_across_mcp_sessions_and_verifier_restart(prepared):
    client, token = authorized(prepared)
    patch(client, token)
    sim, store, _, record = prepared
    restarted = MCPToolGateway(InfrastructureTools(sim), CapabilityRegistry(), Trace(),
                              approvals=ApprovalStore(DurableRunStore(store.path)), run_id=record["run_id"])
    with pytest.raises(MCPToolError, match="permission_denied"):
        patch(restarted, token)
    assert sim.snapshots[HOST]["version"] == "3.1.2"
    restarted.invoke(EXECUTOR, "rollback_patch", approval_token=token, host_id=HOST)
    with pytest.raises(MCPToolError, match="permission_denied"):
        restarted.invoke(EXECUTOR, "rollback_patch", approval_token=token, host_id=HOST)
    assert sim.get_host(HOST)["version"] == "3.1.2"


def test_rollback_cannot_be_used_before_the_approved_patch(prepared):
    client, token = authorized(prepared)
    with pytest.raises(MCPToolError, match="permission_denied"):
        client.invoke(EXECUTOR, "rollback_patch", approval_token=token, host_id=HOST)


@pytest.mark.parametrize("name", ["get_host_health", "list_vulnerabilities", "get_patch_metadata", "verify_host_health"])
def test_cross_tenant_reads_denied_even_for_admin(prepared, name):
    client = MCPToolGateway(InfrastructureTools(prepared[0]), CapabilityRegistry(), Trace())
    with pytest.raises(MCPToolError, match="permission_denied"):
        client.invoke(replace(EXECUTOR, tenant_id="team-b", roles=("admin",)), name, host_id=HOST)


def test_two_simultaneous_approvals_claim_exactly_once(prepared):
    _, store, _, record = prepared
    def claim():
        try:
            return ApprovalStore(DurableRunStore(store.path)).claim(record["run_id"], TENANT, "alice")
        except ExecutionConflict:
            return None
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(lambda _: claim(), range(4)))
    assert sum(token is not None for token in results) == 1
    with store._connect() as conn:
        assert conn.execute("SELECT COUNT(*) FROM approval_grants").fetchone()[0] == 1


def test_two_simultaneous_mcp_patches_execute_exactly_once(prepared):
    client, token = authorized(prepared)
    def call():
        try: return patch(client, token)["executed"]
        except MCPToolError: return False
    with ThreadPoolExecutor(max_workers=2) as pool:
        assert list(pool.map(lambda _: call(), range(2))).count(True) == 1
    assert prepared[0].snapshots[HOST]["version"] == "3.1.2"


def test_active_host_lease_blocks_another_run(prepared):
    _, store, workflow, first = prepared
    second = workflow.investigate(TENANT, HOST, CVE)
    workflow.approvals.claim(first["run_id"], TENANT, "alice")
    with pytest.raises(ExecutionConflict, match="host"):
        workflow.approvals.claim(second["run_id"], TENANT, "alice")
    assert store.get(second["run_id"])["status"] == "WAITING_APPROVAL"


def test_duplicate_approval_returns_cached_outcome_without_patching_again(prepared):
    sim, _, workflow, record = prepared
    done = workflow.approve_and_execute(record["run_id"], "alice", tenant_id=TENANT)
    repeat = workflow.approve_and_execute(record["run_id"], "alice", tenant_id=TENANT)
    assert repeat == done
    assert sim.snapshots[HOST]["version"] == "3.1.2"
    assert done["payload"]["operations"] == {"execute_approved_patch": "SUCCEEDED"}


def test_other_tenant_cannot_approve_or_read_run(prepared):
    _, store, workflow, record = prepared
    assert store.get(record["run_id"], "team-b") is None
    with pytest.raises(KeyError):
        workflow.approve_and_execute(record["run_id"], "mallory", tenant_id="team-b")
    assert store.get(record["run_id"])["status"] == "WAITING_APPROVAL"


def test_backend_unknown_outcome_cannot_be_replayed(prepared):
    sim, store, workflow, record = prepared
    def patch_then_fail(host, version):
        sim.hosts[host]["version"] = version
        raise RuntimeError("backend disconnected")
    sim.patch = patch_then_fail
    with pytest.raises(MCPToolError, match="execution_failed"):
        workflow.approve_and_execute(record["run_id"], "alice", tenant_id=TENANT)
    escalated = store.get(record["run_id"])
    assert escalated["status"] == "ESCALATED"
    assert escalated["payload"]["operations"] == {"execute_approved_patch": "UNKNOWN"}
    with pytest.raises(ExecutionConflict):
        workflow.approve_and_execute(record["run_id"], "alice", tenant_id=TENANT)
    with store._connect() as conn:
        assert conn.execute("SELECT COUNT(*) FROM host_leases").fetchone()[0] == 1


@pytest.mark.parametrize("field,value", [("version", "3.1.3"), ("package", "other-package"), ("target_version", "9.9.9")])
def test_inventory_drift_blocks_execution(prepared, field, value):
    client, token = authorized(prepared)
    prepared[0].hosts[HOST][field] = value
    with pytest.raises(MCPToolError, match="permission_denied"):
        patch(client, token)
    assert not prepared[0].snapshots


@pytest.fixture
def api(prepared, monkeypatch):
    from app.api import main
    monkeypatch.setattr(main, "store", prepared[1])
    claims = {
        "alice-test-token": {"subject": "alice", "tenant_id": TENANT, "roles": ["observer", "approver"], "environment_scopes": ["production"]},
        "bob-test-token": {"subject": "bob", "tenant_id": "team-b", "roles": ["observer", "approver"], "environment_scopes": ["production"]},
        "observer-test-token": {"subject": "observer", "tenant_id": TENANT, "roles": ["observer"], "environment_scopes": ["production"]},
    }
    monkeypatch.setenv("OPSPILOT_API_IDENTITIES", json.dumps(claims))
    return TestClient(main.app)


def headers(token="alice-test-token"):
    return {"Authorization": f"Bearer {token}"}


def test_api_requires_authentication_and_filters_runs(api, prepared):
    run = prepared[3]["run_id"]
    assert api.get(f"/v2/runs/{run}").status_code == 401
    assert api.get(f"/v2/runs/{run}", headers=headers("fake-token")).status_code == 401
    assert api.get(f"/v2/runs/{run}", headers=headers("bob-test-token")).status_code == 404
    assert api.get(f"/v2/runs/{run}/events", headers=headers("bob-test-token")).status_code == 404
    assert api.get(f"/v2/runs/{run}", headers=headers()).status_code == 200


def test_api_cannot_spoof_tenant_agent_or_approver(api, prepared):
    run = prepared[3]["run_id"]
    assert api.post("/v2/incidents", json={"tenant_id": "team-b"}, headers=headers()).status_code == 403
    assert api.post("/v2/incidents", json={"agent_id": "admin"}, headers=headers()).status_code == 422
    assert api.post(f"/v2/runs/{run}/approve", json={"approver": "admin"}, headers=headers()).status_code == 422
    assert api.post(f"/v2/runs/{run}/approve", json={}, headers=headers("observer-test-token")).status_code == 403
    assert api.post(f"/v2/runs/{run}/approve", json={}, headers=headers("bob-test-token")).status_code == 404
    done = api.post(f"/v2/runs/{run}/approve", json={}, headers=headers())
    assert done.status_code == 200
    assert done.json()["payload"]["approval"]["approver"] == "alice"
    assert api.post(f"/v2/runs/{run}/approve", json={}, headers=headers()).json() == done.json()


def test_api_authenticated_investigation(api):
    created = api.post("/v2/incidents", json={}, headers=headers())
    assert created.status_code == 202
    assert created.json()["payload"]["agent"]["agent_id"] == "alice"
    assert api.post("/v2/incidents", json={"tenant_id": "team-b"}, headers=headers("bob-test-token")).status_code == 403


def test_failed_authorization_retains_the_execution_audit(prepared):
    _, store, workflow, record = prepared
    workflow.simulator.hosts[HOST]["version"] = "3.1.3"
    with pytest.raises(MCPToolError):
        workflow.approve_and_execute(record["run_id"], "alice", tenant_id=TENANT)
    persisted = store.get(record["run_id"])
    assert persisted["status"] == "ESCALATED"
    assert any(event["event"] == "mcp.tool.failed" for event in persisted["payload"]["events"])


def test_api_has_no_default_identity_bypass(api, prepared, monkeypatch):
    monkeypatch.delenv("OPSPILOT_API_IDENTITIES", raising=False)
    run = prepared[3]["run_id"]
    assert api.get(f"/v2/runs/{run}", headers=headers()).status_code == 401


def test_api_checks_environment_scope_for_read_and_approval(api, prepared, monkeypatch):
    monkeypatch.setenv("OPSPILOT_API_IDENTITIES", json.dumps({
        "restricted-token": {"subject": "restricted", "tenant_id": TENANT,
                             "roles": ["observer", "approver"], "environment_scopes": ["nonproduction"]}
    }))
    run = prepared[3]["run_id"]
    restricted = headers("restricted-token")
    assert api.get(f"/v2/runs/{run}", headers=restricted).status_code == 403
    assert api.get(f"/v2/runs/{run}/events", headers=restricted).status_code == 403
    assert api.post(f"/v2/runs/{run}/approve", json={}, headers=restricted).status_code == 403
    assert prepared[1].get(run)["status"] == "WAITING_APPROVAL"


def test_cross_tenant_investigation_does_not_persist_a_run(prepared):
    sim, store, workflow, _ = prepared
    with pytest.raises(MCPToolError, match="permission_denied"):
        workflow.investigate("team-b", HOST, CVE)
    with store._connect() as conn:
        assert conn.execute("SELECT COUNT(*) FROM runs").fetchone()[0] == 1
    assert not sim.snapshots


@pytest.mark.parametrize("failure", [False, True])
def test_verified_terminal_outcome_releases_host_lease(prepared, failure):
    _, store, workflow, record = prepared
    record["payload"]["inject_failure"] = failure
    store.save(record["run_id"], TENANT, record["status"], record["autonomy"], record["payload"])
    done = workflow.approve_and_execute(record["run_id"], "alice", tenant_id=TENANT)
    assert done["status"] == ("ROLLED_BACK" if failure else "SUCCEEDED")
    with store._connect() as conn:
        assert conn.execute("SELECT COUNT(*) FROM host_leases").fetchone()[0] == 0
