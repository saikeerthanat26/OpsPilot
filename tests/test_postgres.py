"""Real PostgreSQL checks; CI runs these against a PostgreSQL 16 service."""
import os
from concurrent.futures import ThreadPoolExecutor

import pytest
from sqlalchemy import text

from app.orchestration.enterprise_workflow import EnterpriseOpsWorkflow
from app.platform.enterprise import AgentIdentity, DurableRunStore
from app.security.approvals import ExecutionConflict
from app.storage.models import metadata
from app.storage.simulator import DurableSimulator

URL = os.getenv("OPSPILOT_TEST_POSTGRES_URL")
pytestmark = pytest.mark.skipif(not URL, reason="requires OPSPILOT_TEST_POSTGRES_URL")
TENANT = "platform-sre"
EXECUTOR = AgentIdentity("sre-executor", TENANT, ("observer", "operator"), ("production",))


@pytest.fixture
def store(monkeypatch):
    monkeypatch.setenv("OPSPILOT_DATABASE_URL", URL)
    from app.storage.bootstrap import main
    main()
    store = DurableRunStore(URL)
    with store.database.engine.begin() as connection:
        for table in metadata.sorted_tables: connection.execute(table.delete())
    yield store
    store.database.engine.dispose()


def incident(workflow, fail=False):
    return workflow.investigate(TENANT, "prod-api-01", "CVE-DEMO-2026-001", inject_failure=fail)


@pytest.mark.parametrize("fail", [False, True])
def test_postgres_migration_checkpoint_and_restart(store, fail):
    original = EnterpriseOpsWorkflow(store=store)
    record = incident(original, fail)
    restarted = EnterpriseOpsWorkflow(store=DurableRunStore(URL))
    done = restarted.approve_and_execute(record["run_id"], "alice", tenant_id=TENANT)
    assert done["status"] == ("ROLLED_BACK" if fail else "SUCCEEDED")
    with store.database.checkpointer() as saver:
        assert len(list(saver.list({"configurable": {"thread_id": record["run_id"]}}))) >= 6
    with store.database.engine.connect() as connection:
        assert connection.execute(text("SELECT version_num FROM alembic_version")).scalar() == "001_control_plane"
    again = EnterpriseOpsWorkflow(store=DurableRunStore(URL))
    assert again.approve_and_execute(record["run_id"], "alice", tenant_id=TENANT) == done


def test_postgres_concurrent_claims_have_one_winner(store):
    workflow = EnterpriseOpsWorkflow(store=store)
    record = incident(workflow)
    def claim(owner):
        other = EnterpriseOpsWorkflow(store=DurableRunStore(URL))
        try:
            other.approvals.claim(record["run_id"], TENANT, owner, worker_owner=owner)
            return True
        except (ExecutionConflict, ValueError): return False
    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sum(pool.map(claim, ["alice", "bob"])) == 1
    with store._connect() as connection:
        assert connection.execute("SELECT COUNT(*) FROM approval_grants").scalar() == 1
        assert connection.execute("SELECT COUNT(*) FROM execution_workers").scalar() == 1


def test_postgres_recovers_proven_mutation_without_replay(store):
    workflow = EnterpriseOpsWorkflow(store=store)
    record = incident(workflow)
    token = workflow.approvals.claim(record["run_id"], TENANT, "alice")
    workflow.approvals.reserve(token, record["run_id"], EXECUTOR, "execute_approved_patch",
                               {"host_id": "prod-api-01", "to_version": "3.1.4"})
    DurableSimulator(store, run_id=record["run_id"]).patch("prod-api-01", "3.1.4")
    done = EnterpriseOpsWorkflow(store=DurableRunStore(URL)).recover(record["run_id"], "bob", tenant_id=TENANT)
    assert done["status"] == "SUCCEEDED"
    assert any(e["event"] == "execution.reused" for e in done["payload"]["events"])


def test_postgres_unknown_mutation_remains_blocked(store):
    workflow = EnterpriseOpsWorkflow(store=store)
    record = incident(workflow)
    token = workflow.approvals.claim(record["run_id"], TENANT, "alice")
    workflow.approvals.reserve(token, record["run_id"], EXECUTOR, "execute_approved_patch",
                               {"host_id": "prod-api-01", "to_version": "3.1.4"})
    with pytest.raises(ExecutionConflict):
        EnterpriseOpsWorkflow(store=DurableRunStore(URL)).recover(record["run_id"], "bob", tenant_id=TENANT)
    with store._connect() as connection:
        assert connection.execute("SELECT COUNT(*) FROM host_leases").scalar() == 1
    assert DurableSimulator(store).get_host("prod-api-01")["version"] == "3.1.2"
