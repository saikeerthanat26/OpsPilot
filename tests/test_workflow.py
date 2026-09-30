from app.orchestration.workflow import OpsPilotWorkflow
from app.domain.models import Status
from simulator.infrastructure import InfrastructureSimulator

def test_production_change_requires_approval():
    r=OpsPilotWorkflow(InfrastructureSimulator()).run("prod-api-01","CVE-DEMO-2026-001",approved=False)
    assert r.status==Status.WAITING_APPROVAL

def test_approved_patch_succeeds():
    r=OpsPilotWorkflow(InfrastructureSimulator()).run("prod-api-01","CVE-DEMO-2026-001",approved=True)
    assert r.status==Status.SUCCEEDED

def test_failed_health_check_rolls_back():
    sim=InfrastructureSimulator(fail_validation=True)
    r=OpsPilotWorkflow(sim).run("prod-api-01","CVE-DEMO-2026-001",approved=True)
    assert r.status==Status.ROLLED_BACK
    assert sim.get_host("prod-api-01")["version"]=="3.1.2"
