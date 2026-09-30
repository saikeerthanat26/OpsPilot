import json
from pathlib import Path
from tempfile import TemporaryDirectory

from app.orchestration.enterprise_workflow import EnterpriseOpsWorkflow
from app.orchestration.workflow import OpsPilotWorkflow
from app.platform.enterprise import DurableRunStore
from simulator.infrastructure import InfrastructureSimulator
from app.storage.simulator import DurableSimulator
from app.platform.enterprise import AgentIdentity


def main():
    cases = json.loads(Path(__file__).with_name("golden_scenarios.json").read_text())
    passed = 0
    with TemporaryDirectory(prefix="opspilot-evals-") as directory:
        for case in cases:
            legacy = OpsPilotWorkflow(InfrastructureSimulator(case.get("inject_failure", False))).run(
                case["host"], case["cve"], approved=True,
            )
            outcomes = [(case["id"], legacy.status.value, legacy.autonomy.value)]
            sim = InfrastructureSimulator(case.get("inject_failure", False))
            workflow = EnterpriseOpsWorkflow(sim, DurableRunStore(str(Path(directory) / f"{case['id']}.db")))
            record = workflow.investigate("platform-sre", case["host"], case["cve"],
                                          inject_failure=case.get("inject_failure", False))
            enterprise = workflow.approve_and_execute(record["run_id"], "evaluation-approver", tenant_id="platform-sre")
            outcomes.append((f"enterprise-{case['id']}", enterprise["status"], enterprise["autonomy"]))
            # Simulate a restart after a durable backend commit but before the
            # operation acknowledgement. Recovery must reuse proof, not repatch.
            durable_store = DurableRunStore(str(Path(directory) / f"restart-{case['id']}.db"))
            durable = EnterpriseOpsWorkflow(store=durable_store)
            pending = durable.investigate("platform-sre", case["host"], case["cve"],
                                          inject_failure=case.get("inject_failure", False))
            token = durable.approvals.claim(pending["run_id"], "platform-sre", "evaluation-approver")
            plan = pending["payload"]["plan"]
            executor = AgentIdentity("sre-executor", "platform-sre", ("observer", "operator"), ("production",))
            durable.approvals.reserve(token, pending["run_id"], executor, "execute_approved_patch",
                                     {"host_id": case["host"], "to_version": plan["to_version"]})
            DurableSimulator(durable_store, run_id=pending["run_id"],
                             fail_validation=case.get("inject_failure", False)).patch(case["host"], plan["to_version"])
            recovered = EnterpriseOpsWorkflow(store=DurableRunStore(durable_store.path)).recover(
                pending["run_id"], "recovery-evaluator", tenant_id="platform-sre")
            assert any(event["event"] == "execution.reused" for event in recovered["payload"]["events"])
            outcomes.append((f"restart-{case['id']}", recovered["status"], recovered["autonomy"]))
            for name, status, autonomy in outcomes:
                ok = status == case["expected_status"] and (
                    "expected_autonomy" not in case or autonomy == case["expected_autonomy"]
                )
                passed += ok
                print(name, "PASS" if ok else "FAIL", status, autonomy)
    count = len(cases) * 3
    print(f"task_completion={passed / count:.0%}")
    return 0 if passed == count else 1


if __name__ == "__main__":
    raise SystemExit(main())
