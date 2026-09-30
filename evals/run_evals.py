import json
from pathlib import Path
from tempfile import TemporaryDirectory

from app.orchestration.enterprise_workflow import EnterpriseOpsWorkflow
from app.orchestration.workflow import OpsPilotWorkflow
from app.platform.enterprise import DurableRunStore
from simulator.infrastructure import InfrastructureSimulator


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
            for name, status, autonomy in outcomes:
                ok = status == case["expected_status"] and (
                    "expected_autonomy" not in case or autonomy == case["expected_autonomy"]
                )
                passed += ok
                print(name, "PASS" if ok else "FAIL", status, autonomy)
    count = len(cases) * 2
    print(f"task_completion={passed / count:.0%}")
    return 0 if passed == count else 1


if __name__ == "__main__":
    raise SystemExit(main())
