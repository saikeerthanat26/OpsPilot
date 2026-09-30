import json
from pathlib import Path
from app.orchestration.workflow import OpsPilotWorkflow
from simulator.infrastructure import InfrastructureSimulator
cases=json.loads(Path("evals/golden_scenarios.json").read_text())
passed=0
for c in cases:
    r=OpsPilotWorkflow(InfrastructureSimulator(c.get("inject_failure",False))).run(c["host"],c["cve"],approved=True)
    ok=r.status.value==c["expected_status"] and ("expected_autonomy" not in c or r.autonomy.value==c["expected_autonomy"])
    passed+=ok; print(c["id"],"PASS" if ok else "FAIL",r.status.value,r.autonomy.value)
print(f"task_completion={passed/len(cases):.0%}")
