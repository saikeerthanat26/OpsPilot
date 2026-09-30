import argparse
from app.orchestration.workflow import OpsPilotWorkflow
from simulator.infrastructure import InfrastructureSimulator

def main():
    p=argparse.ArgumentParser()
    p.add_argument('--failure', action='store_true', help='inject post-patch health failure and demonstrate rollback')
    args=p.parse_args()
    sim=InfrastructureSimulator(fail_validation=args.failure)
    workflow=OpsPilotWorkflow(sim)
    result=workflow.run("prod-api-01", "CVE-DEMO-2026-001", approved=True)
    print(result.pretty())

if __name__ == '__main__': main()
