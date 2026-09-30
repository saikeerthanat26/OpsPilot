class DeterministicExecutor:
    def __init__(self,tools,trace): self.tools=tools; self.trace=trace
    def execute(self,plan,approval_token):
        self.trace.add("execution.started",f"plan={plan.plan_id}")
        self.tools.execute_approved_patch(plan.host_id,plan.to_version,approval_token)
        self.trace.add("canary.patched",plan.host_id)
        health=self.tools.verify_host_health(plan.host_id)
        self.trace.add("verification.completed",str(health))
        if not health["healthy"]:
            self.tools.rollback_patch(plan.host_id)
            self.trace.add("rollback.completed",plan.host_id)
            return False
        return True
