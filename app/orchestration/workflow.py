import uuid
from app.domain.models import Evidence, WorkflowResult, Status
from app.tools.infrastructure import InfrastructureTools
from app.agents.diagnostics import DiagnosticAgent
from app.agents.vulnerability import VulnerabilityAgent
from app.agents.planner import RemediationPlanner
from app.retrieval.knowledge import KnowledgeService
from app.policy.engine import PolicyEngine
from app.execution.executor import DeterministicExecutor
from app.observability.tracing import Trace

class OpsPilotWorkflow:
    def __init__(self, simulator):
        self.tools=InfrastructureTools(simulator); self.trace=Trace(); self.policy=PolicyEngine()
    def run(self,host,cve,approved=False):
        run_id=str(uuid.uuid4()); evidence=[]
        self.trace.add("workflow.started",f"host={host}, cve={cve}")
        evidence += DiagnosticAgent(self.tools).run(host); self.trace.add("diagnostics.completed")
        evidence += VulnerabilityAgent(self.tools).run(host,cve); self.trace.add("vulnerability.completed")
        docs=KnowledgeService().retrieve("openssl critical patch")
        evidence += [Evidence("runbook",d["id"],d["text"]) for d in docs]; self.trace.add("knowledge.retrieved",f"documents={len(docs)}")
        plan=RemediationPlanner(self.tools).plan(host,cve); self.trace.add("plan.created",f"plan={plan.plan_id}, blast_radius={plan.blast_radius}")
        level,authorized=self.policy.authorize(plan,approved); self.trace.add("policy.evaluated",f"autonomy={level.value}, authorized={authorized}")
        if not authorized:
            self.trace.add("approval.required","production mutation blocked")
            return WorkflowResult(run_id,Status.WAITING_APPROVAL,level,evidence,self.trace.events,"Execution paused pending human approval.")
        self.trace.add("approval.validated")
        ok=DeterministicExecutor(self.tools,self.trace).execute(plan,"approved")
        status=Status.SUCCEEDED if ok else Status.ROLLED_BACK
        msg="Patch verified successfully." if ok else "Health validation failed; patch rolled back and incident escalated."
        if not ok: self.trace.add("incident.escalated","post-change verification failed")
        return WorkflowResult(run_id,status,level,evidence,self.trace.events,msg)
