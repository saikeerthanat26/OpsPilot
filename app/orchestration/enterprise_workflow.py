import uuid
from app.domain.models import Evidence, Status
from app.tools.infrastructure import InfrastructureTools
from app.retrieval.knowledge import KnowledgeService
from app.agents.planner import RemediationPlanner
from app.policy.engine import PolicyEngine
from app.observability.tracing import Trace
from app.platform.enterprise import AgentIdentity, CapabilityRegistry, ToolGateway, ModelRouter, DurableRunStore

class EnterpriseOpsWorkflow:
    def __init__(self, simulator, store=None):
        self.simulator=simulator; self.store=store or DurableRunStore(); self.registry=CapabilityRegistry(); self.router=ModelRouter()

    def investigate(self, tenant_id, host_id, cve, agent_id="sre-investigator", inject_failure=False):
        run_id=str(uuid.uuid4()); trace=Trace(); tools=InfrastructureTools(self.simulator); gateway=ToolGateway(tools,self.registry,trace)
        identity=AgentIdentity(agent_id,tenant_id,("observer","operator"),("production","nonproduction"))
        trace.add("workflow.started",f"tenant={tenant_id}, host={host_id}, cve={cve}")
        route=self.router.route("incident_reasoning","internal"); trace.add("model.routed",f"provider={route['provider']}, model={route['model']}")
        health=gateway.invoke(identity,"get_host_health",host_id=host_id)
        vulns=gateway.invoke(identity,"list_vulnerabilities",host_id=host_id)
        evidence=[Evidence("metrics",k,v) for k,v in health.items()]+[Evidence("vulnerability","requested_cve_present",cve in vulns),Evidence("vulnerability","active",vulns)]
        docs=KnowledgeService().retrieve("openssl critical patch"); evidence += [Evidence("runbook",d["id"],d["text"]) for d in docs]
        trace.add("evidence.package.created",f"items={len(evidence)}")
        plan=RemediationPlanner(tools).plan(host_id,cve); trace.add("plan.created",f"plan={plan.plan_id}, blast_radius={plan.blast_radius}")
        level,_=PolicyEngine().authorize(plan,False); trace.add("policy.evaluated",f"autonomy={level.value}, production={plan.production}")
        status=Status.WAITING_APPROVAL if level.value=="L2_APPROVAL_REQUIRED" else Status.PLANNED
        if status==Status.WAITING_APPROVAL: trace.add("approval.required","production mutation blocked at tool gateway")
        payload={"host_id":host_id,"cve":cve,"plan":plan.__dict__,"evidence":[e.__dict__ for e in evidence],"events":trace.events,"model_route":route,"agent":{"agent_id":identity.agent_id,"roles":list(identity.roles)},"inject_failure":inject_failure}
        self.store.save(run_id,tenant_id,status.value,level.value,payload)
        return self.store.get(run_id)

    def approve_and_execute(self, run_id, approver):
        record=self.store.get(run_id)
        if not record: raise KeyError("run not found")
        if record["status"] != Status.WAITING_APPROVAL.value: raise ValueError(f"run is {record['status']}, not WAITING_APPROVAL")
        from simulator.infrastructure import InfrastructureSimulator
        sim=InfrastructureSimulator(record["payload"].get("inject_failure",False)); tools=InfrastructureTools(sim); trace=Trace(); registry=self.registry; gateway=ToolGateway(tools,registry,trace)
        identity=AgentIdentity("sre-executor",record["tenant_id"],("observer","operator"),("production",))
        p=record["payload"]["plan"]; token=f"approved:{approver}:{uuid.uuid4()}"; trace.add("approval.granted",f"approver={approver}")
        gateway.invoke(identity,"execute_approved_patch",approval_token=token,host_id=p["host_id"],to_version=p["to_version"])
        health=gateway.invoke(identity,"verify_host_health",host_id=p["host_id"])
        if health["healthy"]:
            status=Status.SUCCEEDED; trace.add("workflow.succeeded","post-change verification passed")
        else:
            gateway.invoke(identity,"rollback_patch",approval_token=token,host_id=p["host_id"]); status=Status.ROLLED_BACK; trace.add("incident.escalated","verification failed; rollback completed")
        record["payload"]["events"] += trace.events; record["payload"]["approval"]={"approver":approver,"token_id":token.split(":")[-1]}; record["payload"]["postcheck"]=health
        self.store.save(run_id,record["tenant_id"],status.value,record["autonomy"],record["payload"])
        return self.store.get(run_id)
