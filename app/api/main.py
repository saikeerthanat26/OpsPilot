from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from app.orchestration.workflow import OpsPilotWorkflow
from app.orchestration.enterprise_workflow import EnterpriseOpsWorkflow
from app.platform.enterprise import CapabilityRegistry, DurableRunStore
from simulator.infrastructure import InfrastructureSimulator

app=FastAPI(title="OpsPilot Enterprise Agentic SRE Control Plane",version="0.2.0",description="Policy-governed agentic SRE platform with durable workflows, agent identity and a capability gateway.")
store=DurableRunStore()

class IncidentRequest(BaseModel):
    host_id:str="prod-api-01"; cve:str="CVE-DEMO-2026-001"; approved:bool=False; inject_failure:bool=False
class EnterpriseIncidentRequest(BaseModel):
    tenant_id:str=Field(default="platform-sre",description="Owning team/tenant")
    host_id:str="prod-api-01"; cve:str="CVE-DEMO-2026-001"; agent_id:str="sre-investigator"; inject_failure:bool=False
class ApprovalRequest(BaseModel): approver:str="oncall-sre@example.com"

@app.get("/")
def root(): return {"service":"OpsPilot","version":"0.2.0","purpose":"Enterprise Agentic SRE Control Plane","docs":"/docs"}
@app.get("/health")
def health(): return {"status":"ok","version":"0.2.0"}
@app.get("/ready")
def ready(): return {"status":"ready","durable_store":"sqlite"}
@app.get("/v1/capabilities")
def capabilities(): return {"capabilities":CapabilityRegistry().list()}

# Backward-compatible V0.1 demo endpoint
@app.post("/v1/incidents/investigate")
def investigate(req:IncidentRequest):
    r=OpsPilotWorkflow(InfrastructureSimulator(req.inject_failure)).run(req.host_id,req.cve,req.approved)
    return {"run_id":r.run_id,"status":r.status.value,"autonomy":r.autonomy.value,"message":r.message,"evidence":[e.__dict__ for e in r.evidence],"events":r.events}

@app.post("/v2/incidents",status_code=202)
def create_incident(req:EnterpriseIncidentRequest):
    return EnterpriseOpsWorkflow(InfrastructureSimulator(req.inject_failure),store).investigate(req.tenant_id,req.host_id,req.cve,req.agent_id,req.inject_failure)
@app.get("/v2/runs/{run_id}")
def get_run(run_id:str):
    r=store.get(run_id)
    if not r: raise HTTPException(404,"run not found")
    return r
@app.post("/v2/runs/{run_id}/approve")
def approve(run_id:str,req:ApprovalRequest):
    try: return EnterpriseOpsWorkflow(InfrastructureSimulator(),store).approve_and_execute(run_id,req.approver)
    except KeyError: raise HTTPException(404,"run not found")
    except ValueError as e: raise HTTPException(409,str(e))
@app.get("/v2/runs/{run_id}/events")
def events(run_id:str):
    r=store.get(run_id)
    if not r: raise HTTPException(404,"run not found")
    return {"run_id":run_id,"events":r["payload"].get("events",[])}
