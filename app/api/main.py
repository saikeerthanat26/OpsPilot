from fastapi import Depends, FastAPI, HTTPException
from pydantic import BaseModel, ConfigDict, Field
from app.orchestration.workflow import OpsPilotWorkflow
from app.orchestration.enterprise_workflow import EnterpriseOpsWorkflow
from app.platform.enterprise import CapabilityRegistry, DurableRunStore
from simulator.infrastructure import InfrastructureSimulator
from app.security.identity import Principal, authenticated_principal
from app.mcp.client import MCPToolError
from app.tools.providers import configured_backend
from app.orchestration.langgraph_workflow import build_execution_graph
from app.security.approvals import ExecutionConflict

app=FastAPI(title="OpsPilot Enterprise Agentic SRE Control Plane",version="0.7.0",description="Policy-governed agentic SRE platform with durable workflows, agent identity and a capability gateway.")
store=DurableRunStore()

class IncidentRequest(BaseModel):
    host_id:str="prod-api-01"; cve:str="CVE-DEMO-2026-001"; approved:bool=False; inject_failure:bool=False
class EnterpriseIncidentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    tenant_id:str=Field(default="platform-sre",description="Owning team/tenant")
    host_id:str="prod-api-01"; cve:str="CVE-DEMO-2026-001"; inject_failure:bool=False
class ApprovalRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

@app.get("/")
def root(): return {"service":"OpsPilot","version":"0.7.0","purpose":"Enterprise Agentic SRE Control Plane","docs":"/docs"}
@app.get("/health")
def health(): return {"status":"ok","version":"0.7.0"}
@app.get("/ready")
def ready():
    try:
        with store._connect() as conn: conn.execute("SELECT 1")
    except Exception: raise HTTPException(503,"control-plane database unavailable") from None
    return {"status":"ready","durable_store":store.database.engine.dialect.name}
@app.get("/v1/capabilities")
def capabilities(): return {"capabilities":CapabilityRegistry().list()}

# Backward-compatible V0.1 demo endpoint
@app.post("/v1/incidents/investigate")
def investigate(req:IncidentRequest):
    r=OpsPilotWorkflow(InfrastructureSimulator(req.inject_failure)).run(req.host_id,req.cve,req.approved)
    return {"run_id":r.run_id,"status":r.status.value,"autonomy":r.autonomy.value,"message":r.message,"evidence":[e.__dict__ for e in r.evidence],"events":r.events}

@app.post("/v2/incidents",status_code=202)
def create_incident(req:EnterpriseIncidentRequest, principal:Principal=Depends(authenticated_principal)):
    if req.tenant_id != principal.identity.tenant_id:
        raise HTTPException(403, "tenant mismatch")
    try:
        return EnterpriseOpsWorkflow(configured_backend(store),store).investigate(
            req.tenant_id, req.host_id, req.cve, principal.subject, req.inject_failure,
            identity=principal.identity,
        )
    except MCPToolError:
        raise HTTPException(403, "capability access denied") from None

@app.get("/v2/runs/{run_id}")
def get_run(run_id:str, principal:Principal=Depends(authenticated_principal)):
    record=store.get(run_id, principal.identity.tenant_id)
    if not record: raise HTTPException(404,"run not found")
    environment = "production" if record["payload"]["plan"]["production"] else "nonproduction"
    if environment not in principal.identity.environment_scopes:
        raise HTTPException(403, "environment scope required")
    return record

@app.post("/v2/runs/{run_id}/approve")
def approve(run_id:str, req:ApprovalRequest, principal:Principal=Depends(authenticated_principal)):
    if "approver" not in principal.identity.roles:
        raise HTTPException(403, "approver role required")
    record = store.get(run_id, principal.identity.tenant_id)
    if not record: raise HTTPException(404, "run not found")
    environment = "production" if record["payload"]["plan"]["production"] else "nonproduction"
    if environment not in principal.identity.environment_scopes:
        raise HTTPException(403, "environment scope required")
    try:
        return EnterpriseOpsWorkflow(configured_backend(store),store).approve_and_execute(
            run_id, principal.subject, tenant_id=principal.identity.tenant_id,
        )
    except KeyError: raise HTTPException(404,"run not found")
    except ValueError as exc: raise HTTPException(409,str(exc))
    except (PermissionError, MCPToolError):
        raise HTTPException(409, "execution blocked; inspect run for reconciliation") from None

@app.get("/v2/runs/{run_id}/events")
def events(run_id:str, principal:Principal=Depends(authenticated_principal)):
    record = get_run(run_id, principal)
    return {"run_id":run_id,"events":EnterpriseOpsWorkflow(configured_backend(store),store)._events(record)}


@app.post("/v2/runs/{run_id}/recover")
def recover(run_id:str, req:ApprovalRequest, principal:Principal=Depends(authenticated_principal)):
    if "approver" not in principal.identity.roles: raise HTTPException(403,"approver role required")
    get_run(run_id,principal)
    try:
        return EnterpriseOpsWorkflow(configured_backend(store),store).recover(run_id,principal.subject,tenant_id=principal.identity.tenant_id)
    except KeyError: raise HTTPException(404,"run not found")
    except (ExecutionConflict, PermissionError, MCPToolError):
        raise HTTPException(409,"recovery blocked; backend outcome or worker lease needs reconciliation") from None


@app.get("/v2/runs/{run_id}/checkpoint")
def checkpoint(run_id:str, principal:Principal=Depends(authenticated_principal)):
    get_run(run_id,principal)
    with store.database.checkpointer() as saver:
        snapshot=build_execution_graph(checkpointer=saver).get_state({"configurable":{"thread_id":run_id}})
    if not snapshot.values: return {"run_id":run_id,"checkpoint":None}
    return {"run_id":run_id,"checkpoint_id":snapshot.config["configurable"]["checkpoint_id"],
            "status":snapshot.values.get("status"),"pending_nodes":list(snapshot.next)}
