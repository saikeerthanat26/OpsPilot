import uuid

from app.security.approvals import ApprovalStore
from app.observability.tracing import Trace
from app.storage.repositories import AuditRepository
from app.storage.simulator import DurableSimulator
from app.security.approvals import ExecutionConflict

from app.domain.models import Status
from app.platform.enterprise import (
    CapabilityRegistry,
    ModelRouter,
    DurableRunStore,
)
from app.orchestration.langgraph_workflow import (
    run_investigation,
    run_execution,
)


class EnterpriseOpsWorkflow:
    def __init__(self, simulator=None, store=None):
        self.store = store or DurableRunStore()
        self.simulator = simulator or DurableSimulator(self.store).seed()
        self.audit = AuditRepository(self.store)
        self.registry = CapabilityRegistry()
        self.router = ModelRouter()
        self.approvals = ApprovalStore(self.store)

    def investigate(
        self,
        tenant_id,
        host_id,
        cve,
        agent_id="sre-investigator",
        inject_failure=False,
        *,
        identity=None,
    ):
        """
        Execute the investigation portion through LangGraph.

        LangGraph owns orchestration.
        ToolGateway owns capability enforcement.
        DurableRunStore owns persisted workflow state.
        """

        if identity is not None and identity.tenant_id != tenant_id:
            raise PermissionError("caller tenant mismatch")
        run_id = str(uuid.uuid4())

        result = run_investigation(
            simulator=self.simulator,
            tenant_id=tenant_id,
            host_id=host_id,
            cve=cve,
            agent_id=agent_id,
            inject_failure=inject_failure,
            identity=identity,
            trace=Trace(lambda event: self.audit.append(run_id, tenant_id, event)),
            run_id=run_id,
        )

        status = (
            Status.WAITING_APPROVAL
            if result["status"] == "WAITING_APPROVAL"
            else Status.PLANNED
        )

        identity = result["identity"]

        payload = {
            "host_id": host_id,
            "cve": cve,
            "plan": result["plan"],
            "evidence": result["evidence"],
            "events": result["trace"].events,
            "model_route": result["model_route"],
            "agent": {
                "agent_id": identity.agent_id,
                "roles": list(identity.roles),
            },
            "inject_failure": inject_failure,
            "orchestrator": "langgraph",
        }

        self.store.save(
            run_id,
            tenant_id,
            status.value,
            result["autonomy"],
            payload,
        )

        return self.store.get(run_id, tenant_id)

    def _record(self, run_id, tenant_id):
        record = self.store.get(run_id, tenant_id)
        if not record: raise KeyError("run not found")
        if self.simulator.get_host(record["payload"]["host_id"])["tenant_id"] != tenant_id:
            raise PermissionError("host belongs to another tenant")
        return record

    def approve_and_execute(self, run_id, approver, *, tenant_id):
        self._record(run_id, tenant_id)
        owner = str(uuid.uuid4())
        token = self.approvals.claim(run_id, tenant_id, approver, worker_owner=owner)
        if token is None: return self.store.get(run_id, tenant_id)
        return self._execute(run_id, tenant_id, approver, token, owner)

    def recover(self, run_id, approver, *, tenant_id):
        record = self._record(run_id, tenant_id)
        if record["status"] in ("SUCCEEDED", "ROLLED_BACK"):
            return record
        owner = str(uuid.uuid4())
        # Authenticated reapproval rotates expired grants; active workers cannot be stolen.
        token = self.approvals.recover_grant(run_id, tenant_id, approver, owner)
        try:
            backend = self.simulator.for_run(run_id) if hasattr(self.simulator, "for_run") else self.simulator
            for capability, status in self.approvals.operations(run_id).items():
                if status in ("STARTED", "UNKNOWN"):
                    receipt = backend.reconcile(capability) if hasattr(backend, "reconcile") else None
                    if not receipt or receipt.get("status") != "SUCCEEDED":
                        raise ExecutionConflict("backend outcome unresolved; mutation will not be replayed")
                    self.approvals.reconcile_result(run_id, capability, receipt["result"])
            self.audit.append(run_id, tenant_id, {"ts":self.store.timestamp(), "event":"workflow.recovering", "detail":"durable checkpoint and receipts validated"})
        except Exception:
            record = self.store.get(run_id, tenant_id)
            record["payload"]["operations"] = self.approvals.operations(run_id)
            self.approvals.escalate_owned(run_id, tenant_id, record["autonomy"], record["payload"], owner)
            self.approvals.release_worker(run_id, owner)
            raise
        return self._execute(run_id, tenant_id, approver, token, owner, resume=True)

    def _events(self, record):
        items = record["payload"].get("events", []) + self.audit.list(record["run_id"], record["tenant_id"])
        import json
        unique = {json.dumps(item, sort_keys=True): item for item in items}
        return sorted(unique.values(), key=lambda e:e["ts"])

    def _execute(self, run_id, tenant_id, approver, token, owner, resume=False):
        record = self.store.get(run_id, tenant_id)
        self.simulator.fail_validation = record["payload"].get("inject_failure", False)
        trace = Trace(lambda event: self.audit.append(run_id, tenant_id, event))
        try:
            result = run_execution(simulator=self.simulator, tenant_id=tenant_id,
                plan=record["payload"]["plan"], approver=approver, approval_token=token,
                approvals=self.approvals, run_id=run_id, trace=trace, resume=resume, worker_owner=owner)
            status = result["status"]
            if status not in ("SUCCEEDED", "ROLLED_BACK", "WAITING_EXTERNAL"):
                raise RuntimeError("execution ended without a verified terminal outcome")
            record["payload"].update(
                events=self._events(record), postcheck=result["postcheck"],
                execution_result=result.get("execution_result"), execution_orchestrator="langgraph",
                operations=self.approvals.operations(run_id))
            self.approvals.complete(run_id, tenant_id, status, record["autonomy"], record["payload"], worker_owner=owner)
        except Exception:
            trace.add("incident.escalated", "execution interrupted; reconciliation required")
            record["payload"].update(events=self._events(record), operations=self.approvals.operations(run_id))
            self.approvals.escalate_owned(run_id, tenant_id, record["autonomy"], record["payload"], owner)
            raise
        finally:
            self.approvals.release_worker(run_id, owner)
        return self.store.get(run_id, tenant_id)
