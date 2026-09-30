import uuid

from app.security.approvals import ApprovalStore
from app.observability.tracing import Trace

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
    def __init__(self, simulator, store=None):
        self.simulator = simulator
        self.store = store or DurableRunStore()
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

    def approve_and_execute(
        self,
        run_id,
        approver,
        *,
        tenant_id,
    ):
        """
        Resume a persisted WAITING_APPROVAL workflow.

        The execution lifecycle is now orchestrated by LangGraph:

        approval
          -> execute
          -> verify
          -> succeed

        or:

        approval
          -> execute
          -> verify
          -> rollback
          -> escalate

        Infrastructure mutations still pass through ToolGateway.
        """

        record = self.store.get(run_id, tenant_id)
        if not record:
            raise KeyError("run not found")
        plan = record["payload"]["plan"]
        if self.simulator.get_host(plan["host_id"])["tenant_id"] != tenant_id:
            raise PermissionError("host belongs to another tenant")
        approval_token = self.approvals.claim(run_id, tenant_id, approver)
        if approval_token is None:
            return self.store.get(run_id, tenant_id)
        record = self.store.get(run_id, tenant_id)
        self.simulator.fail_validation = record["payload"].get("inject_failure", False)
        execution_trace = Trace()
        try:
            result = run_execution(
                simulator=self.simulator,
                tenant_id=tenant_id,
                plan=plan,
                approver=approver,
                approval_token=approval_token,
                approvals=self.approvals,
                run_id=run_id,
                trace=execution_trace,
            )
        except Exception:
            # Do not resume/retry a possibly completed mutation after transport failure.
            record["payload"]["operations"] = self.approvals.operations(run_id)
            record["payload"]["events"] += execution_trace.events
            record["payload"]["events"].append({
                "ts": self.store.timestamp(), "event": "incident.escalated",
                "detail": "execution interrupted; reconciliation required",
            })
            self.store.save(run_id, tenant_id, Status.ESCALATED.value, record["autonomy"], record["payload"])
            raise

        if result["status"] == "SUCCEEDED":
            status = Status.SUCCEEDED

        elif result["status"] == "ROLLED_BACK":
            status = Status.ROLLED_BACK

        else:
            raise RuntimeError(
                "execution graph ended in "
                f"unexpected state: {result['status']}"
            )

        # Preserve the original investigation event history
        # and append the execution graph history.
        record["payload"]["events"] += (
            result["trace"].events
        )

        record["payload"]["postcheck"] = (
            result["postcheck"]
        )

        record["payload"][
            "execution_orchestrator"
        ] = "langgraph"

        record["payload"]["operations"] = self.approvals.operations(run_id)
        self.approvals.complete(
            run_id,
            record["tenant_id"],
            status.value,
            record["autonomy"],
            record["payload"],
        )

        return self.store.get(run_id, tenant_id)
