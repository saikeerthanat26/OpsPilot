import uuid

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

    def investigate(
        self,
        tenant_id,
        host_id,
        cve,
        agent_id="sre-investigator",
        inject_failure=False,
    ):
        """
        Execute the investigation portion through LangGraph.

        LangGraph owns orchestration.
        ToolGateway owns capability enforcement.
        DurableRunStore owns persisted workflow state.
        """

        run_id = str(uuid.uuid4())

        result = run_investigation(
            simulator=self.simulator,
            tenant_id=tenant_id,
            host_id=host_id,
            cve=cve,
            agent_id=agent_id,
            inject_failure=inject_failure,
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

        return self.store.get(run_id)

    def approve_and_execute(
        self,
        run_id,
        approver,
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

        record = self.store.get(run_id)

        if not record:
            raise KeyError("run not found")

        if (
            record["status"]
            != Status.WAITING_APPROVAL.value
        ):
            raise ValueError(
                f"run is {record['status']}, "
                "not WAITING_APPROVAL"
            )

        from simulator.infrastructure import (
            InfrastructureSimulator,
        )

        simulator = InfrastructureSimulator(
            record["payload"].get(
                "inject_failure",
                False,
            )
        )

        approval_token = (
            f"approved:{approver}:{uuid.uuid4()}"
        )

        result = run_execution(
            simulator=simulator,
            tenant_id=record["tenant_id"],
            plan=record["payload"]["plan"],
            approver=approver,
            approval_token=approval_token,
        )

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

        record["payload"]["approval"] = {
            "approver": approver,
            "token_id": (
                approval_token.split(":")[-1]
            ),
        }

        record["payload"]["postcheck"] = (
            result["postcheck"]
        )

        record["payload"][
            "execution_orchestrator"
        ] = "langgraph"

        self.store.save(
            run_id,
            record["tenant_id"],
            status.value,
            record["autonomy"],
            record["payload"],
        )

        return self.store.get(run_id)