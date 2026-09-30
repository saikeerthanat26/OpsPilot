from __future__ import annotations

from typing import Any, TypedDict

from langgraph.graph import END, START, StateGraph

from app.agents.planner import RemediationPlanner
from app.domain.models import Evidence
from app.observability.tracing import Trace
from app.platform.enterprise import (
    AgentIdentity,
    CapabilityRegistry,
    ModelRouter,
    ToolGateway,
)
from app.policy.engine import PolicyEngine
from app.retrieval.knowledge import KnowledgeService
from app.tools.infrastructure import InfrastructureTools


class OpsPilotState(TypedDict, total=False):
    # Request context
    tenant_id: str
    host_id: str
    cve: str
    agent_id: str
    inject_failure: bool

    # Runtime dependencies
    simulator: Any
    trace: Any

    # Investigation context
    identity: Any
    model_route: dict[str, Any]
    health: dict[str, Any]
    vulnerabilities: list[str]
    evidence: list[dict[str, Any]]

    # Planning
    domain_plan: Any
    plan: dict[str, Any]

    # Policy / approval
    autonomy: str
    approved: bool
    approver: str
    approval_token: str

    # Execution
    executor_identity: Any
    execution_result: Any
    postcheck: dict[str, Any]
    rollback_result: Any

    # Workflow state
    status: str


# ============================================================
# INVESTIGATION NODES
# ============================================================

def investigate(state: OpsPilotState) -> dict:
    trace = state["trace"]

    identity = AgentIdentity(
        state.get("agent_id", "sre-investigator"),
        state["tenant_id"],
        ("observer", "operator"),
        ("production", "nonproduction"),
    )

    trace.add(
        "workflow.started",
        (
            f"tenant={state['tenant_id']}, "
            f"host={state['host_id']}, "
            f"cve={state['cve']}"
        ),
    )

    return {
        "identity": identity,
        "status": "INVESTIGATING",
    }


def route_model(state: OpsPilotState) -> dict:
    trace = state["trace"]

    route = ModelRouter().route(
        "incident_reasoning",
        "internal",
    )

    trace.add(
        "model.routed",
        (
            f"provider={route['provider']}, "
            f"model={route['model']}"
        ),
    )

    return {
        "model_route": route,
        "status": "MODEL_ROUTED",
    }


def gather_evidence(state: OpsPilotState) -> dict:
    trace = state["trace"]

    tools = InfrastructureTools(
        state["simulator"]
    )

    gateway = ToolGateway(
        tools,
        CapabilityRegistry(),
        trace,
    )

    health = gateway.invoke(
        state["identity"],
        "get_host_health",
        host_id=state["host_id"],
    )

    vulnerabilities = gateway.invoke(
        state["identity"],
        "list_vulnerabilities",
        host_id=state["host_id"],
    )

    evidence = [
        Evidence(
            "metrics",
            key,
            value,
        ).__dict__
        for key, value in health.items()
    ]

    evidence.extend(
        [
            Evidence(
                "vulnerability",
                "requested_cve_present",
                state["cve"] in vulnerabilities,
            ).__dict__,
            Evidence(
                "vulnerability",
                "active",
                vulnerabilities,
            ).__dict__,
        ]
    )

    docs = KnowledgeService().retrieve(
        "openssl critical patch"
    )

    evidence.extend(
        [
            Evidence(
                "runbook",
                doc["id"],
                doc["text"],
            ).__dict__
            for doc in docs
        ]
    )

    trace.add(
        "evidence.package.created",
        f"items={len(evidence)}",
    )

    return {
        "health": health,
        "vulnerabilities": vulnerabilities,
        "evidence": evidence,
        "status": "EVIDENCE_COLLECTED",
    }


def create_plan(state: OpsPilotState) -> dict:
    trace = state["trace"]

    tools = InfrastructureTools(
        state["simulator"]
    )

    plan = RemediationPlanner(tools).plan(
        state["host_id"],
        state["cve"],
    )

    trace.add(
        "plan.created",
        (
            f"plan={plan.plan_id}, "
            f"blast_radius={plan.blast_radius}"
        ),
    )

    return {
        "domain_plan": plan,
        "plan": plan.__dict__,
        "status": "PLANNED",
    }


def evaluate_policy(state: OpsPilotState) -> dict:
    trace = state["trace"]

    plan = state["domain_plan"]

    level, _ = PolicyEngine().authorize(
        plan,
        False,
    )

    trace.add(
        "policy.evaluated",
        (
            f"autonomy={level.value}, "
            f"production={plan.production}"
        ),
    )

    return {
        "autonomy": level.value,
        "status": (
            "WAITING_APPROVAL"
            if level.value == "L2_APPROVAL_REQUIRED"
            else "PLANNED"
        ),
    }


def route_after_policy(
    state: OpsPilotState,
) -> str:

    if (
        state["autonomy"]
        == "L2_APPROVAL_REQUIRED"
    ):
        return "wait_for_approval"

    return "ready"


def wait_for_approval(
    state: OpsPilotState,
) -> dict:

    state["trace"].add(
        "approval.required",
        "production mutation blocked at tool gateway",
    )

    return {
        "status": "WAITING_APPROVAL",
    }


def ready(
    state: OpsPilotState,
) -> dict:

    return {
        "status": "PLANNED",
    }


# ============================================================
# EXECUTION NODES
# ============================================================

def grant_approval(
    state: OpsPilotState,
) -> dict:
    """
    Establish the separate executor identity.

    The approval token itself is created by EnterpriseOpsWorkflow
    before invoking this graph so the persisted workflow owns the
    approval record.
    """

    trace = state["trace"]

    identity = AgentIdentity(
        "sre-executor",
        state["tenant_id"],
        ("observer", "operator"),
        ("production",),
    )

    trace.add(
        "approval.granted",
        f"approver={state['approver']}",
    )

    return {
        "executor_identity": identity,
        "approved": True,
        "status": "APPROVED",
    }


def execute_patch(
    state: OpsPilotState,
) -> dict:
    """
    LangGraph decides that execution is the next state.

    ToolGateway remains responsible for capability and
    approval enforcement.
    """

    tools = InfrastructureTools(
        state["simulator"]
    )

    gateway = ToolGateway(
        tools,
        CapabilityRegistry(),
        state["trace"],
    )

    plan = state["plan"]

    result = gateway.invoke(
        state["executor_identity"],
        "execute_approved_patch",
        approval_token=state["approval_token"],
        host_id=plan["host_id"],
        to_version=plan["to_version"],
    )

    return {
        "execution_result": result,
        "status": "EXECUTED",
    }


def verify_health(
    state: OpsPilotState,
) -> dict:

    tools = InfrastructureTools(
        state["simulator"]
    )

    gateway = ToolGateway(
        tools,
        CapabilityRegistry(),
        state["trace"],
    )

    health = gateway.invoke(
        state["executor_identity"],
        "verify_host_health",
        host_id=state["plan"]["host_id"],
    )

    return {
        "postcheck": health,
        "status": "VERIFYING",
    }


def route_after_verification(
    state: OpsPilotState,
) -> str:

    if state["postcheck"]["healthy"]:
        return "succeed"

    return "rollback"


def succeed(
    state: OpsPilotState,
) -> dict:

    state["trace"].add(
        "workflow.succeeded",
        "post-change verification passed",
    )

    return {
        "status": "SUCCEEDED",
    }


def rollback(
    state: OpsPilotState,
) -> dict:

    tools = InfrastructureTools(
        state["simulator"]
    )

    gateway = ToolGateway(
        tools,
        CapabilityRegistry(),
        state["trace"],
    )

    result = gateway.invoke(
        state["executor_identity"],
        "rollback_patch",
        approval_token=state["approval_token"],
        host_id=state["plan"]["host_id"],
    )

    return {
        "rollback_result": result,
        "status": "ROLLING_BACK",
    }


def escalate(
    state: OpsPilotState,
) -> dict:

    state["trace"].add(
        "incident.escalated",
        "verification failed; rollback completed",
    )

    return {
        "status": "ROLLED_BACK",
    }


# ============================================================
# INVESTIGATION GRAPH
# ============================================================

def build_investigation_graph():
    graph = StateGraph(OpsPilotState)

    graph.add_node("investigate", investigate)
    graph.add_node("route_model", route_model)
    graph.add_node(
        "gather_evidence",
        gather_evidence,
    )
    graph.add_node(
        "create_plan",
        create_plan,
    )
    graph.add_node(
        "evaluate_policy",
        evaluate_policy,
    )
    graph.add_node(
        "wait_for_approval",
        wait_for_approval,
    )
    graph.add_node("ready", ready)

    graph.add_edge(
        START,
        "investigate",
    )
    graph.add_edge(
        "investigate",
        "route_model",
    )
    graph.add_edge(
        "route_model",
        "gather_evidence",
    )
    graph.add_edge(
        "gather_evidence",
        "create_plan",
    )
    graph.add_edge(
        "create_plan",
        "evaluate_policy",
    )

    graph.add_conditional_edges(
        "evaluate_policy",
        route_after_policy,
        {
            "wait_for_approval":
                "wait_for_approval",
            "ready":
                "ready",
        },
    )

    graph.add_edge(
        "wait_for_approval",
        END,
    )
    graph.add_edge(
        "ready",
        END,
    )

    return graph.compile()


# ============================================================
# EXECUTION / RESUME GRAPH
# ============================================================

def build_execution_graph():
    graph = StateGraph(OpsPilotState)

    graph.add_node(
        "grant_approval",
        grant_approval,
    )
    graph.add_node(
        "execute_patch",
        execute_patch,
    )
    graph.add_node(
        "verify_health",
        verify_health,
    )
    graph.add_node(
        "succeed",
        succeed,
    )
    graph.add_node(
        "rollback",
        rollback,
    )
    graph.add_node(
        "escalate",
        escalate,
    )

    graph.add_edge(
        START,
        "grant_approval",
    )

    graph.add_edge(
        "grant_approval",
        "execute_patch",
    )

    graph.add_edge(
        "execute_patch",
        "verify_health",
    )

    graph.add_conditional_edges(
        "verify_health",
        route_after_verification,
        {
            "succeed": "succeed",
            "rollback": "rollback",
        },
    )

    graph.add_edge(
        "succeed",
        END,
    )

    graph.add_edge(
        "rollback",
        "escalate",
    )

    graph.add_edge(
        "escalate",
        END,
    )

    return graph.compile()


investigation_graph = (
    build_investigation_graph()
)

execution_graph = (
    build_execution_graph()
)


# ============================================================
# PUBLIC ENTRY POINTS
# ============================================================

def run_investigation(
    *,
    simulator,
    tenant_id: str,
    host_id: str,
    cve: str,
    agent_id: str = "sre-investigator",
    inject_failure: bool = False,
):

    trace = Trace()

    initial_state: OpsPilotState = {
        "tenant_id": tenant_id,
        "host_id": host_id,
        "cve": cve,
        "agent_id": agent_id,
        "inject_failure": inject_failure,
        "simulator": simulator,
        "trace": trace,
    }

    return investigation_graph.invoke(
        initial_state
    )


def run_execution(
    *,
    simulator,
    tenant_id: str,
    plan: dict[str, Any],
    approver: str,
    approval_token: str,
):

    trace = Trace()

    initial_state: OpsPilotState = {
        "tenant_id": tenant_id,
        "plan": plan,
        "approver": approver,
        "approval_token": approval_token,
        "approved": True,
        "simulator": simulator,
        "trace": trace,
    }

    return execution_graph.invoke(
        initial_state
    )