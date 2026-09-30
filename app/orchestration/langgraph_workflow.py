from __future__ import annotations

from typing import Any, TypedDict
from dataclasses import asdict

from langgraph.graph import END, START, StateGraph

from app.agents.planner import RemediationPlanner
from app.domain.models import Evidence
from app.observability.tracing import Trace
from app.platform.enterprise import (
    AgentIdentity,
    CapabilityRegistry,
    ModelRouter,
)
from app.mcp.client import MCPToolGateway, PlanningTools
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
    approvals: Any
    run_id: str
    trusted_identity: Any
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

    identity = state.get("trusted_identity") or AgentIdentity(
        state.get("agent_id", "sre-investigator"),
        state["tenant_id"],
        ("observer",),
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

    backend = state["simulator"]
    tools = InfrastructureTools(backend.for_run(state.get("run_id")) if hasattr(backend, "for_run") else backend)

    gateway = MCPToolGateway(
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

    backend = state["simulator"]
    tools = InfrastructureTools(backend.for_run(state.get("run_id")) if hasattr(backend, "for_run") else backend)

    gateway = MCPToolGateway(tools, CapabilityRegistry(), trace)
    plan = RemediationPlanner(PlanningTools(gateway, state["identity"])).plan(
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

    backend = state["simulator"]
    tools = InfrastructureTools(backend.for_run(state.get("run_id")) if hasattr(backend, "for_run") else backend)

    gateway = MCPToolGateway(
        tools,
        CapabilityRegistry(),
        state["trace"],
        approvals=state.get("approvals"), run_id=state.get("run_id"),
    )

    plan = state["plan"]
    if state["approvals"].operations(state["run_id"]).get("execute_approved_patch") == "SUCCEEDED":
        state["trace"].add("execution.reused", "durable patch result; mutation not replayed")
        return {"execution_result": state["approvals"].result(state["run_id"], "execute_approved_patch"), "status": "EXECUTED"}

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

    backend = state["simulator"]
    tools = InfrastructureTools(backend.for_run(state.get("run_id")) if hasattr(backend, "for_run") else backend)

    gateway = MCPToolGateway(
        tools,
        CapabilityRegistry(),
        state["trace"],
        approvals=state.get("approvals"), run_id=state.get("run_id"),
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

    if state["postcheck"].get("pending_external"):
        return "wait_external"
    if state["postcheck"]["healthy"]:
        return "succeed"

    return "rollback"


def wait_external(state):
    state["trace"].add("external.review.required", "change request created; remediation awaits human review/merge")
    return {"status":"WAITING_EXTERNAL"}


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

    backend = state["simulator"]
    tools = InfrastructureTools(backend.for_run(state.get("run_id")) if hasattr(backend, "for_run") else backend)

    gateway = MCPToolGateway(
        tools,
        CapabilityRegistry(),
        state["trace"],
        approvals=state.get("approvals"), run_id=state.get("run_id"),
    )

    if state["approvals"].operations(state["run_id"]).get("rollback_patch") == "SUCCEEDED":
        return {"rollback_result": state["approvals"].result(state["run_id"], "rollback_patch"), "status": "ROLLING_BACK"}
    if not state["plan"].get("rollback_available", True):
        raise PermissionError("backend requires separate recovery authorization; no automatic rollback")
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

def build_execution_graph(runtime=None, checkpointer=None):
    def bind(fn):
        if runtime is None: return fn
        def node(state):
            if runtime.get("worker_owner"):
                runtime["approvals"].renew_worker(runtime["run_id"], runtime["worker_owner"])
            ephemeral = {**state, **runtime}
            if isinstance(ephemeral.get("executor_identity"), dict):
                ephemeral["executor_identity"] = AgentIdentity(**ephemeral["executor_identity"])
            result = fn(ephemeral)
            if isinstance(result.get("executor_identity"), AgentIdentity):
                result["executor_identity"] = asdict(result["executor_identity"])
            return result
        return node

    graph = StateGraph(OpsPilotState)

    graph.add_node(
        "grant_approval",
        bind(grant_approval),
    )
    graph.add_node(
        "execute_patch",
        bind(execute_patch),
    )
    graph.add_node(
        "verify_health",
        bind(verify_health),
    )
    graph.add_node("wait_external", bind(wait_external))
    graph.add_node(
        "succeed",
        bind(succeed),
    )
    graph.add_node(
        "rollback",
        bind(rollback),
    )
    graph.add_node(
        "escalate",
        bind(escalate),
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
            "wait_external": "wait_external",
            "rollback": "rollback",
        },
    )

    graph.add_edge("wait_external", END)
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

    return graph.compile(checkpointer=checkpointer)


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
    identity=None,
    trace=None,
    run_id=None,
):

    trace = trace or Trace()

    initial_state: OpsPilotState = {
        "tenant_id": tenant_id,
        "host_id": host_id,
        "cve": cve,
        "agent_id": agent_id,
        "trusted_identity": identity,
        "run_id": run_id,
        "inject_failure": inject_failure,
        "simulator": simulator,
        "trace": trace,
    }

    return investigation_graph.invoke(
        initial_state
    )


def run_execution(*, simulator, tenant_id, plan, approver, approval_token,
                  approvals, run_id, trace=None, resume=False, worker_owner=None):
    trace = trace or Trace()
    # Runtime objects and approval credentials never enter persisted graph state.
    runtime = {"simulator": simulator, "trace": trace, "approvals": approvals,
               "approval_token": approval_token, "run_id": run_id, "worker_owner": worker_owner}
    initial = {"tenant_id": tenant_id, "plan": plan, "approver": approver,
               "approved": True, "run_id": run_id}
    config = {"configurable": {"thread_id": run_id}}
    with approvals.runs.database.checkpointer() as saver:
        graph = build_execution_graph(runtime, saver)
        snapshot = graph.get_state(config)
        if resume and snapshot.values:
            if snapshot.values.get("status")=="WAITING_EXTERNAL":
                graph.update_state(config, {"status":"EXECUTED"}, as_node="execute_patch")
                snapshot=graph.get_state(config)
            result = graph.invoke(None, config) if snapshot.next else snapshot.values
        else:
            result = graph.invoke(initial, config)
    return {**result, "trace": trace}
