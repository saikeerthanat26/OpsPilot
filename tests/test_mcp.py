import asyncio
import sys

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.shared.memory import create_connected_server_and_client_session

from app.mcp.client import MCPToolError, MCPToolGateway
from app.mcp.server import create_server
from app.observability.tracing import Trace
from app.platform.enterprise import AgentIdentity, CapabilityRegistry
from app.tools.infrastructure import InfrastructureTools
from simulator.infrastructure import InfrastructureSimulator


def identity(roles=("observer", "operator"), scopes=("production",)):
    return AgentIdentity("sre-executor", "platform-sre", roles, scopes)


def gateway(sim, trace=None):
    return MCPToolGateway(InfrastructureTools(sim), CapabilityRegistry(), trace or Trace())


def test_discovery_and_wire_contracts():
    async def check():
        server = create_server(InfrastructureTools(InfrastructureSimulator()), identity(), Trace())
        async with create_connected_server_and_client_session(server) as session:
            tools = (await session.list_tools()).tools
            assert {t.name for t in tools} == {c["name"] for c in CapabilityRegistry().list()}
            patch = next(t for t in tools if t.name == "execute_approved_patch")
            assert patch.inputSchema["additionalProperties"] is False
            assert set(patch.inputSchema["required"]) == {"host_id", "to_version"}
            assert patch.annotations.readOnlyHint is False
            for args in ({}, {"host_id": 42}, {"host_id": ""},
                         {"host_id": "prod-api-01", "approval_token": "forged"},
                         {"host_id": "prod-api-01", "identity": {"roles": ["admin"]}}):
                result = await session.call_tool("get_host_health", args)
                assert result.isError
                assert result.structuredContent == {"error": "invalid_arguments"}
            unknown = await session.call_tool("shell", {"command": "rm -rf /"})
            assert unknown.isError
    asyncio.run(check())


@pytest.mark.parametrize("agent,token", [
    (identity(), None),
    (identity(("observer",)), "approved:test"),
    (identity(scopes=("nonproduction",)), "approved:test"),
])
def test_server_denies_mutation_without_authority(agent, token):
    sim = InfrastructureSimulator()
    with pytest.raises(MCPToolError, match="permission_denied"):
        gateway(sim).invoke(agent, "execute_approved_patch", approval_token=token,
                            host_id="prod-api-01", to_version="3.1.4")
    assert sim.get_host("prod-api-01")["version"] == "3.1.2"
    assert not sim.snapshots


def test_mcp_execution_verification_and_rollback_share_state():
    sim = InfrastructureSimulator(fail_validation=True)
    trace = Trace()
    client, token = approved_gateway(sim, trace)
    client.invoke(identity(), "execute_approved_patch", approval_token=token,
                  host_id="prod-api-01", to_version="3.1.4")
    assert sim.get_host("prod-api-01")["version"] == "3.1.4"
    assert client.invoke(identity(), "verify_host_health", host_id="prod-api-01")["healthy"] is False
    with pytest.raises(MCPToolError):
        client.invoke(identity(), "rollback_patch", host_id="prod-api-01")
    client.invoke(identity(), "rollback_patch", approval_token=token, host_id="prod-api-01")
    assert sim.get_host("prod-api-01")["version"] == "3.1.2"
    assert any(e["event"] == "mcp.call.completed" for e in trace.events)
    assert token not in str(trace.events)


def test_unknown_host_error_is_sanitized():
    with pytest.raises(MCPToolError, match="not_found"):
        gateway(InfrastructureSimulator()).invoke(identity(), "get_host_health", host_id="missing")


def test_standalone_stdio_server_is_read_only():
    async def check():
        async with asyncio.timeout(15):
            async with stdio_client(StdioServerParameters(
                command=sys.executable, args=["-m", "app.mcp.server"]
            )) as (read, write):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    assert len((await session.list_tools()).tools) == 6
                    health = await session.call_tool("get_host_health", {"host_id": "prod-api-01"})
                    assert health.structuredContent["data"]["environment"] == "production"
                    denied = await session.call_tool("execute_approved_patch", {
                        "host_id": "prod-api-01", "to_version": "3.1.4"
                    })
                    assert denied.isError
    asyncio.run(check())


def test_timeout_is_audited_and_never_retried(monkeypatch):
    from contextlib import asynccontextmanager
    import app.mcp.client as client_module

    calls = []

    class SlowSession:
        async def call_tool(self, name, arguments):
            calls.append(name)
            await asyncio.sleep(1)

    @asynccontextmanager
    async def slow_connection(*args, **kwargs):
        yield SlowSession()

    monkeypatch.setattr(client_module, "create_connected_server_and_client_session", slow_connection)
    sim = InfrastructureSimulator()
    trace = Trace()
    client = MCPToolGateway(InfrastructureTools(sim), CapabilityRegistry(), trace, timeout_seconds=0.01)
    with pytest.raises(TimeoutError):
        client.invoke(identity(), "execute_approved_patch", approval_token="approved:test",
                      host_id="prod-api-01", to_version="3.1.4")
    assert calls == ["execute_approved_patch"]
    assert any(e["event"] == "mcp.call.failed" for e in trace.events)
    assert not sim.snapshots


def test_backend_failure_does_not_leak_credentials():
    class BrokenTools(InfrastructureTools):
        def execute_approved_patch(self, host_id, to_version, approval_token):
            raise RuntimeError(f"backend secret: {approval_token}")

    trace = Trace()
    client, token = approved_gateway(InfrastructureSimulator(), trace, BrokenTools)
    with pytest.raises(MCPToolError, match="execution_failed") as error:
        client.invoke(identity(), "execute_approved_patch", approval_token=token,
                      host_id="prod-api-01", to_version="3.1.4")
    assert token not in str(error.value)
    assert token not in str(trace.events)


def approved_gateway(sim, trace, tools_class=InfrastructureTools):
    import tempfile
    from app.platform.enterprise import DurableRunStore
    from app.orchestration.enterprise_workflow import EnterpriseOpsWorkflow
    from app.security.approvals import ApprovalStore
    store = DurableRunStore(tempfile.mktemp(suffix=".db"))
    workflow = EnterpriseOpsWorkflow(sim, store)
    record = workflow.investigate("platform-sre", "prod-api-01", "CVE-DEMO-2026-001")
    approvals = ApprovalStore(store)
    token = approvals.claim(record["run_id"], "platform-sre", "alice")
    return MCPToolGateway(tools_class(sim), CapabilityRegistry(), trace,
                          approvals=approvals, run_id=record["run_id"]), token
