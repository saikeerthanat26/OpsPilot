"""Synchronous LangGraph adapter over real MCP sessions using memory transport.

The simulator stays shared across calls. Transport can later move to a persistent
remote session once authenticated identity/approval propagation is implemented.
"""
import asyncio
from datetime import timedelta

from mcp.shared.memory import create_connected_server_and_client_session

from app.mcp.server import create_server


class MCPToolError(RuntimeError):
    pass


class MCPToolGateway:
    def __init__(self, tools, registry, trace, timeout_seconds=180, *, approvals=None, run_id=None):
        self.tools, self.registry, self.trace = tools, registry, trace
        self.timeout_seconds = timeout_seconds
        self.approvals, self.run_id = approvals, run_id

    async def invoke_async(self, identity, capability, *, approval_token=None, **arguments):
        server = create_server(self.tools, identity, self.trace, approval_token, approvals=self.approvals, run_id=self.run_id)
        self.trace.add("mcp.call.started", f"capability={capability}")
        try:
            async with asyncio.timeout(self.timeout_seconds):
                async with create_connected_server_and_client_session(
                    server, read_timeout_seconds=timedelta(seconds=self.timeout_seconds)
                ) as session:
                    result = await session.call_tool(capability, arguments)
            payload = result.structuredContent
            if result.isError:
                raise MCPToolError(f"MCP tool {capability} failed: {(payload or {}).get('error', 'tool_error')}")
            if not isinstance(payload, dict) or "data" not in payload:
                raise MCPToolError("invalid MCP tool response")
        except Exception:
            self.trace.add("mcp.call.failed", f"capability={capability}")
            # No automatic mutation retries: a timeout may have an unknown outcome.
            raise
        self.trace.add("mcp.call.completed", f"capability={capability}")
        return payload["data"]

    def invoke(self, identity, capability, *, approval_token=None, **arguments):
        return asyncio.run(self.invoke_async(
            identity, capability, approval_token=approval_token, **arguments
        ))


class PlanningTools:
    """Only the two read capabilities needed by the deterministic planner."""
    def __init__(self, gateway, identity):
        self.gateway, self.identity = gateway, identity

    def get_host_health(self, host_id):
        return self.gateway.invoke(self.identity, "get_host_health", host_id=host_id)

    def get_patch_metadata(self, host_id):
        return self.gateway.invoke(self.identity, "get_patch_metadata", host_id=host_id)
