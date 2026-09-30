"""Identity and approval are trusted server context, never MCP tool arguments."""
import asyncio
import json

from mcp import types
from mcp.server import Server
from mcp.server.stdio import stdio_server
from pydantic import ValidationError

from app.mcp.contracts import CONTRACTS
from app.platform.enterprise import AgentIdentity, CapabilityRegistry, ToolGateway
from app.observability.tracing import Trace
from app.tools.infrastructure import InfrastructureTools
from simulator.infrastructure import InfrastructureSimulator


def create_server(tools, identity, trace, approval_token=None, *, approvals=None, run_id=None):
    server = Server("opspilot-infrastructure", version="0.5.0")
    registry = CapabilityRegistry()
    gateway = ToolGateway(tools, registry, trace, approvals=approvals, run_id=run_id)

    @server.list_tools()
    async def list_tools():
        return [
            types.Tool(
                name=cap["name"], description=cap["description"],
                inputSchema=CONTRACTS[cap["name"]].model_json_schema(),
                annotations=types.ToolAnnotations(
                    readOnlyHint=not cap["mutating"],
                    destructiveHint=cap["mutating"],
                    idempotentHint=not cap["mutating"], openWorldHint=False,
                ),
            )
            for cap in registry.list()
        ]

    @server.call_tool(validate_input=False)
    async def call_tool(name, arguments):
        try:
            if name not in CONTRACTS:
                raise LookupError("unknown capability")
            args = CONTRACTS[name].model_validate(arguments).model_dump()
            data = gateway.invoke(identity, name, approval_token=approval_token, **args)
            payload = {"data": data}
            return types.CallToolResult(
                content=[types.TextContent(type="text", text=json.dumps(payload))],
                structuredContent=payload,
            )
        except (ValidationError, PermissionError, LookupError) as exc:
            code = ("invalid_arguments" if isinstance(exc, ValidationError)
                    else "permission_denied" if isinstance(exc, PermissionError)
                    else "not_found")
        except Exception:
            code = "execution_failed"
        # Keep approval credentials and backend exception details out of the wire response.
        trace.add("mcp.tool.failed", f"capability={name}, code={code}")
        payload = {"error": code}
        return types.CallToolResult(
            isError=True, content=[types.TextContent(type="text", text=json.dumps(payload))],
            structuredContent=payload,
        )

    return server


async def main():
    # Standalone local server is read-only. No caller-supplied identities or approvals.
    server = create_server(
        InfrastructureTools(InfrastructureSimulator()),
        AgentIdentity("mcp-local-observer", "platform-sre", ("observer",), ("production",)),
        Trace(),
    )
    async with stdio_server() as (read, write):
        await server.run(read, write, server.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
