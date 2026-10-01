#!/usr/bin/env python3
from __future__ import annotations

import argparse
import asyncio
import json
from typing import Any

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from re_core.adapters import ghidra_profile, ida_profile


async def probe(command: str, arguments: list[str], adapter: str) -> dict[str, Any]:
    parameters = StdioServerParameters(command=command, args=arguments)
    async with stdio_client(parameters) as (reader, writer):
        async with ClientSession(reader, writer) as session:
            initialized = await session.initialize()
            tools = await session.list_tools()
            resources = await session.list_resources()
            tool_names = sorted(item.name for item in tools.tools)
            resource_uris = sorted(str(item.uri) for item in resources.resources)
            profile = None
            if adapter == "ida":
                profile = ida_profile(
                    tool_names,
                    endpoint="",
                    discovered_resources=resource_uris,
                )
            elif adapter == "ghidra":
                profile = ghidra_profile(
                    tool_names,
                    endpoint="",
                    discovered_resources=resource_uris,
                )
            return {
                "status": "passed",
                "server_name": initialized.serverInfo.name,
                "server_version": initialized.serverInfo.version,
                "tool_count": len(tools.tools),
                "tools": tool_names,
                "resource_count": len(resources.resources),
                "resources": resource_uris,
                "adapter": (
                    {
                        "host": profile.host,
                        "coverage": profile.coverage_report(),
                        "operation_policy": profile.policy_report("read_only"),
                        "capabilities": profile.available(),
                        "unknown_tools": profile.unknown_tools(),
                        "known_resources": profile.available_resources(),
                        "unknown_resources": profile.unknown_resources(),
                    }
                    if profile is not None
                    else None
                ),
            }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Initialize a reviewed stdio MCP and list tools/resources."
    )
    parser.add_argument("--command", required=True)
    parser.add_argument("--adapter", choices=("", "ida", "ghidra"), default="")
    parser.add_argument("arguments", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    arguments = list(args.arguments)
    if arguments[:1] == ["--"]:
        arguments = arguments[1:]
    try:
        print(
            json.dumps(
                asyncio.run(probe(args.command, arguments, args.adapter)), indent=2
            )
        )
        return 0
    except (OSError, RuntimeError) as error:
        print(json.dumps({"status": "failed", "error": str(error)}, indent=2))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
