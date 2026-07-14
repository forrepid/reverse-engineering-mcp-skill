#!/usr/bin/env python3
from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path
from typing import Any

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


def _result_text(result: Any) -> str:
    return "\n".join(
        str(text)
        for item in result.content
        if (text := getattr(item, "text", None)) is not None
    )


async def verify(
    bridge: Path,
    ghidra_server: str,
    expected_program: str | None,
) -> dict[str, Any]:
    parameters = StdioServerParameters(
        command=sys.executable,
        args=[str(bridge), "--ghidra-server", ghidra_server],
    )
    async with stdio_client(parameters) as (reader, writer):
        async with ClientSession(reader, writer) as session:
            initialized = await session.initialize()
            tools = await session.list_tools()
            tool_names = sorted(item.name for item in tools.tools)
            required = {"ghidra_health", "list_functions", "get_current_function"}
            missing = sorted(required - set(tool_names))
            if missing:
                raise RuntimeError("required Ghidra MCP tools missing: " + ", ".join(missing))

            health = await session.call_tool("ghidra_health", {})
            functions = await session.call_tool("list_functions", {})
            current = await session.call_tool("get_current_function", {})
            health_text = _result_text(health)
            functions_text = _result_text(functions)
            current_text = _result_text(current)

            if health.isError or "status=ok" not in health_text:
                raise RuntimeError(f"Ghidra health check failed: {health_text!r}")
            if expected_program and f"program={expected_program}" not in health_text:
                raise RuntimeError(
                    f"active Program mismatch; expected {expected_program!r}: {health_text!r}"
                )
            if functions.isError or not functions_text.strip():
                raise RuntimeError("Ghidra function listing returned no data")
            if current.isError:
                raise RuntimeError(f"current-function read failed: {current_text!r}")

            return {
                "status": "passed",
                "server_name": initialized.serverInfo.name,
                "server_version": initialized.serverInfo.version,
                "tool_count": len(tool_names),
                "health": health_text.splitlines(),
                "function_listing_nonempty": True,
                "current_function": current_text,
                "calls": {
                    "ghidra_health_error": health.isError,
                    "list_functions_error": functions.isError,
                    "get_current_function_error": current.isError,
                },
            }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify a live CodeBrowser Program through the Ghidra MCP bridge."
    )
    parser.add_argument("--bridge", type=Path, required=True)
    parser.add_argument(
        "--ghidra-server",
        default="http://127.0.0.1:8080/",
        help="Loopback URL exposed by the enabled Ghidra plugin.",
    )
    parser.add_argument(
        "--expected-program",
        help="Optional active Program name required in the health response.",
    )
    args = parser.parse_args()
    bridge = args.bridge.expanduser().resolve()
    if not bridge.is_file():
        parser.error("--bridge must identify the reviewed Ghidra MCP bridge")
    try:
        result = asyncio.run(
            verify(bridge, args.ghidra_server, args.expected_program)
        )
        print(json.dumps(result, indent=2))
        return 0
    except (OSError, RuntimeError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
