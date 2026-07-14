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


def _result_json(result: Any) -> Any:
    structured = getattr(result, "structuredContent", None)
    if structured is not None:
        return structured
    for item in result.content:
        text = getattr(item, "text", None)
        if text:
            return json.loads(text)
    raise RuntimeError("MCP tool returned no JSON content")


async def verify(command: Path, sample: Path) -> dict[str, Any]:
    parameters = StdioServerParameters(
        command=str(command),
        args=["--stdio", "--max-workers", "1"],
    )
    async with stdio_client(parameters) as (reader, writer):
        async with ClientSession(reader, writer) as session:
            initialized = await session.initialize()
            tools = await session.list_tools()
            resources = await session.list_resources()
            tool_names = sorted(item.name for item in tools.tools)
            required = {"idb_open", "server_health", "list_funcs"}
            missing = sorted(required - set(tool_names))
            if missing:
                raise RuntimeError("required idalib MCP tools missing: " + ", ".join(missing))

            opened_result = await session.call_tool(
                "idb_open",
                {
                    "input_path": str(sample),
                    "mode": "force_headless",
                    "run_auto_analysis": True,
                    "build_caches": True,
                    "init_hexrays": True,
                    "idle_ttl_sec": 600,
                    "preferred_session_id": "re-skill-smoke",
                },
            )
            opened = _result_json(opened_result)
            if opened_result.isError or not opened.get("success"):
                raise RuntimeError(f"idb_open failed: {opened!r}")
            database = opened["session"]["session_id"]

            health_result = await session.call_tool(
                "server_health", {"database": database}
            )
            functions_result = await session.call_tool(
                "list_funcs",
                {
                    "database": database,
                    "queries": {"offset": 0, "count": 5, "filter": ""},
                },
            )
            health = _result_json(health_result)
            functions = _result_json(functions_result)
            if health_result.isError or health.get("status") != "ok":
                raise RuntimeError(f"server_health failed: {health!r}")
            if not health.get("auto_analysis_ready"):
                raise RuntimeError(f"IDA auto-analysis is not ready: {health!r}")
            if functions_result.isError or not functions:
                raise RuntimeError("IDA function listing returned no data")

            return {
                "status": "passed",
                "server_name": initialized.serverInfo.name,
                "server_version": initialized.serverInfo.version,
                "tool_count": len(tool_names),
                "resource_count": len(resources.resources),
                "database": database,
                "module": health.get("module"),
                "input_path": health.get("input_path"),
                "auto_analysis_ready": health.get("auto_analysis_ready"),
                "hexrays_ready": health.get("hexrays_ready"),
                "function_listing_nonempty": True,
                "calls": {
                    "idb_open_error": opened_result.isError,
                    "server_health_error": health_result.isError,
                    "list_funcs_error": functions_result.isError,
                },
            }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify a trusted sample through the IDA idalib MCP supervisor."
    )
    parser.add_argument("--command", type=Path, required=True)
    parser.add_argument("--sample", type=Path, required=True)
    args = parser.parse_args()
    command = args.command.expanduser().resolve()
    sample = args.sample.expanduser().resolve()
    if not command.is_file():
        parser.error("--command must identify idalib-mcp.exe")
    if not sample.is_file():
        parser.error("--sample must identify a trusted local sample")
    try:
        print(json.dumps(asyncio.run(verify(command, sample)), indent=2))
        return 0
    except (OSError, RuntimeError, KeyError, json.JSONDecodeError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
