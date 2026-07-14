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


async def verify(server_script: Path) -> dict[str, Any]:
    parameters = StdioServerParameters(
        command=sys.executable,
        args=[str(server_script)],
        env={
            "RE_MCP_MODE": "read_only",
            "RE_MCP_LOG_LEVEL": "ERROR",
            "RE_MCP_MAX_FILE_BYTES": "536870912",
            "RE_MCP_MAX_REGION_BYTES": "1048576",
            "RE_MCP_MAX_SCAN_BYTES": "67108864",
            "RE_MCP_ALLOWED_ROOTS": "",
            "RE_MCP_PROVIDER_CONFIG": "",
            "RE_MCP_PROVIDER_TIMEOUT_SECONDS": "120",
            "RE_MCP_MAX_PROVIDER_OUTPUT_BYTES": "4194304",
        },
    )
    async with stdio_client(parameters) as (reader, writer):
        async with ClientSession(reader, writer) as session:
            initialized = await session.initialize()
            tools = await session.list_tools()
            tool_names = sorted(item.name for item in tools.tools)
            required = {
                "runtime_environment",
                "feature_catalog_check",
                "provider_preflight",
                "local_feature_analysis",
                "run_static_provider",
                "system_readiness",
            }
            missing = sorted(required - set(tool_names))
            if missing:
                raise RuntimeError("required MCP tools missing: " + ", ".join(missing))
            environment = await session.call_tool("runtime_environment", {})
            catalog = await session.call_tool("feature_catalog_check", {})
            preflight = await session.call_tool("provider_preflight", {})
            return {
                "status": "passed",
                "server_name": initialized.serverInfo.name,
                "server_version": initialized.serverInfo.version,
                "tool_count": len(tool_names),
                "tools": tool_names,
                "calls": {
                    "runtime_environment_error": environment.isError,
                    "feature_catalog_check_error": catalog.isError,
                    "provider_preflight_error": preflight.isError,
                },
            }


def main() -> int:
    parser = argparse.ArgumentParser(description="Run an actual stdio MCP smoke test.")
    parser.add_argument(
        "--server-script",
        type=Path,
        default=Path(__file__).resolve().with_name("re_mcp_server.py"),
    )
    args = parser.parse_args()
    script = args.server_script.expanduser().resolve()
    if not script.is_file() or script.name != "re_mcp_server.py":
        parser.error("--server-script must identify re_mcp_server.py")
    try:
        print(json.dumps(asyncio.run(verify(script)), indent=2))
        return 0
    except (OSError, RuntimeError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
