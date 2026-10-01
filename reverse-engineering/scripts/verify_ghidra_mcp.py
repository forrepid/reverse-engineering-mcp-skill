#!/usr/bin/env python3
from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin
from urllib.request import Request, urlopen
from pathlib import Path
from typing import Any

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from re_core.adapters import ghidra_profile


def _result_text(result: Any) -> str:
    return "\n".join(
        str(text)
        for item in result.content
        if (text := getattr(item, "text", None)) is not None
    )


def _http_status(url: str, token: str | None) -> tuple[int, str]:
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    request = Request(url, headers=headers, method="GET")
    try:
        with urlopen(request, timeout=5) as response:
            return response.status, response.read().decode("utf-8", errors="replace")
    except HTTPError as error:
        return error.code, error.read().decode("utf-8", errors="replace")
    except (OSError, URLError) as error:
        raise RuntimeError(f"Ghidra HTTP auth probe failed: {error}") from error


def _verify_http_auth(ghidra_server: str, token: str) -> dict[str, int]:
    health_url = urljoin(ghidra_server.rstrip("/") + "/", "health")
    missing_status, _ = _http_status(health_url, None)
    wrong_status, _ = _http_status(health_url, "invalid-probe-token")
    valid_status, direct_health = _http_status(health_url, token)
    if (missing_status, wrong_status, valid_status) != (401, 401, 200):
        raise RuntimeError(
            "Ghidra bearer-auth contract failed: expected 401/401/200, got "
            f"{missing_status}/{wrong_status}/{valid_status}"
        )
    if "status=ok" not in direct_health:
        raise RuntimeError(f"authenticated Ghidra /health response is invalid: {direct_health!r}")
    return {
        "missing_token": missing_status,
        "wrong_token": wrong_status,
        "valid_token": valid_status,
    }


async def verify(
    bridge: Path,
    ghidra_server: str,
    expected_program: str | None,
    token: str | None,
    host_profile: str,
) -> dict[str, Any]:
    if not token:
        raise RuntimeError("RE_GHIDRA_TOKEN must contain the configured per-install token")
    # Validate loopback before making any HTTP request; remote targets are out of scope.
    ghidra_profile((), endpoint=ghidra_server)
    auth_statuses = _verify_http_auth(ghidra_server, token)
    parameters = StdioServerParameters(
        command=sys.executable,
        args=[str(bridge), "--ghidra-server", ghidra_server],
        env={**os.environ, "RE_GHIDRA_TOKEN": token},
    )


    if host_profile in {"read_only", "read_write"}:
        parameters.args.extend(["--profile", host_profile])
    async with stdio_client(parameters) as (reader, writer):
        async with ClientSession(reader, writer) as session:
            initialized = await session.initialize()
            tools = await session.list_tools()
            tool_names = sorted(item.name for item in tools.tools)
            resources = await session.list_resources()
            resource_uris = sorted(str(item.uri) for item in resources.resources)
            profile = ghidra_profile(
                tool_names,
                endpoint=ghidra_server,
                discovered_resources=resource_uris,
            )
            if host_profile in {"read_only", "read_write"}:
                allowed_classes = {"read"} if host_profile == "read_only" else {"read", "annotate"}
                mutation_tools = [
                    name
                    for name in tool_names
                    if (operation := profile.classify(name)) is None
                    or operation.value not in allowed_classes
                ]
                if mutation_tools:
                    raise RuntimeError(
                        f"{host_profile} Ghidra profile exposed disallowed tools: "
                        + ", ".join(mutation_tools)
                    )
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
                "http_auth_statuses": auth_statuses,
                "resource_count": len(resource_uris),
                "coverage": profile.coverage_report(),
                "operation_policy": profile.policy_report(host_profile),
                "unknown_tools": profile.unknown_tools(),
                "unknown_resources": profile.unknown_resources(),
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
        "--profile", choices=("current", "read_only", "read_write"), default="read_only",
        help="Host profile to verify; defaults to the safer read_only profile.",
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
            verify(
                bridge, args.ghidra_server, args.expected_program,
                os.environ.get("RE_GHIDRA_TOKEN"), args.profile,
            )
        )
        print(json.dumps(result, indent=2))
        return 0
    except Exception as error:
        message = str(error)
        token = os.environ.get("RE_GHIDRA_TOKEN")
        if token:
            message = message.replace(token, "[REDACTED]")
        print(f"error: {message}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
