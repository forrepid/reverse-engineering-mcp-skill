from __future__ import annotations

import importlib.metadata
import importlib.util
import ipaddress
import shutil
import sys
import urllib.error
import urllib.request
import os
import json
import subprocess
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse

from .environment import RuntimeEnvironment
from .external import provider_status
from .feature_catalog import validate_feature_catalog
from .broker_config import BrokerConfigError, load_broker_config, probe_broker_health
from .broker_discovery import discover_local_brokers


DEPENDENCIES = ("mcp", "capstone", "lief", "pefile")


def _probe_idalib_health(executable: Path, timeout: float = 10.0) -> dict[str, Any]:
    """Issue MCP initialize/tools/list to the explicitly selected idalib server."""
    try:
        process = subprocess.Popen(
            [str(executable), "--stdio", "--max-workers", "1"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            shell=False,
        )
    except OSError as error:
        return {"status": "unavailable", "verified": False, "error": str(error)}
    if process.stdin is None or process.stdout is None:
        process.kill()
        return {"status": "failed", "verified": False, "error": "stdio pipes are unavailable"}
    stdin = process.stdin
    stdout = process.stdout

    def send(message: dict[str, Any]) -> None:
        wire = json.dumps(message, separators=(",", ":")).encode()
        stdin.write(wire + b"\n")
        stdin.flush()

    def receive() -> dict[str, Any]:
        line = stdout.readline()
        if not line:
            raise RuntimeError("server closed its MCP stdout")
        if len(line) > 4 * 1024 * 1024:
            raise RuntimeError("MCP response exceeds 4 MiB")
        payload = json.loads(line)
        if not isinstance(payload, dict):
            raise RuntimeError("MCP response must be a JSON object")
        return payload

    try:
        import threading
        response_box: list[dict[str, Any] | BaseException] = []
        def read_response() -> None:
            try:
                response_box.append(receive())
            except BaseException as error:
                response_box.append(error)

        reader = threading.Thread(target=read_response, daemon=True)
        reader.start()
        send({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2024-11-05", "capabilities": {}, "clientInfo": {"name": "re-doctor", "version": "0.5.0"}}})
        reader.join(timeout)
        if reader.is_alive() or not response_box:
            raise RuntimeError("initialize timed out")
        init = response_box.pop()
        if isinstance(init, BaseException):
            raise RuntimeError(str(init))
        if init.get("id") != 1 or "error" in init:
            raise RuntimeError("initialize failed")
        # idalib-mcp's stdio transport is line-delimited and dispatches every
        # request synchronously; queue the notification before tools/list and
        # only then wait for the single response.
        send({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}})
        send({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
        reader = threading.Thread(target=read_response, daemon=True)
        reader.start()
        reader.join(timeout)
        if reader.is_alive() or not response_box:
            raise RuntimeError("tools/list timed out")
        tools_response = response_box.pop()
        if isinstance(tools_response, BaseException):
            raise RuntimeError(str(tools_response))
        if tools_response.get("id") != 2 or "error" in tools_response:
            raise RuntimeError("tools/list failed")
        tools = tools_response.get("result", {}).get("tools", [])
        return {"status": "verified", "verified": True, "probe": "MCP initialize + tools/list", "tool_count": len(tools), "tool_names": [item.get("name") for item in tools if isinstance(item, dict)]}
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as error:
        return {"status": "failed", "verified": False, "error": str(error)}
    finally:
        try:
            if process.stdin is not None:
                process.stdin.close()
            process.wait(timeout=1)
        except (OSError, subprocess.TimeoutExpired):
            process.kill()
            try:
                process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                pass
        for pipe in (process.stdin, process.stdout):
            if pipe is not None:
                pipe.close()


def _dependency_status() -> list[dict[str, Any]]:
    records = []
    for name in DEPENDENCIES:
        importable = importlib.util.find_spec(name) is not None
        try:
            version = importlib.metadata.version(name) if importable else None
        except importlib.metadata.PackageNotFoundError:
            version = None
        records.append({"name": name, "importable": importable, "version": version})
    return records


def _file(path: str | Path | None) -> Path | None:
    if path is None or not str(path).strip():
        return None
    candidate = Path(path).expanduser().resolve()
    return candidate if candidate.is_file() else None


def _directory(path: str | Path | None) -> Path | None:
    if path is None or not str(path).strip():
        return None
    candidate = Path(path).expanduser().resolve()
    return candidate if candidate.is_dir() else None


def _is_loopback_http(server: str) -> bool:
    parsed = urlparse(server)
    host = parsed.hostname
    loopback = False
    if host:
        try:
            loopback = (
                host.lower() == "localhost" or ipaddress.ip_address(host).is_loopback
            )
        except ValueError:
            loopback = False
    return parsed.scheme in {"http", "https"} and loopback


def _ghidra_health(server: str, token: str | None = None) -> dict[str, Any]:
    loopback = _is_loopback_http(server)
    health_url = urljoin(server.rstrip("/") + "/", "health")
    if not loopback:
        return {
            "health_url": health_url,
            "plugin_reachable": False,
            "active_program": None,
            "health_error": "Ghidra health URL must use HTTP(S) on a loopback host.",
        }
    try:
        headers = {"Accept": "text/plain"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        request = urllib.request.Request(health_url, headers=headers)
        with urllib.request.urlopen(request, timeout=0.75) as response:  # noqa: S310
            body = response.read(4096).decode("utf-8", errors="replace")
        fields = dict(
            line.split("=", 1) for line in body.splitlines() if "=" in line
        )
        reachable = fields.get("status") == "ok"
        program = fields.get("program")
        return {
            "health_url": health_url,
            "plugin_reachable": reachable,
            "active_program": None if program in {None, "", "none"} else program,
            "health_error": None if reachable else "Unexpected health response.",
        }
    except (OSError, TimeoutError, urllib.error.URLError) as error:
        return {
            "health_url": health_url,
            "plugin_reachable": False,
            "active_program": None,
            "health_error": str(error),
        }


def _ghidra_status(
    home: Path | None, bridge: Path | None, server: str
) -> dict[str, Any]:
    launchers: list[Path] = []
    headless: list[Path] = []
    if home is not None:
        launchers = [
            candidate
            for candidate in (home / "ghidraRun.bat", home / "ghidraRun")
            if candidate.is_file()
        ]
        headless = [
            candidate
            for candidate in (
                home / "support" / "analyzeHeadless.bat",
                home / "support" / "analyzeHeadless",
            )
            if candidate.is_file()
        ]
    application_properties = home / "Ghidra" / "application.properties" if home else None
    version = None
    if application_properties is not None and application_properties.is_file():
        for line in application_properties.read_text(
            encoding="utf-8", errors="replace"
        ).splitlines():
            if line.startswith("application.version="):
                version = line.partition("=")[2].strip()
                break
    plugin = home / "Ghidra" / "Extensions" / "GhidraMCP" if home else None
    plugin_jar = plugin / "lib" / "GhidraMCP.jar" if plugin else None
    plugin_properties = plugin / "extension.properties" if plugin else None
    plugin_installed = bool(
        plugin_jar
        and plugin_jar.is_file()
        and plugin_properties
        and plugin_properties.is_file()
    )
    server_loopback = _is_loopback_http(server)
    bridge_valid = bridge is not None and bridge.name == "bridge_mcp_ghidra.py"
    auth_token = os.environ.get("RE_GHIDRA_TOKEN")
    health = _ghidra_health(server, auth_token) if plugin_installed else {
        "health_url": urljoin(server.rstrip("/") + "/", "health"),
        "plugin_reachable": False,
        "active_program": None,
        "health_error": "GhidraMCP extension is not installed.",
    }
    return {
        "home": str(home) if home is not None else None,
        "version": version,
        "launcher": str(launchers[0]) if launchers else None,
        "headless": str(headless[0]) if headless else None,
        "bridge": str(bridge) if bridge is not None else None,
        "bridge_basename_valid": bridge_valid,
        "server_loopback": server_loopback,
        "plugin": str(plugin) if plugin is not None else None,
        "plugin_jar": str(plugin_jar) if plugin_jar is not None else None,
        "plugin_installed": plugin_installed,
        "installed": bool(launchers and headless),
        "config_ready": bool(
            launchers
            and headless
            and bridge_valid
            and plugin_installed
            and server_loopback
            and auth_token
        ),
        "live_plugin_verified": health["plugin_reachable"],
        "active_program": health["active_program"],
        "live_program_verified": bool(health["active_program"]),
        "health_url": health["health_url"],
        "health_error": health["health_error"],
        "authentication": {
            "configured": bool(auth_token),
            "required": True,
            "source": "RE_GHIDRA_TOKEN process environment only",
        },
    }


def build_readiness_report(
    runtime: RuntimeEnvironment,
    *,
    ida_path: str | Path | None = None,
    idalib_mcp: str | Path | None = None,
    ghidra_home: str | Path | None = None,
    ghidra_bridge: str | Path | None = None,
    ghidra_server: str = "http://127.0.0.1:8080/",
    probe_ida: bool = False,
    ghidra_token: str | None = None,
) -> dict[str, Any]:
    ida = _file(ida_path)
    idalib = _file(idalib_mcp)
    if idalib is None:
        discovered = shutil.which("idalib-mcp") or shutil.which("idalib-mcp.exe")
        idalib = _file(discovered)
    old_token = os.environ.get("RE_GHIDRA_TOKEN")
    if ghidra_token is not None:
        os.environ["RE_GHIDRA_TOKEN"] = ghidra_token
    try:
        ghidra = _ghidra_status(_directory(ghidra_home), _file(ghidra_bridge), ghidra_server)
    finally:
        if old_token is None:
            os.environ.pop("RE_GHIDRA_TOKEN", None)
        else:
            os.environ["RE_GHIDRA_TOKEN"] = old_token
    dependencies = _dependency_status()
    providers = provider_status(runtime.provider_config)
    try:
        broker_config = load_broker_config()
        broker_status: dict[str, Any] = broker_config.public_status()
        broker_status["health"] = probe_broker_health(broker_config)
    except BrokerConfigError as error:
        broker_status = {
            "provider": "unknown",
            "status": "invalid_configuration",
            "configured": False,
            "error": str(error),
            "continuous_capture": False,
            "submission_enabled": False,
        }
    catalog = validate_feature_catalog()
    local_ready = catalog["valid"] and all(item["importable"] for item in dependencies)
    ida_ready = ida is not None and idalib is not None
    ida_live = _probe_idalib_health(idalib) if probe_ida and idalib is not None else None
    actions = []
    if ida is None:
        actions.append("Pass --ida with an existing ida.exe to enable IDA readiness.")
    if idalib is None:
        actions.append("Install/activate the reviewed ida-pro-mcp idalib entry point.")
    if ida_live and not ida_live.get("verified"):
        actions.append("IDA MCP live probe failed; inspect ida.live_probe.error and keep live status unverified.")
    if not ghidra["installed"]:
        actions.append("Install a reviewed Ghidra release and pass --ghidra-home.")
    if not ghidra["bridge_basename_valid"]:
        actions.append("Install upstream GhidraMCP and pass --ghidra-bridge.")
    if not ghidra["server_loopback"]:
        actions.append("Use an HTTP(S) loopback URL for --ghidra-server.")
    if not ghidra["authentication"]["configured"]:
        actions.append("Set RE_GHIDRA_TOKEN in the launching process and Ghidra JVM -Dghidra.mcp.token to the same private token.")
    if ghidra["installed"] and not ghidra["plugin_installed"]:
        actions.append("Install the reviewed GhidraMCP extension under Ghidra/Extensions.")
    if ghidra["config_ready"] and not ghidra["live_plugin_verified"]:
        actions.append(
            "Open a Ghidra CodeBrowser tool and enable GhidraMCP once; the loopback health endpoint will then become reachable."
        )
    if not any(item["runnable"] for item in providers):
        actions.append("Install or configure at least one allowlisted static provider.")
    if broker_status["status"] == "test_only":
        actions.append("A test-only mock broker is configured; it has no capture, signing, or sample-submission capability.")
    elif broker_status["status"] != "configured_unverified":
        actions.append(
            "Runtime OEP broker is not configured: set RE_BROKER_PROVIDER, loopback/HTTPS URL, broker ID, and pinned public-key digest; no samples are submitted."
        )
    else:
        actions.append(
            "Broker endpoint config is present but capture/signing compatibility is unverified; health probe never submits a sample."
        )
    return {
        "schema_version": "0.5.0",
        "python": {"executable": sys.executable, "version": sys.version.split()[0]},
        "environment": runtime.to_dict(),
        "feature_catalog": catalog,
        "dependencies": dependencies,
        "ida": {
            "executable": str(ida) if ida is not None else None,
            "idalib_mcp": str(idalib) if idalib is not None else None,
            "config_ready": ida_ready,
            "live_database_verified": False,
            "live_probe_status": ida_live["status"] if ida_live else "not_checked",
            "live_probe": ida_live,
        },
        "ghidra": ghidra,
        "runtime_oep_broker": {
            **broker_status,
            "local_candidates": discover_local_brokers(),
            "adapter": None,
            "note": "Configuration/health only. Live capture, sample submission, and signing adapter are not enabled by this probe.",
        },
        "providers": providers,
        "summary": {
            "local_companion_ready": local_ready,
            "ida_config_ready": ida_ready,
            "ida_live_mcp_verified": bool(ida_live and ida_live.get("verified")),
            "ida_live_probe_status": ida_live["status"] if ida_live else "not_checked",
            "ghidra_config_ready": ghidra["config_ready"],
            "live_host_claim": ghidra["live_program_verified"],
        },
        "actions": actions,
    }
