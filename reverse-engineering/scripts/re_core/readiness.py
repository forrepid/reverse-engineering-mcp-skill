from __future__ import annotations

import importlib.metadata
import importlib.util
import ipaddress
import shutil
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse

from .environment import RuntimeEnvironment
from .external import provider_status
from .feature_catalog import validate_feature_catalog


DEPENDENCIES = ("mcp", "capstone", "lief", "pefile")


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


def _ghidra_health(server: str) -> dict[str, Any]:
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
        request = urllib.request.Request(health_url, headers={"Accept": "text/plain"})
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
    health = _ghidra_health(server) if plugin_installed else {
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
        ),
        "live_plugin_verified": health["plugin_reachable"],
        "active_program": health["active_program"],
        "live_program_verified": bool(health["active_program"]),
        "health_url": health["health_url"],
        "health_error": health["health_error"],
    }


def build_readiness_report(
    runtime: RuntimeEnvironment,
    *,
    ida_path: str | Path | None = None,
    idalib_mcp: str | Path | None = None,
    ghidra_home: str | Path | None = None,
    ghidra_bridge: str | Path | None = None,
    ghidra_server: str = "http://127.0.0.1:8080/",
) -> dict[str, Any]:
    ida = _file(ida_path)
    idalib = _file(idalib_mcp)
    if idalib is None:
        discovered = shutil.which("idalib-mcp") or shutil.which("idalib-mcp.exe")
        idalib = _file(discovered)
    ghidra = _ghidra_status(
        _directory(ghidra_home), _file(ghidra_bridge), ghidra_server
    )
    dependencies = _dependency_status()
    providers = provider_status(runtime.provider_config)
    catalog = validate_feature_catalog()
    local_ready = catalog["valid"] and all(item["importable"] for item in dependencies)
    ida_ready = ida is not None and idalib is not None
    actions = []
    if ida is None:
        actions.append("Pass --ida with an existing ida.exe to enable IDA readiness.")
    if idalib is None:
        actions.append("Install/activate the reviewed ida-pro-mcp idalib entry point.")
    if not ghidra["installed"]:
        actions.append("Install a reviewed Ghidra release and pass --ghidra-home.")
    if not ghidra["bridge_basename_valid"]:
        actions.append("Install upstream GhidraMCP and pass --ghidra-bridge.")
    if not ghidra["server_loopback"]:
        actions.append("Use an HTTP(S) loopback URL for --ghidra-server.")
    if ghidra["installed"] and not ghidra["plugin_installed"]:
        actions.append("Install the reviewed GhidraMCP extension under Ghidra/Extensions.")
    if ghidra["config_ready"] and not ghidra["live_plugin_verified"]:
        actions.append(
            "Open a Ghidra CodeBrowser tool and enable GhidraMCP once; the loopback health endpoint will then become reachable."
        )
    if not any(item["runnable"] for item in providers):
        actions.append("Install or configure at least one allowlisted static provider.")
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
        },
        "ghidra": ghidra,
        "providers": providers,
        "summary": {
            "local_companion_ready": local_ready,
            "ida_config_ready": ida_ready,
            "ghidra_config_ready": ghidra["config_ready"],
            "live_host_claim": ghidra["live_program_verified"],
        },
        "actions": actions,
    }
