from __future__ import annotations

import json
import ipaddress
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .environment import environment_contract, resolve_config_environment


class ClientConfigError(RuntimeError):
    """Raised when a portable MCP client configuration is invalid."""


@dataclass(frozen=True)
class ClientProfile:
    id: str
    display_name: str
    output_name: str
    merge_target: str
    root_key: str
    format: str
    documentation: str


CLIENTS: tuple[ClientProfile, ...] = (
    ClientProfile(
        "codex",
        "OpenAI Codex CLI/Desktop/IDE",
        "codex.config.toml",
        "~/.codex/config.toml or .codex/config.toml",
        "mcp_servers",
        "toml",
        "https://developers.openai.com/codex/mcp/",
    ),
    ClientProfile(
        "claude-code",
        "Claude Code",
        "claude-code.mcp.json",
        "project .mcp.json or user ~/.claude.json via claude mcp add",
        "mcpServers",
        "json",
        "https://code.claude.com/docs/en/mcp",
    ),
    ClientProfile(
        "qwen-code",
        "Qwen Code",
        "qwen-code.settings.json",
        "project .qwen/settings.json or user ~/.qwen/settings.json",
        "mcpServers",
        "json",
        "https://qwenlm.github.io/qwen-code-docs/en/users/features/mcp/",
    ),
    ClientProfile(
        "vscode",
        "Visual Studio Code",
        "vscode.mcp.json",
        "workspace .vscode/mcp.json or MCP: Open User Configuration",
        "servers",
        "json",
        "https://code.visualstudio.com/docs/agent-customization/mcp-servers",
    ),
    ClientProfile(
        "visual-studio",
        "Microsoft Visual Studio",
        "visual-studio.mcp.json",
        "solution .mcp.json/.vs/mcp.json or %USERPROFILE%/.mcp.json",
        "servers",
        "json",
        "https://learn.microsoft.com/en-us/visualstudio/ide/mcp-servers?view=visualstudio",
    ),
    ClientProfile(
        "zed",
        "Zed",
        "zed.settings.json",
        "Zed settings.json via Settings > AI > MCP Servers",
        "context_servers",
        "json",
        "https://zed.dev/docs/ai/mcp",
    ),
    ClientProfile(
        "antigravity",
        "Google Antigravity IDE/CLI",
        "antigravity.mcp_config.json",
        "workspace .agents/mcp_config.json or ~/.gemini/config/mcp_config.json",
        "mcpServers",
        "json",
        "https://antigravity.google/docs/mcp",
    ),
    ClientProfile(
        "kimi",
        "Kimi Code CLI",
        "kimi.mcp.json",
        "project .kimi-code/mcp.json or user ~/.kimi-code/mcp.json",
        "mcpServers",
        "json",
        "https://www.kimi.com/code/docs/en/kimi-code-cli/customization/mcp.html",
    ),
)


def client_profiles() -> dict[str, Any]:
    contract = environment_contract({})
    return {
        "schema_version": "0.5.0",
        "count": len(CLIENTS),
        "clients": [asdict(item) for item in CLIENTS],
        "companion_environment": {
            "required_count": contract["required_count"],
            "secret_count": contract["secret_count"],
            "variables": [item["name"] for item in contract["variables"]],
            "rendering": "explicit-env-per-companion-entry",
        },
    }


def _profile(client: str) -> ClientProfile:
    match = next((item for item in CLIENTS if item.id == client), None)
    if match is None:
        raise ClientConfigError(
            "unknown client; expected one of: "
            + ", ".join(item.id for item in CLIENTS)
        )
    return match


def _validate_inputs(
    python_executable: str | Path,
    companion_script: str | Path,
    idalib_mcp: str | Path | None,
    ghidra_bridge: str | Path | None,
    ghidra_server: str,
    max_workers: int,
) -> tuple[Path, Path, Path | None, Path | None]:
    python_path = Path(python_executable).expanduser().resolve()
    companion_path = Path(companion_script).expanduser().resolve()
    idalib_path = (
        Path(idalib_mcp).expanduser().resolve() if idalib_mcp is not None else None
    )
    ghidra_path = (
        Path(ghidra_bridge).expanduser().resolve()
        if ghidra_bridge is not None
        else None
    )
    if not python_path.is_file():
        raise ClientConfigError(f"Python executable does not exist: {python_path}")
    if not companion_path.is_file():
        raise ClientConfigError(f"companion MCP script does not exist: {companion_path}")
    if companion_path.name != "re_mcp_server.py":
        raise ClientConfigError("companion script must be re_mcp_server.py")
    if idalib_path is not None:
        if not idalib_path.is_file():
            raise ClientConfigError(f"idalib-mcp executable does not exist: {idalib_path}")
        if idalib_path.name.lower() not in {"idalib-mcp", "idalib-mcp.exe"}:
            raise ClientConfigError("idalib MCP basename must be idalib-mcp or idalib-mcp.exe")
    if ghidra_path is not None:
        if not ghidra_path.is_file():
            raise ClientConfigError(f"Ghidra MCP bridge does not exist: {ghidra_path}")
        if ghidra_path.name != "bridge_mcp_ghidra.py":
            raise ClientConfigError("Ghidra bridge basename must be bridge_mcp_ghidra.py")
        parsed = urlparse(ghidra_server)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ClientConfigError("ghidra_server must be an absolute HTTP(S) URL")
        try:
            loopback = ipaddress.ip_address(parsed.hostname).is_loopback
        except ValueError:
            loopback = parsed.hostname.lower() == "localhost"
        if not loopback:
            raise ClientConfigError("Ghidra MCP server must use a loopback host")
    if not 1 <= max_workers <= 32:
        raise ClientConfigError("max_workers must be between 1 and 32")
    return python_path, companion_path, idalib_path, ghidra_path


def _server_commands(
    python_path: Path,
    companion_path: Path,
    idalib_path: Path | None,
    ghidra_path: Path | None,
    ghidra_server: str,
    max_workers: int,
    environment: dict[str, str],
) -> dict[str, dict[str, Any]]:
    servers: dict[str, dict[str, Any]] = {
        "reverse-engineering-companion": {
            "command": str(python_path),
            "args": [str(companion_path)],
            "env": dict(environment),
        }
    }
    if idalib_path is not None:
        servers["ida-pro-idalib"] = {
            "command": str(idalib_path),
            "args": ["--stdio", "--max-workers", str(max_workers)],
        }
    if ghidra_path is not None:
        servers["ghidra-mcp"] = {
            "command": str(python_path),
            "args": [str(ghidra_path), "--ghidra-server", ghidra_server],
        }
    return servers


def _toml_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def _codex_toml(servers: dict[str, dict[str, Any]]) -> str:
    lines = [
        "# Merge these tables into ~/.codex/config.toml or .codex/config.toml.",
        "# Review paths and keep tool approval prompts enabled.",
        "",
    ]
    for name, server in servers.items():
        lines.extend(
            [
                f"[mcp_servers.{name}]",
                f"command = {_toml_string(server['command'])}",
                "args = ["
                + ", ".join(_toml_string(value) for value in server["args"])
                + "]",
                'default_tools_approval_mode = "prompt"',
                "startup_timeout_sec = 30",
                "tool_timeout_sec = 120",
                "enabled = true",
            ]
        )
        environment = server.get("env", {})
        if environment:
            lines.append("")
            lines.append(f"[mcp_servers.{name}.env]")
            lines.extend(
                f"{key} = {_toml_string(value)}"
                for key, value in sorted(environment.items())
            )
        lines.append("")
    return "\n".join(lines)


def _json_server(client: str, server: dict[str, Any]) -> dict[str, Any]:
    payload = {"command": server["command"], "args": list(server["args"])}
    if server.get("env"):
        payload["env"] = dict(server["env"])
    if client == "claude-code":
        payload["type"] = "stdio"
    elif client == "qwen-code":
        payload.update(
            {
                "trust": False,
                "timeout": 120000,
                "discoveryTimeoutMs": 30000,
            }
        )
    elif client in {"vscode", "visual-studio"}:
        payload["type"] = "stdio"
    elif client == "kimi":
        payload.update(
            {
                "enabled": True,
                "startupTimeoutMs": 30000,
                "toolTimeoutMs": 120000,
            }
        )
    return payload


def render_client_config(
    client: str,
    *,
    python_executable: str | Path,
    companion_script: str | Path,
    idalib_mcp: str | Path | None = None,
    ghidra_bridge: str | Path | None = None,
    ghidra_server: str = "http://127.0.0.1:8080/",
    max_workers: int = 4,
    env_assignments: Sequence[str] = (),
    env_file: str | Path | None = None,
) -> str:
    profile = _profile(client)
    python_path, companion_path, idalib_path, ghidra_path = _validate_inputs(
        python_executable,
        companion_script,
        idalib_mcp,
        ghidra_bridge,
        ghidra_server,
        max_workers,
    )
    environment = resolve_config_environment(
        assignments=env_assignments,
        env_file=env_file,
    )
    servers = _server_commands(
        python_path,
        companion_path,
        idalib_path,
        ghidra_path,
        ghidra_server,
        max_workers,
        environment,
    )
    if profile.format == "toml":
        return _codex_toml(servers)
    payload = {
        profile.root_key: {
            name: _json_server(client, server) for name, server in servers.items()
        }
    }
    return json.dumps(payload, indent=2, ensure_ascii=False) + "\n"


def render_all_client_configs(
    output_dir: str | Path,
    *,
    python_executable: str | Path,
    companion_script: str | Path,
    idalib_mcp: str | Path | None = None,
    ghidra_bridge: str | Path | None = None,
    ghidra_server: str = "http://127.0.0.1:8080/",
    clients: list[str] | tuple[str, ...] | None = None,
    max_workers: int = 4,
    env_assignments: Sequence[str] = (),
    env_file: str | Path | None = None,
    force: bool = False,
) -> dict[str, Any]:
    selected = list(clients or [item.id for item in CLIENTS])
    if not selected or len(selected) != len(set(selected)):
        raise ClientConfigError("client selection must be non-empty and unique")
    profiles = [_profile(client) for client in selected]
    environment = resolve_config_environment(
        assignments=env_assignments,
        env_file=env_file,
    )
    normalized_assignments = tuple(
        f"{name}={value}" for name, value in environment.items()
    )
    target_dir = Path(output_dir).expanduser().resolve()
    target_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = target_dir / "manifest.json"
    targets = [*(target_dir / profile.output_name for profile in profiles), manifest_path]
    existing = [str(target) for target in targets if target.exists()]
    if existing and not force:
        raise ClientConfigError(
            "generated outputs already exist; use --force to replace them: "
            + ", ".join(existing)
        )
    outputs: list[dict[str, Any]] = []
    for profile in profiles:
        target = target_dir / profile.output_name
        content = render_client_config(
            profile.id,
            python_executable=python_executable,
            companion_script=companion_script,
            idalib_mcp=idalib_mcp,
            ghidra_bridge=ghidra_bridge,
            ghidra_server=ghidra_server,
            max_workers=max_workers,
            env_assignments=normalized_assignments,
        )
        target.write_text(content, encoding="utf-8")
        outputs.append(
            {
                "client": profile.id,
                "path": str(target),
                "merge_target": profile.merge_target,
                "documentation": profile.documentation,
            }
        )
    server_names = ["reverse-engineering-companion"]
    if idalib_mcp is not None:
        server_names.append("ida-pro-idalib")
    if ghidra_bridge is not None:
        server_names.append("ghidra-mcp")
    manifest = {
        "schema_version": "0.5.0",
        "status": "generated-not-installed",
        "automatic_installation": False,
        "servers": server_names,
        "companion_environment": environment,
        "outputs": outputs,
        "security": [
            "Review absolute executable and script paths before merging.",
            "Keep client trust and per-tool approval prompts enabled.",
            "Project-level MCP files can execute local commands; trust the repository first.",
            "Generated fragments do not modify any client configuration automatically.",
            "The companion needs no secret; only documented RE_MCP_* values are rendered.",
        ],
    }
    manifest_path.write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return {**manifest, "manifest": str(manifest_path)}
