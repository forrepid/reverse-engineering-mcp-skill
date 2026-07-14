from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
from dataclasses import asdict, dataclass
from importlib.metadata import PackageNotFoundError, distributions, version
from pathlib import Path
from typing import Any, IO


class McpSupervisorError(RuntimeError):
    """Raised when an MCP launch violates the local safety policy."""


@dataclass(frozen=True)
class McpLaunchPlan:
    transport: str
    executable: str
    executable_sha256: str
    command: list[str]
    endpoint: str
    available: bool
    isolated_contexts: bool
    max_workers: int
    package_version: str = "unknown"
    session_model: str = "persistent-per-database-worker"
    shell: bool = False
    schema_version: str = "0.5.0"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _resolve_idalib_mcp(executable: str | Path | None) -> str:
    if executable:
        candidate = Path(executable).expanduser().resolve()
        return str(candidate) if candidate.is_file() else ""
    return shutil.which("idalib-mcp") or shutil.which("idalib-mcp.exe") or ""


def _sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _package_version_for(executable: str) -> str:
    candidates: list[Path] = []
    if executable:
        root = Path(executable).resolve().parent.parent
        candidates.append(root / "Lib" / "site-packages")
        candidates.extend((root / "lib").glob("python*/site-packages"))
    for site_packages in candidates:
        if not site_packages.is_dir():
            continue
        for distribution in distributions(path=[str(site_packages)]):
            package_name = distribution.metadata["Name"] or ""
            if package_name.lower() == "ida-pro-mcp":
                return distribution.version
    try:
        return version("ida-pro-mcp")
    except PackageNotFoundError:
        return "unknown"


def _validate_mcp_executable(executable: str) -> None:
    if not executable:
        return
    name = Path(executable).name.lower()
    if name not in {"idalib-mcp", "idalib-mcp.exe"}:
        raise McpSupervisorError("only the idalib-mcp entry point is allowlisted")


def build_mcp_launch_plan(
    *,
    transport: str = "stdio",
    executable: str | Path | None = None,
    host: str = "127.0.0.1",
    port: int = 8745,
    max_workers: int = 4,
    isolated_contexts: bool = True,
) -> McpLaunchPlan:
    if transport not in {"http", "stdio"}:
        raise ValueError("transport must be http or stdio")
    if host not in {"127.0.0.1", "::1", "localhost"}:
        raise McpSupervisorError("v0 idalib-mcp launch plans are loopback-only")
    if not 1 <= port <= 65535:
        raise ValueError("invalid MCP port")
    if not 1 <= max_workers <= 64:
        raise ValueError("max_workers must be between 1 and 64")
    if not isolated_contexts:
        raise McpSupervisorError(
            "shared database contexts are forbidden; idalib-mcp uses one worker per database"
        )
    resolved = _resolve_idalib_mcp(executable)
    _validate_mcp_executable(resolved)
    command: list[str] = []
    if resolved:
        command = [resolved]
        if transport == "stdio":
            command.append("--stdio")
        else:
            command.extend(["--host", host, "--port", str(port)])
        command.extend(["--max-workers", str(max_workers)])
    package_version = _package_version_for(resolved)
    return McpLaunchPlan(
        transport=transport,
        executable=resolved,
        executable_sha256=_sha256_file(resolved) if resolved else "",
        command=command,
        endpoint=f"http://{host}:{port}/mcp" if transport == "http" else "stdio://local",
        available=bool(resolved),
        isolated_contexts=isolated_contexts,
        max_workers=max_workers,
        package_version=package_version,
    )


class IdalibMcpSupervisor:
    """Supervise only the loopback HTTP form of an allowlisted idalib-mcp."""

    def __init__(self, plan: McpLaunchPlan, log_path: str | Path) -> None:
        if plan.transport != "http":
            raise McpSupervisorError(
                "background supervision is only valid for HTTP transport"
            )
        if not plan.available:
            raise McpSupervisorError("idalib-mcp is not installed or not selected")
        _validate_mcp_executable(plan.executable)
        self.plan = plan
        self.log_path = Path(log_path).resolve()
        self.process: subprocess.Popen[bytes] | None = None
        self._log: IO[bytes] | None = None

    def start(self, *, confirm_sha256: str) -> int:
        if self.process and self.process.poll() is None:
            raise McpSupervisorError("idalib-mcp is already running")
        if confirm_sha256.lower() != self.plan.executable_sha256:
            raise McpSupervisorError(
                "explicit confirmation hash does not match the MCP launch plan"
            )
        if _sha256_file(self.plan.executable) != self.plan.executable_sha256:
            raise McpSupervisorError(
                "idalib-mcp executable changed after the launch plan was created"
            )
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self._log = self.log_path.open("ab")
        creationflags = (
            getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0
        )
        self.process = subprocess.Popen(
            self.plan.command,
            stdin=subprocess.DEVNULL,
            stdout=self._log,
            stderr=subprocess.STDOUT,
            shell=False,
            creationflags=creationflags,
        )
        return self.process.pid

    def stop(self, timeout: float = 10.0) -> None:
        if not self.process:
            return
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        if self._log:
            self._log.close()
        self._log = None
        self.process = None
