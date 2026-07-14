from __future__ import annotations

import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Callable, Protocol
from urllib.parse import urlencode


class IdaLiveError(RuntimeError):
    """Raised when a live IDA request cannot meet the evidence contract."""


class ToolCaller(Protocol):
    def __call__(self, name: str, arguments: dict[str, Any]) -> Any: ...


class ResourceReader(Protocol):
    def __call__(self, uri: str) -> Any: ...


@dataclass(frozen=True)
class ContextRequest:
    key: str
    tool: str
    arguments: dict[str, Any]
    required: bool = False


def _canonical_address(value: str | int) -> str:
    if isinstance(value, int):
        address = value
    else:
        address = int(value.strip(), 0)
    if address < 0:
        raise ValueError("address cannot be negative")
    return f"0x{address:X}"


def _extract_items(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if isinstance(payload, dict):
        for key in ("sessions", "items", "databases", "result"):
            candidate = payload.get(key)
            if isinstance(candidate, list):
                return [item for item in candidate if isinstance(item, dict)]
        if any(key in payload for key in ("session_id", "database", "backend")):
            return [payload]
    return []


def attach_active_idb(
    call_tool: ToolCaller,
    *,
    expected_path: str | Path | None = None,
    prefer_gui: bool = True,
    adopt_discovered: bool = False,
) -> dict[str, Any]:
    errors: list[str] = []
    sessions: list[dict[str, Any]] = []
    used_tool = ""
    for tool in ("idb_list", "idalib_list"):
        try:
            candidate = call_tool(tool, {})
            candidate_sessions = _extract_items(candidate)
            if candidate_sessions:
                sessions = candidate_sessions
                used_tool = tool
                break
            errors.append(f"{tool}: no sessions in response")
        except Exception as error:
            errors.append(f"{tool}: {error}")
    if not used_tool:
        raise IdaLiveError("session discovery failed: " + "; ".join(errors))
    if not sessions:
        raise IdaLiveError("no IDA/idalib database session was reported")

    expected = Path(expected_path).resolve() if expected_path else None

    def rank(session: dict[str, Any]) -> tuple[int, int, int]:
        backend = str(session.get("backend", "")).lower()
        return (
            int(bool(session.get("is_current_context"))),
            int(bool(session.get("is_active"))),
            int(prefer_gui and backend == "gui"),
        )

    matching = sessions
    if expected:
        matching = []
        for session in sessions:
            candidate = next(
                (
                    session.get(key)
                    for key in ("input_path", "path", "database_path", "file")
                    if session.get(key)
                ),
                None,
            )
            if candidate and Path(str(candidate)).resolve() == expected:
                matching.append(session)
        if not matching:
            raise IdaLiveError("no live session matches the expected database path")
    selected = max(matching, key=rank)
    session_id = selected.get("session_id") or selected.get("database") or selected.get(
        "id"
    )
    if not session_id and adopt_discovered:
        input_path = selected.get("input_path") or selected.get("path")
        if not input_path:
            raise IdaLiveError("discovered IDA session has no path for adoption")
        backend = str(selected.get("backend", "")).lower()
        mode = "prefer_gui" if prefer_gui and backend == "gui" else "prefer_headless"
        adopted = call_tool(
            "idb_open",
            {
                "input_path": str(input_path),
                "mode": mode,
                "run_auto_analysis": True,
                "build_caches": True,
                "init_hexrays": True,
            },
        )
        if isinstance(adopted, dict) and isinstance(adopted.get("session"), dict):
            selected = adopted["session"]
            session_id = selected.get("session_id")
            used_tool = f"{used_tool}+idb_open"
    if not session_id:
        raise IdaLiveError(
            "selected IDA instance is discovered but not adopted; call with "
            "adopt_discovered=True after reviewing the target path"
        )
    return {
        "session_id": str(session_id),
        "backend": selected.get("backend", "unknown"),
        "is_active": bool(selected.get("is_active")),
        "is_current_context": bool(selected.get("is_current_context")),
        "discovery_tool": used_tool,
        "session": selected,
        "read_only_default": True,
    }


def wait_for_autoanalysis(
    status_reader: Callable[[], dict[str, Any]],
    *,
    timeout: float = 300.0,
    interval: float = 1.0,
) -> dict[str, Any]:
    if not 0.05 <= interval <= 30:
        raise ValueError("interval must be between 0.05 and 30 seconds")
    if not 0.1 <= timeout <= 3600:
        raise ValueError("timeout must be between 0.1 and 3600 seconds")
    started = time.monotonic()
    polls = 0
    last: dict[str, Any] = {}
    while time.monotonic() - started <= timeout:
        last = status_reader()
        polls += 1
        if not isinstance(last, dict):
            raise IdaLiveError("auto-analysis status must be an object")
        if last.get("error"):
            raise IdaLiveError(f"auto-analysis failed: {last['error']}")
        state = str(last.get("state", "")).lower()
        ready = bool(
            last.get("ready")
            or last.get("auto_analysis_complete")
            or ("is_analyzing" in last and last.get("is_analyzing") is False)
            or state in {"complete", "completed", "idle", "finished"}
        )
        if ready:
            return {
                "ready": True,
                "polls": polls,
                "elapsed_seconds": round(time.monotonic() - started, 3),
                "status": last,
            }
        time.sleep(interval)
    raise IdaLiveError(
        f"auto-analysis did not complete within {timeout}s; last status={last}"
    )


def build_context_requests(
    *,
    database: str,
    address: str | int,
    byte_count: int = 64,
) -> list[ContextRequest]:
    if not database.strip():
        raise ValueError("database session identifier is required")
    if not 1 <= byte_count <= 4096:
        raise ValueError("byte_count must be between 1 and 4096")
    canonical = _canonical_address(address)
    shared = {"database": database}
    return [
        ContextRequest(
            "function",
            "lookup_funcs",
            {**shared, "queries": [canonical]},
            required=True,
        ),
        ContextRequest(
            "bytes",
            "get_bytes",
            {**shared, "addrs": [{"addr": canonical, "size": byte_count}]},
            required=True,
        ),
        ContextRequest(
            "disassembly",
            "disasm",
            {**shared, "addr": canonical},
        ),
        ContextRequest(
            "pseudocode",
            "decompile",
            {**shared, "addr": canonical},
        ),
        ContextRequest(
            "xrefs_to",
            "xrefs_to",
            {**shared, "addrs": [canonical]},
        ),
        ContextRequest(
            "callees",
            "callees",
            {**shared, "addrs": [canonical]},
        ),
    ]


def collect_current_context(
    call_tool: ToolCaller,
    *,
    database: str,
    address: str | int | None = None,
    read_resource: ResourceReader | None = None,
    byte_count: int = 64,
) -> dict[str, Any]:
    cursor_payload: Any = None
    if address is None:
        if read_resource is None:
            raise IdaLiveError("address or ida://cursor resource access is required")
        cursor_payload = read_resource("ida://cursor")
        if isinstance(cursor_payload, dict):
            address = next(
                (
                    cursor_payload.get(key)
                    for key in ("address", "ea", "addr", "value")
                    if cursor_payload.get(key) is not None
                ),
                None,
            )
        if address is None:
            raise IdaLiveError("cursor resource did not include an address")
    canonical = _canonical_address(address)
    results: dict[str, Any] = {}
    errors: list[dict[str, Any]] = []
    for request in build_context_requests(
        database=database,
        address=canonical,
        byte_count=byte_count,
    ):
        try:
            results[request.key] = call_tool(request.tool, request.arguments)
        except Exception as error:
            errors.append(
                {
                    "key": request.key,
                    "tool": request.tool,
                    "required": request.required,
                    "error": str(error),
                }
            )
    if any(item["required"] for item in errors):
        raise IdaLiveError(f"required context requests failed: {errors}")
    return {
        "schema_version": "0.5.0",
        "database": database,
        "address": canonical,
        "cursor": cursor_payload,
        "evidence": results,
        "errors": errors,
        "untrusted_binary_content": True,
        "mutation_performed": False,
    }


def create_project_deeplink(
    *,
    database: str,
    address: str | int,
    view: str = "disassembly",
) -> str:
    if view not in {"disassembly", "pseudocode", "hex", "graph"}:
        raise ValueError("unsupported IDB view")
    query = urlencode(
        {
            "database": database,
            "address": _canonical_address(address),
            "view": view,
        }
    )
    return f"re-idb://open?{query}"


def requests_to_dict(requests: list[ContextRequest]) -> list[dict[str, Any]]:
    return [asdict(request) for request in requests]
