from __future__ import annotations

import json
import os
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


MAX_EVENTS = 500
MAX_EVENT_BYTES = 16 * 1024
ALLOWED_VALUE_KEYS = {
    "sample_sha256",
    "declared_ep_rva",
    "declared_ep_va",
    "static_candidate_count",
    "runtime_verified",
    "runtime_oep_va",
    "runtime_oep_rva",
    "dump_file_offset",
    "display_text",
    "provider",
    "broker_id",
    "plan_sha256",
    "network",
    "timeout_seconds",
    "ready_for_broker_submission",
    "task_id",
    "task_status",
}


def event_store_dir() -> Path:
    if os.name == "nt":
        base = Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData/Local")
    else:
        base = Path(os.environ.get("XDG_STATE_HOME") or Path.home() / ".local/state")
    return base / "reverse-engineering-companion" / "oep-events"


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _safe_values(values: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in values.items():
        if key not in ALLOWED_VALUE_KEYS:
            continue
        if isinstance(value, (str, int, float, bool)) or value is None:
            result[key] = value[:512] if isinstance(value, str) else value
    return result


def append_oep_event(
    operation: str,
    description: str,
    status: str,
    values: dict[str, Any],
    *,
    directory: str | Path | None = None,
) -> dict[str, Any]:
    if operation not in {
        "oep_static_candidates", "oep_runtime_plan", "oep_runtime_verify",
        "oep_runtime_start", "oep_runtime_status",
    }:
        raise ValueError("unsupported dashboard operation")
    event_id = str(uuid.uuid4())
    timestamp_utc = _utc_now()
    event = {
        "event_id": event_id,
        "timestamp_utc": timestamp_utc,
        "operation": operation,
        "description": description[:256],
        "status": status[:64],
        "values": _safe_values(values),
    }
    encoded = json.dumps(event, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if len(encoded) > MAX_EVENT_BYTES:
        raise ValueError("dashboard event exceeds its size ceiling")
    root = Path(directory) if directory is not None else event_store_dir()
    root.mkdir(parents=True, exist_ok=True)
    path = root / f"{timestamp_utc.replace(':', '').replace('-', '')}-{event_id}.json"
    fd, temporary = tempfile.mkstemp(prefix="event-", suffix=".tmp", dir=root)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(encoded)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    files = sorted(root.glob("*.json"), key=lambda item: item.name, reverse=True)
    for stale in files[MAX_EVENTS:]:
        try:
            stale.unlink()
        except OSError:
            pass
    return event


def read_oep_events(
    limit: int = 100, *, directory: str | Path | None = None
) -> list[dict[str, Any]]:
    if not 1 <= limit <= MAX_EVENTS:
        raise ValueError(f"limit must be between 1 and {MAX_EVENTS}")
    root = Path(directory) if directory is not None else event_store_dir()
    if not root.is_dir():
        return []
    records: list[dict[str, Any]] = []
    for path in sorted(root.glob("*.json"), key=lambda item: item.name, reverse=True)[:limit]:
        try:
            if path.stat().st_size > MAX_EVENT_BYTES:
                continue
            payload = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(payload, dict) and payload.get("operation") in {
                "oep_static_candidates", "oep_runtime_plan", "oep_runtime_verify"
            }:
                records.append(payload)
        except (OSError, json.JSONDecodeError):
            continue
    return records
