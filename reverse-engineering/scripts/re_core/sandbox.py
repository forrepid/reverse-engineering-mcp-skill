from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from .models import utc_now


APPROVED_PROVIDER_TYPES = {"cape", "drakvuf", "vmray", "internal"}


def create_sandbox_plan(
    sample: str | Path,
    *,
    provider: str,
    timeout_seconds: int = 300,
    network: str = "blocked",
) -> dict[str, Any]:
    provider = provider.lower()
    if provider not in APPROVED_PROVIDER_TYPES:
        raise ValueError(
            "provider must be one of: " + ", ".join(sorted(APPROVED_PROVIDER_TYPES))
        )
    if not 30 <= timeout_seconds <= 3600:
        raise ValueError("timeout must be between 30 and 3600 seconds")
    if network not in {"blocked", "simulated", "restricted"}:
        raise ValueError("network must be blocked, simulated, or restricted")
    path = Path(sample).resolve()
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            size += len(chunk)
            digest.update(chunk)
    return {
        "schema_version": "0.5.0",
        "created_at": utc_now(),
        "status": "not_submitted",
        "provider_type": provider,
        "sample": {
            "path": str(path),
            "size": size,
            "sha256": digest.hexdigest(),
        },
        "policy": {
            "host_execution_forbidden": True,
            "snapshot_required": True,
            "disposable_environment_required": True,
            "timeout_seconds": timeout_seconds,
            "network": network,
            "credentials_in_guest_forbidden": True,
            "shared_clipboard_forbidden": True,
            "shared_folders_read_only_or_disabled": True,
        },
        "capture": [
            "process_tree",
            "file_events",
            "registry_events",
            "network_events",
            "api_trace",
            "memory_indicators",
            "dropped_files",
        ],
        "approval_required": True,
        "note": (
            "This is a plan only. A separately configured, approved broker must "
            "perform submission; no host fallback is implemented."
        ),
    }
