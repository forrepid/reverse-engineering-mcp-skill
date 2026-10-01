from __future__ import annotations

import hashlib
import re
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
    image_digest: str | None = None,
    snapshot_id: str | None = None,
    cpu_cores: int = 2,
    memory_mb: int = 2048,
    disk_mb: int = 4096,
    max_trace_bytes: int = 32 * 1024 * 1024,
    max_dump_bytes: int = 64 * 1024 * 1024,
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
    if image_digest is not None and not re.fullmatch(r"(?:sha256:)?[0-9a-fA-F]{64}", image_digest):
        raise ValueError("image_digest must be a SHA-256 hex digest, optionally prefixed with sha256:")
    if snapshot_id is not None and (not snapshot_id.strip() or len(snapshot_id) > 256):
        raise ValueError("snapshot_id must contain 1 to 256 non-whitespace characters")
    if not 1 <= cpu_cores <= 64:
        raise ValueError("cpu_cores must be between 1 and 64")
    if not 256 <= memory_mb <= 262144:
        raise ValueError("memory_mb must be between 256 and 262144")
    if not 1024 <= disk_mb <= 1048576:
        raise ValueError("disk_mb must be between 1024 and 1048576")
    if not 1024 * 1024 <= max_trace_bytes <= 1024 * 1024 * 1024:
        raise ValueError("max_trace_bytes must be between 1 MiB and 1 GiB")
    if not 1024 * 1024 <= max_dump_bytes <= 512 * 1024 * 1024:
        raise ValueError("max_dump_bytes must be between 1 MiB and 512 MiB")
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
        "status": "plan_only",
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
        "environment": {
            "provider_type": provider,
            "image_digest": image_digest.lower().removeprefix("sha256:") if image_digest else None,
            "snapshot_id": snapshot_id,
            "fresh_disposable_clone_required": True,
        },
        "resource_limits": {
            "cpu_cores": cpu_cores,
            "timeout_seconds": timeout_seconds,
            "memory_mb": memory_mb,
            "disk_mb": disk_mb,
            "max_trace_bytes": max_trace_bytes,
            "max_dump_bytes": max_dump_bytes,
        },
        "runtime_oep": {
            "ready_for_broker_submission": bool(
                image_digest and snapshot_id and network == "blocked"
            ),
            "attempts": 1,
            "required_events": [
                "process_start", "module_map", "memory_map", "unpack_complete",
                "control_transfer", "instruction",
            ],
            "required_event_loss_count": 0,
            "dump_kind": "reconstructed_pe",
            "display_label": "Runtime OEP",
            "display_value": None,
            "display_status": "not_verified",
        },
        "broker_capture_contract": {
            "status": "not_configured",
            "adapter": None,
            "continuous_capture": False,
            "required_outputs": ["normalized_trace.json", "reconstructed_pe_dump", "ed25519_attestation.json"],
            "required_signing": "Ed25519; private key remains in broker/HSM",
            "submission_enabled": False,
            "note": "No broker endpoint/identity/signing key is configured. This plan is not submitted; broker capture is unavailable.",
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
            "This is a plan only. No broker adapter is configured; the sample is not submitted and no host fallback is implemented."
        ),
    }
