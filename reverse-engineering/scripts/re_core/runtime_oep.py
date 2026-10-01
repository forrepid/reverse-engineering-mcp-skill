from __future__ import annotations

import base64
import hashlib
import json
import re
from pathlib import Path
from typing import Any, cast

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .advanced_pe import _rva_to_file_offset, _validate_file_backed_rva_map
from .analyzers import AnalysisError, parse_pe


MAX_PE_BYTES = 64 * 1024 * 1024
MAX_TRACE_BYTES = 64 * 1024 * 1024
MAX_CONTROL_EVENTS = 500_000


def re_full_sha256(value: str) -> bool:
    return re.fullmatch(r"[0-9a-fA-F]{64}", value) is not None


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _read_limited(path: str | Path, limit: int) -> bytes:
    source = Path(path).expanduser().resolve(strict=True)
    if not source.is_file():
        raise ValueError("evidence input is not a regular file")
    size = source.stat().st_size
    if size > limit:
        raise ValueError(f"evidence input exceeds the configured {limit}-byte limit")
    return source.read_bytes()


def _decode_public_key(data: bytes) -> bytes:
    if len(data) == 32:
        return data
    stripped = data.strip()
    try:
        decoded = bytes.fromhex(stripped.decode("ascii"))
    except (UnicodeDecodeError, ValueError):
        try:
            decoded = base64.b64decode(stripped, validate=True)
        except ValueError as error:
            raise ValueError("broker public key must be raw, 64-character hex, or base64") from error
    if len(decoded) != 32:
        raise ValueError("Ed25519 public key must decode to exactly 32 bytes")
    return decoded


def _json_object(data: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(data)
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise ValueError(f"{label} is not valid UTF-8 JSON") from error
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object")
    return value


def _inconclusive(*reasons: str) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "status": "inconclusive",
        "runtime_verified": False,
        "candidate": None,
        "oep_display": "Runtime OEP: NOT VERIFIED (insufficient or inconclusive runtime evidence)",
        "reasons": list(reasons),
    }


def verify_runtime_oep_evidence(
    sample_path: str | Path,
    plan_path: str | Path,
    trace_path: str | Path,
    dump_path: str | Path,
    attestation_path: str | Path,
    broker_public_key_path: str | Path,
    *,
    trusted_broker_id: str,
    confirm_plan_sha256: str,
    expected_broker_public_key_sha256: str | None = None,
) -> dict[str, Any]:
    """Verify signed, normalized evidence from an externally approved isolated run.

    This function only reads supplied files. It does not submit or execute a sample.
    """
    try:
        sample_data = _read_limited(sample_path, MAX_PE_BYTES)
        plan_data = _read_limited(plan_path, 1024 * 1024)
        trace_data = _read_limited(trace_path, MAX_TRACE_BYTES)
        dump_data = _read_limited(dump_path, MAX_PE_BYTES)
        attestation_data = _read_limited(attestation_path, 1024 * 1024)
        key_data = _read_limited(broker_public_key_path, 4096)
        sample_hash = _digest(sample_data)
        plan_hash = _digest(plan_data)
        trace_hash = _digest(trace_data)
        dump_hash = _digest(dump_data)
        plan = _json_object(plan_data, "approved sandbox plan")
        trace = _json_object(trace_data, "normalized trace")
        attestation = _json_object(attestation_data, "broker attestation")
        sample_pe = parse_pe(sample_data)
        dump_pe = parse_pe(dump_data)
    except (OSError, ValueError, AnalysisError) as error:
        return _inconclusive(str(error))

    if plan_hash.lower() != confirm_plan_sha256.lower():
        return {**_inconclusive("explicitly confirmed plan hash does not match the supplied plan"), "status": "rejected"}
    try:
        public_key_hash = _digest(_decode_public_key(key_data))
    except ValueError as error:
        return {**_inconclusive(str(error)), "status": "rejected"}
    if expected_broker_public_key_sha256 is not None:
        expected_key_hash = expected_broker_public_key_sha256.lower().removeprefix("sha256:")
        if not re_full_sha256(expected_key_hash) or public_key_hash != expected_key_hash:
            return {**_inconclusive("broker public key does not match the operator-pinned SHA-256 digest"), "status": "rejected"}
    if plan.get("approval_required") is not True:
        return {**_inconclusive("plan does not declare an approval gate"), "status": "rejected"}
    policy = plan.get("policy")
    if not isinstance(policy, dict) or any(
        policy.get(key) is not True
        for key in (
            "host_execution_forbidden", "snapshot_required", "disposable_environment_required",
            "credentials_in_guest_forbidden", "shared_clipboard_forbidden",
            "shared_folders_read_only_or_disabled",
        )
    ) or policy.get("network") != "blocked":
        return {**_inconclusive("plan is missing required isolated, snapshot, or zero-egress policy"), "status": "rejected"}
    environment = plan.get("environment")
    limits = plan.get("resource_limits")
    runtime_plan = plan.get("runtime_oep")
    if (
        not isinstance(environment, dict)
        or not isinstance(limits, dict)
        or not isinstance(runtime_plan, dict)
        or runtime_plan.get("ready_for_broker_submission") is not True
        or environment.get("fresh_disposable_clone_required") is not True
        or not environment.get("snapshot_id")
        or not isinstance(environment.get("image_digest"), str)
        or len(environment["image_digest"]) != 64
        or not re_full_sha256(environment["image_digest"])
    ):
        return {**_inconclusive("plan lacks pinned disposable image, clean snapshot, or runtime OEP readiness"), "status": "rejected"}
    if (
        runtime_plan.get("attempts") != 1
        or runtime_plan.get("required_event_loss_count") != 0
        or runtime_plan.get("dump_kind") != "reconstructed_pe"
        or environment.get("provider_type") != plan.get("provider_type")
        or policy.get("timeout_seconds") != limits.get("timeout_seconds")
    ):
        return {**_inconclusive("plan runtime OEP attempt, provider, telemetry, dump, or timeout contract is inconsistent"), "status": "rejected"}
    for limit_name in ("cpu_cores", "timeout_seconds", "memory_mb", "disk_mb", "max_trace_bytes", "max_dump_bytes"):
        if type(limits.get(limit_name)) is not int or limits[limit_name] <= 0:
            return {**_inconclusive(f"plan resource limit {limit_name} is missing or invalid"), "status": "rejected"}
    if (
        limits["cpu_cores"] > 64
        or limits["timeout_seconds"] > 3600
        or limits["memory_mb"] > 262144
        or limits["disk_mb"] > 1048576
        or limits["max_trace_bytes"] > MAX_TRACE_BYTES
        or limits["max_dump_bytes"] > MAX_PE_BYTES
    ):
        return {**_inconclusive("approved plan exceeds verifier resource ceilings"), "status": "rejected"}
    if len(trace_data) > limits["max_trace_bytes"] or len(dump_data) > limits["max_dump_bytes"]:
        return _inconclusive("trace or dump exceeds the exact approved plan quota")
    plan_sample = plan.get("sample")
    if not isinstance(plan_sample, dict) or plan_sample.get("sha256") != sample_hash:
        return {**_inconclusive("plan sample hash does not match the supplied sample"), "status": "rejected"}

    signed_payload = {key: value for key, value in attestation.items() if key != "signature"}
    if attestation.get("schema_version") != "1" or attestation.get("algorithm") != "Ed25519":
        return {**_inconclusive("unsupported broker attestation schema or signature algorithm"), "status": "rejected"}
    if attestation.get("broker_id") != trusted_broker_id:
        return {**_inconclusive("broker identity is not the configured trusted broker"), "status": "rejected"}
    if attestation.get("plan_sha256") != plan_hash or attestation.get("sample_sha256") != sample_hash:
        return {**_inconclusive("attested plan or sample hash does not match"), "status": "rejected"}
    if attestation.get("trace_sha256") != trace_hash or attestation.get("dump_sha256") != dump_hash:
        return {**_inconclusive("trace or dump hash does not match the broker attestation"), "status": "rejected"}
    try:
        signature = base64.b64decode(str(attestation.get("signature", "")), validate=True)
        canonical_payload = json.dumps(
            signed_payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
        Ed25519PublicKey.from_public_bytes(_decode_public_key(key_data)).verify(signature, canonical_payload)
    except (InvalidSignature, ValueError, TypeError) as error:
        return {**_inconclusive(f"broker signature verification failed: {type(error).__name__}"), "status": "rejected"}

    approval = attestation.get("approval")
    if (
        not isinstance(approval, dict)
        or approval.get("approved") is not True
        or approval.get("plan_sha256") != plan_hash
    ):
        return {**_inconclusive("signed broker attestation does not bind an approval to this exact plan"), "status": "rejected"}
    if attestation.get("dump_kind") != "reconstructed_pe":
        return _inconclusive("runtime dump is not a supported reconstructed PE image")

    session_id = attestation.get("session_id")
    if (
        not session_id
        or trace.get("session_id") != session_id
        or trace.get("broker_id") != trusted_broker_id
        or trace.get("sample_sha256") != sample_hash
    ):
        return {**_inconclusive("trace session or sample identity does not match the attestation"), "status": "rejected"}
    if trace.get("plan_sha256") != plan_hash:
        return {**_inconclusive("trace is not bound to the explicitly confirmed plan"), "status": "rejected"}
    if trace.get("complete") is not True or attestation.get("trace_complete") is not True:
        return _inconclusive("trace is incomplete")
    if (
        type(trace.get("event_loss_count")) is not int
        or type(attestation.get("event_loss_count")) is not int
        or trace.get("event_loss_count") != 0
        or attestation.get("event_loss_count") != 0
    ):
        return _inconclusive("telemetry event loss is non-zero or unavailable")
    raw_events = trace.get("events")
    if not isinstance(raw_events, list) or not raw_events or len(raw_events) > MAX_CONTROL_EVENTS:
        return _inconclusive("trace event list is missing or exceeds the event limit")
    if attestation.get("event_count") != len(raw_events):
        return {**_inconclusive("trace event count does not match the signed attestation"), "status": "rejected"}
    if any(not isinstance(event, dict) for event in raw_events):
        return _inconclusive("trace event entries must be objects")
    events = cast(list[dict[str, Any]], raw_events)
    sequences: list[int] = []
    for event in events:
        sequence = event.get("seq")
        if type(sequence) is not int:
            return _inconclusive("trace events do not have integer sequence numbers")
        sequences.append(sequence)
    if sequences != sorted(set(sequences)):
        return _inconclusive("trace events are duplicated or out of sequence")

    candidate_va = attestation.get("candidate_va")
    runtime_base = attestation.get("runtime_image_base")
    image_size = attestation.get("image_size")
    if not all(type(value) is int and value >= 0 for value in (candidate_va, runtime_base, image_size)):
        return _inconclusive("attested candidate address or runtime image range is invalid")
    candidate_va = cast(int, candidate_va)
    runtime_base = cast(int, runtime_base)
    image_size = cast(int, image_size)
    if image_size <= 0 or candidate_va < runtime_base or candidate_va >= runtime_base + image_size:
        return _inconclusive("candidate is outside the attested runtime image range")
    if not _validate_file_backed_rva_map(dump_data, dump_pe):
        return _inconclusive("dump PE section mapping is ambiguous or out of bounds")
    dump_image_size = int(dump_pe.get("size_of_image") or 0)
    if (
        image_size != dump_image_size
        or sample_pe.get("bits") != dump_pe.get("bits")
        or sample_pe.get("machine") != dump_pe.get("machine")
    ):
        return _inconclusive("dump image size or architecture does not match the attested runtime image")
    candidate_rva = candidate_va - runtime_base
    if int(dump_pe["entry_point_rva"]) != candidate_rva:
        return _inconclusive("reconstructed dump AddressOfEntryPoint does not match the executed runtime candidate")
    section = next(
        (
            item for item in dump_pe["sections"]
            if item.virtual_address <= candidate_rva < item.virtual_address + max(item.virtual_size, item.raw_size)
        ),
        None,
    )
    candidate_offset = _rva_to_file_offset(dump_pe, candidate_rva, len(dump_data))
    if section is None or "X" not in section.permissions or candidate_offset is None:
        return _inconclusive("candidate does not map to file-backed executable bytes in the reconstructed dump")

    process_start = next((item for item in events if item.get("type") == "process_start"), None)
    module_map = next((item for item in events if item.get("type") == "module_map" and item.get("image_sha256") == sample_hash), None)
    unpack = next((item for item in events if item.get("type") == "unpack_complete"), None)
    transfer = next(
        (item for item in events if item.get("type") == "control_transfer" and item.get("phase") == "post_unpack" and item.get("to_va") == candidate_va),
        None,
    )
    execution = next(
        (item for item in events if item.get("type") == "instruction" and item.get("address") == candidate_va),
        None,
    )
    executable_mapping = next(
        (
            item for item in events
            if item.get("type") == "memory_map"
            and isinstance(item.get("base"), int)
            and isinstance(item.get("size"), int)
            and cast(int, item.get("base")) <= candidate_va < cast(int, item.get("base")) + cast(int, item.get("size"))
            and cast(int, item.get("base")) < runtime_base + image_size
            and runtime_base <= cast(int, item.get("base")) + cast(int, item.get("size"))
            and "X" in str(item.get("protection", "")).upper()
        ),
        None,
    )
    if not all((process_start, module_map, unpack, transfer, execution, executable_mapping)):
        return _inconclusive("trace lacks process, original-image map, post-unpack transfer, executable mapping, or candidate execution evidence")
    assert process_start is not None
    assert module_map is not None
    assert unpack is not None
    assert transfer is not None
    assert execution is not None
    assert executable_mapping is not None
    if process_start.get("image_sha256") != sample_hash:
        return {**_inconclusive("process-start image hash is not the selected sample"), "status": "rejected"}
    if module_map.get("base") != runtime_base:
        return _inconclusive("original sample image map base does not match the attested runtime base")
    if module_map.get("size") != image_size:
        return _inconclusive("original sample image map size does not match the attested runtime image")
    unpack_base = unpack.get("base")
    unpack_size = unpack.get("size")
    if not isinstance(unpack_base, int) or not isinstance(unpack_size, int):
        return _inconclusive("unpack-complete event has an invalid image range")
    if unpack_base != runtime_base or unpack_size != image_size:
        return _inconclusive("unpack-complete event does not match the attested runtime image range")
    if not (unpack_base <= candidate_va < unpack_base + unpack_size):
        return _inconclusive("unpack-complete event does not cover the candidate address")
    if not (process_start["seq"] <= module_map["seq"] <= unpack["seq"] < transfer["seq"] < execution["seq"]):
        return _inconclusive("runtime event order does not establish post-unpack transfer before candidate execution")
    if executable_mapping["seq"] > execution["seq"]:
        return _inconclusive("executable memory mapping was observed only after candidate execution")
    if (
        not isinstance(transfer.get("from_va"), int)
        or "X" not in str(transfer.get("target_protection", "")).upper()
    ):
        return _inconclusive("control-transfer source or executable target protection is missing")

    return {
        "schema_version": "1.0",
        "status": "verified",
        "runtime_verified": True,
        "sample_sha256": sample_hash,
        "plan_sha256": plan_hash,
        "session_id": session_id,
        "broker_id": trusted_broker_id,
        "broker_public_key_sha256": _digest(_decode_public_key(key_data)),
        "trace_sha256": trace_hash,
        "dump_sha256": dump_hash,
        "sandbox_image_sha256": environment["image_digest"],
        "snapshot_id": environment["snapshot_id"],
        "declared_entry_point_rva": int(sample_pe["entry_point_rva"]),
        "candidate": {
            "va": candidate_va,
            "rva": candidate_rva,
            "dump_file_offset": candidate_offset,
            "section": section.name,
            "evidence": [
                "Ed25519 broker attestation verified against the configured broker key",
                "approved plan hash, sample hash, trace hash, and dump hash match",
                "complete trace has zero reported event loss",
                "post-unpack control transfer is followed by instruction execution at the candidate",
                "candidate maps to file-backed executable bytes in the reconstructed PE dump",
            "reconstructed PE AddressOfEntryPoint matches the transferred-to and executed RVA",
            ],
        },
        "oep_display": (
            f"Runtime OEP: VERIFIED — VA 0x{candidate_va:X} / RVA 0x{candidate_rva:X} "
            f"(dump file offset 0x{candidate_offset:X})"
        ),
        "limitations": [
            "This result trusts the configured broker and its sensor/normalizer implementation.",
            "The verifier imports evidence only; it does not submit or execute the sample.",
            "A broker signature authenticates the evidence bundle, not the broker's correctness.",
            "Full relocation/import reconstruction quality scoring is not implemented in this verifier slice.",
        ],
    }
