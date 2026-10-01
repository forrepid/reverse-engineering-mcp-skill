"""Narrow CAPEv2 REST adapter. Submission is explicit and plan-hash gated."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

import requests  # type: ignore[import-untyped]

from .broker_config import BrokerConfig

MAX_SAMPLE_BYTES = 512 * 1024 * 1024
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
TASK_ID = re.compile(r"^[0-9]{1,20}$")


class CapeBackendError(RuntimeError):
    """CAPE endpoint or request did not satisfy the adapter contract."""


def _api_url(config: BrokerConfig, suffix: str) -> str:
    if config.provider != "cape" or not config.base_url:
        raise CapeBackendError("a configured CAPEv2 provider is required")
    base = config.base_url.rstrip("/")
    return f"{base}/{suffix.lstrip('/')}"


def _session(config: BrokerConfig) -> requests.Session:
    session = requests.Session()
    session.headers.update({"Accept": "application/json"})
    if config.token:
        session.headers["Authorization"] = f"Token {config.token}"
    session.trust_env = False
    return session


def _json(response: requests.Response) -> dict[str, Any]:
    if len(response.content) > MAX_RESPONSE_BYTES:
        raise CapeBackendError("CAPE response exceeded the configured response ceiling")
    response.raise_for_status()
    try:
        value = response.json()
    except (requests.JSONDecodeError, ValueError) as error:
        raise CapeBackendError("CAPE returned a non-JSON response") from error
    if not isinstance(value, dict):
        raise CapeBackendError("CAPE response must be a JSON object")
    return value


def cape_status(config: BrokerConfig, *, timeout_seconds: float = 5.0) -> dict[str, Any]:
    """Return a bounded status summary; no task is created."""
    try:
        with _session(config) as session:
            response = session.get(
                _api_url(config, "cuckoo/status/"), timeout=timeout_seconds, stream=True
            )
            try:
                body = response.raw.read(MAX_RESPONSE_BYTES + 1)
                if len(body) > MAX_RESPONSE_BYTES:
                    raise CapeBackendError("CAPE status response is too large")
                response._content = body
                payload = _json(response)
            finally:
                response.close()
    except requests.RequestException as error:
        raise CapeBackendError(f"CAPE status request failed: {type(error).__name__}") from error
    data = payload.get("data", payload)
    if not isinstance(data, dict):
        raise CapeBackendError("CAPE status payload is not an object")
    return {
        "status": "reachable",
        "provider": "cape",
        "broker_id": config.broker_id,
        "version": data.get("version"),
        "tasks": data.get("tasks") if isinstance(data.get("tasks"), dict) else None,
        "capture_and_oep_signing_verified": False,
    }


def submit_approved_plan(
    config: BrokerConfig,
    sample_path: str | Path,
    plan_path: str | Path,
    *,
    confirm_plan_sha256: str,
    cape_machine: str,
    mapped_image_digest: str,
    mapped_snapshot_id: str,
    network_profile: str,
    timeout_seconds: float = 15.0,
) -> dict[str, Any]:
    """Submit one explicitly approved plan to CAPE; it does not verify runtime OEP.

    The operator-owned mappings bind CAPE machine/profile metadata to the plan.
    CAPE must still enforce the actual network, image, snapshot and resource policy.
    """
    if not config.configured or config.provider != "cape":
        raise CapeBackendError("CAPE must be configured with operator-pinned broker identity and key")
    sample = Path(sample_path).resolve(strict=True)
    plan_file = Path(plan_path).resolve(strict=True)
    if not sample.is_file() or not plan_file.is_file():
        raise CapeBackendError("sample and plan must be regular files")
    if sample.stat().st_size > MAX_SAMPLE_BYTES:
        raise CapeBackendError("sample exceeds the CAPE adapter size ceiling")
    plan_bytes = plan_file.read_bytes()
    plan_hash = hashlib.sha256(plan_bytes).hexdigest()
    if not re.fullmatch(r"[0-9a-fA-F]{64}", confirm_plan_sha256) or plan_hash != confirm_plan_sha256.lower():
        raise CapeBackendError("explicit plan SHA-256 confirmation does not match the plan")
    try:
        plan = json.loads(plan_bytes)
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise CapeBackendError("approved plan must be valid UTF-8 JSON") from error
    if not isinstance(plan, dict):
        raise CapeBackendError("approved plan must be a JSON object")
    sample_hash = hashlib.sha256()
    with sample.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            sample_hash.update(chunk)
    runtime = plan.get("runtime_oep")
    environment = plan.get("environment")
    policy = plan.get("policy")
    planned_sample = plan.get("sample")
    limits = plan.get("resource_limits")
    if (
        plan.get("approval_required") is not True
        or plan.get("provider_type") != "cape"
        or not isinstance(runtime, dict)
        or runtime.get("ready_for_broker_submission") is not True
        or not isinstance(policy, dict)
        or policy.get("network") != "blocked"
        or any(
            policy.get(key) is not True
            for key in (
                "host_execution_forbidden", "snapshot_required",
                "disposable_environment_required", "credentials_in_guest_forbidden",
                "shared_clipboard_forbidden", "shared_folders_read_only_or_disabled",
            )
        )
        or not isinstance(environment, dict)
        or environment.get("image_digest") != mapped_image_digest.lower().removeprefix("sha256:")
        or environment.get("snapshot_id") != mapped_snapshot_id
        or not isinstance(planned_sample, dict)
        or planned_sample.get("sha256") != sample_hash.hexdigest()
        or planned_sample.get("size") != sample.stat().st_size
        or not isinstance(limits, dict)
        or runtime.get("attempts") != 1
        or runtime.get("required_event_loss_count") != 0
        or runtime.get("dump_kind") != "reconstructed_pe"
        or policy.get("timeout_seconds") != limits.get("timeout_seconds")
    ):
        raise CapeBackendError("plan, sample, isolation mapping, or OEP readiness did not match")
    if not re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", cape_machine):
        raise CapeBackendError("CAPE machine label is invalid")
    if network_profile != "blocked":
        raise CapeBackendError("CAPE network profile must be explicitly mapped to blocked")
    task_timeout = limits.get("timeout_seconds")
    if type(task_timeout) is not int or not 30 <= task_timeout <= 3600:
        raise CapeBackendError("plan task timeout is missing or outside the adapter bounds")

    with _session(config) as session, sample.open("rb") as stream:
        response = session.post(
            _api_url(config, "tasks/create/file/"),
            files={"file": (sample.name, stream, "application/octet-stream")},
            data={
                "machine": cape_machine,
                "timeout": str(task_timeout),
                "enforce_timeout": "1",
                "route": "none",
                "custom": f"re-companion-plan-sha256={plan_hash};broker-id={config.broker_id}",
            },
            timeout=timeout_seconds,
            allow_redirects=False,
        )
        payload = _json(response)
    data = payload.get("data", payload)
    task_id = data.get("task_id") if isinstance(data, dict) else None
    if task_id is None and isinstance(data, dict):
        ids = data.get("task_ids")
        task_id = ids[0] if isinstance(ids, list) and len(ids) == 1 else None
    if not isinstance(task_id, (str, int)) or not TASK_ID.fullmatch(str(task_id)):
        raise CapeBackendError("CAPE accepted a response without one unambiguous task ID")
    return {
        "status": "submitted",
        "provider": "cape",
        "broker_id": config.broker_id,
        "task_id": str(task_id),
        "plan_sha256": plan_hash,
        "sample_sha256": sample_hash.hexdigest(),
        "runtime_oep": "NOT VERIFIED",
        "evidence_contract": "CAPE task submission does not provide the signed normalized trace/dump contract",
        "task_status_url": _api_url(config, f"tasks/view/{task_id}/"),
    }


def get_task_status(
    config: BrokerConfig, task_id: str, *, timeout_seconds: float = 5.0
) -> dict[str, Any]:
    """Read one known CAPE task status; no task mutations."""
    if not TASK_ID.fullmatch(task_id):
        raise CapeBackendError("task_id must be a decimal CAPE task identifier")
    with _session(config) as session:
        response = session.get(
            _api_url(config, f"tasks/view/{task_id}/"),
            timeout=timeout_seconds,
            stream=True,
        )
        try:
            body = response.raw.read(MAX_RESPONSE_BYTES + 1)
            if len(body) > MAX_RESPONSE_BYTES:
                raise CapeBackendError("CAPE task response is too large")
            response._content = body
            payload = _json(response)
        finally:
            response.close()
    data = payload.get("data", payload)
    task = data.get("task", data) if isinstance(data, dict) else None
    if not isinstance(task, dict) or str(task.get("id", task_id)) != task_id:
        raise CapeBackendError("CAPE task status response does not match the requested ID")
    return {
        "status": str(task.get("status", "unknown")),
        "provider": "cape",
        "broker_id": config.broker_id,
        "task_id": task_id,
        "completed_on": task.get("completed_on"),
        "runtime_oep": "NOT VERIFIED",
        "evidence_contract": "task state only; signed runtime OEP evidence has not been imported or verified",
    }
