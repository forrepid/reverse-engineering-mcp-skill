from __future__ import annotations

import hashlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import requests

from re_core.broker_config import BrokerConfigError, load_broker_config
from re_core.cape_backend import CapeBackendError, cape_status, get_task_status, submit_approved_plan


class _FakeSession:
    def __init__(self, response: requests.Response) -> None:
        self.headers: dict[str, str] = {}
        self.trust_env = True
        self.response = response
        self.calls: list[tuple[str, str, dict[str, object]]] = []

    def __enter__(self) -> _FakeSession:
        return self

    def __exit__(self, *_: object) -> None:
        return None

    def post(self, url: str, **kwargs: object) -> requests.Response:
        self.calls.append(("POST", url, kwargs))
        return self.response

    def get(self, url: str, **kwargs: object) -> requests.Response:
        self.calls.append(("GET", url, kwargs))
        return self.response


def _response(payload: dict[str, object], status: int = 200) -> requests.Response:
    response = requests.Response()
    response.status_code = status
    response._content = json.dumps(payload).encode()
    response.raw = io.BytesIO(response._content)
    response.headers["Content-Type"] = "application/json"
    return response


def _config(submission: bool = True):
    values = {
        "RE_BROKER_PROVIDER": "cape",
        "RE_BROKER_BASE_URL": "http://127.0.0.1:8000/apiv2",
        "RE_BROKER_ID": "lab-cape-01",
        "RE_BROKER_PUBLIC_KEY": "ab" * 32,
    }
    if submission:
        values.update({
            "RE_BROKER_SUBMISSION_ENABLED": "true",
            "RE_BROKER_CAPE_MACHINE": "win10-x64",
            "RE_BROKER_CAPE_IMAGE_DIGEST": "cd" * 32,
            "RE_BROKER_CAPE_SNAPSHOT_ID": "clean-win10",
            "RE_BROKER_CAPE_NETWORK_PROFILE": "blocked",
        })
    return load_broker_config(values)


class CapeBackendTests(unittest.TestCase):
    def test_cape_health_uses_status_get_without_claiming_identity_or_oep(self) -> None:
        fake = _FakeSession(_response({"data": {"version": "test", "tasks": {"pending": 0}}}))
        with patch("re_core.cape_backend.requests.Session", return_value=fake):
            result = cape_status(_config(submission=False))
        self.assertEqual(fake.calls[0][0:2], ("GET", "http://127.0.0.1:8000/apiv2/cuckoo/status/"))
        self.assertEqual(result["status"], "reachable")
        self.assertFalse(result["capture_and_oep_signing_verified"])

    def test_submission_config_requires_explicit_operator_mappings(self) -> None:
        with self.assertRaises(BrokerConfigError):
            load_broker_config({
                "RE_BROKER_PROVIDER": "cape",
                "RE_BROKER_BASE_URL": "http://127.0.0.1:8000/apiv2",
                "RE_BROKER_ID": "lab-cape-01",
                "RE_BROKER_PUBLIC_KEY": "ab" * 32,
                "RE_BROKER_SUBMISSION_ENABLED": "true",
            })
        self.assertFalse(_config(submission=False).submission_enabled)

    def test_mcp_registers_start_only_after_submission_opt_in(self) -> None:
        import re_mcp_server

        with patch("re_mcp_server.load_broker_config", return_value=_config()):
            server = re_mcp_server.build_server()
            status = re_mcp_server.server_status()
        names = {tool.name for tool in server._tool_manager.list_tools()}
        self.assertIn("oep_runtime_start", names)
        self.assertIn("oep_runtime_status", names)
        self.assertEqual(status["tool_count"], len(names))
        self.assertTrue(status["sample_submission_tool_exposed"])

    def test_submit_requires_exact_confirmation_and_plan_sample_mapping(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            sample = Path(directory) / "fixture.exe"
            sample.write_bytes(b"authorized test fixture")
            sample_sha = hashlib.sha256(sample.read_bytes()).hexdigest()
            plan = {
                "approval_required": True,
                "provider_type": "cape",
                "sample": {"sha256": sample_sha},
                "policy": {
                    "network": "blocked", "timeout_seconds": 300,
                    "host_execution_forbidden": True, "snapshot_required": True,
                    "disposable_environment_required": True, "credentials_in_guest_forbidden": True,
                    "shared_clipboard_forbidden": True,
                    "shared_folders_read_only_or_disabled": True,
                },
                "environment": {"image_digest": "cd" * 32, "snapshot_id": "clean-win10"},
                "resource_limits": {"timeout_seconds": 300},
                "runtime_oep": {
                    "ready_for_broker_submission": True, "attempts": 1,
                    "required_event_loss_count": 0, "dump_kind": "reconstructed_pe",
                },
            }
            plan_path = Path(directory) / "plan.json"
            plan_bytes = json.dumps(plan, sort_keys=True).encode()
            plan_path.write_bytes(plan_bytes)
            with self.assertRaisesRegex(CapeBackendError, "confirmation"):
                submit_approved_plan(
                    _config(), sample, plan_path,
                    confirm_plan_sha256="0" * 64,
                    cape_machine="win10-x64", mapped_image_digest="cd" * 32,
                    mapped_snapshot_id="clean-win10", network_profile="blocked",
                )

    def test_submission_uses_cape_api_and_never_claims_runtime_oep(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            sample = Path(directory) / "fixture.exe"
            sample.write_bytes(b"authorized test fixture")
            plan = {
                "approval_required": True,
                "provider_type": "cape",
                "sample": {
                    "sha256": hashlib.sha256(sample.read_bytes()).hexdigest(),
                    "size": sample.stat().st_size,
                },
                "policy": {
                    "network": "blocked", "timeout_seconds": 300,
                    "host_execution_forbidden": True, "snapshot_required": True,
                    "disposable_environment_required": True, "credentials_in_guest_forbidden": True,
                    "shared_clipboard_forbidden": True,
                    "shared_folders_read_only_or_disabled": True,
                },
                "environment": {"image_digest": "cd" * 32, "snapshot_id": "clean-win10"},
                "resource_limits": {"timeout_seconds": 300},
                "runtime_oep": {
                    "ready_for_broker_submission": True, "attempts": 1,
                    "required_event_loss_count": 0, "dump_kind": "reconstructed_pe",
                },
            }
            plan_path = Path(directory) / "plan.json"
            plan_bytes = json.dumps(plan, sort_keys=True).encode()
            plan_path.write_bytes(plan_bytes)
            digest = hashlib.sha256(plan_bytes).hexdigest()
            fake = _FakeSession(_response({"data": {"task_id": 73}}))
            with patch("re_core.cape_backend.requests.Session", return_value=fake):
                result = submit_approved_plan(
                    _config(), sample, plan_path,
                    confirm_plan_sha256=digest,
                    cape_machine="win10-x64", mapped_image_digest="cd" * 32,
                    mapped_snapshot_id="clean-win10", network_profile="blocked",
                )
            self.assertEqual(fake.calls[0][0:2], ("POST", "http://127.0.0.1:8000/apiv2/tasks/create/file/"))
            self.assertEqual(result["task_id"], "73")
            self.assertEqual(result["runtime_oep"], "NOT VERIFIED")

    def test_task_status_uses_read_only_endpoint(self) -> None:
        fake = _FakeSession(_response({"data": {"task": {"id": 73, "status": "reported"}}}))
        with patch("re_core.cape_backend.requests.Session", return_value=fake):
            result = get_task_status(_config(), "73")
        self.assertEqual(result["status"], "reported")
        self.assertEqual(fake.calls[0][0], "GET")
        with self.assertRaises(CapeBackendError):
            get_task_status(_config(), "73/../../tasks/delete/1")


if __name__ == "__main__":
    unittest.main()
