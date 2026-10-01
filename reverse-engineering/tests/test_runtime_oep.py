from __future__ import annotations

import base64
import hashlib
import json
import sys
import struct
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

# ruff: noqa: E402 -- tests add the sibling scripts directory before imports.
from test_core import build_test_pe

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from re_core.runtime_oep import verify_runtime_oep_evidence


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


class RuntimeOepVerificationTests(unittest.TestCase):
    def _bundle(
        self,
        root: Path,
        *,
        event_loss_count: int = 0,
        omit_transfer: bool = False,
        dump_entry_rva: int = 0x1000,
    ) -> dict[str, Path | str]:
        sample = root / "sample.exe"
        dump = root / "reconstructed.exe"
        plan_path = root / "approved-plan.json"
        trace_path = root / "trace.json"
        attestation_path = root / "attestation.json"
        key_path = root / "broker.pub"
        sample_data = build_test_pe()
        sample.write_bytes(sample_data)
        dump_data = bytearray(sample_data)
        struct.pack_into("<I", dump_data, 0x98 + 16, dump_entry_rva)
        dump.write_bytes(dump_data)
        sample_hash = hashlib.sha256(sample_data).hexdigest()
        plan = {
            "approval_required": True,
            "provider_type": "internal",
            "sample": {"sha256": sample_hash},
            "policy": {
                "host_execution_forbidden": True,
                "snapshot_required": True,
                "disposable_environment_required": True,
                "credentials_in_guest_forbidden": True,
                "shared_clipboard_forbidden": True,
                "shared_folders_read_only_or_disabled": True,
                "timeout_seconds": 300,
                "network": "blocked",
            },
            "environment": {
                "provider_type": "internal",
                "image_digest": "a" * 64,
                "snapshot_id": "clean-snapshot-01",
                "fresh_disposable_clone_required": True,
            },
            "resource_limits": {
                "cpu_cores": 2,
                "timeout_seconds": 300,
                "memory_mb": 2048,
                "disk_mb": 4096,
                "max_trace_bytes": 32 * 1024 * 1024,
                "max_dump_bytes": 64 * 1024 * 1024,
            },
            "runtime_oep": {
                "ready_for_broker_submission": True,
                "attempts": 1,
                "required_event_loss_count": 0,
                "dump_kind": "reconstructed_pe",
            },
        }
        plan_data = _canonical(plan)
        plan_path.write_bytes(plan_data)
        plan_hash = hashlib.sha256(plan_data).hexdigest()
        runtime_base = 0x10000000
        candidate_va = runtime_base + 0x1000
        events = [
            {"seq": 1, "type": "process_start", "image_sha256": sample_hash},
            {"seq": 2, "type": "module_map", "image_sha256": sample_hash, "base": runtime_base, "size": 0x3000},
            {"seq": 3, "type": "unpack_complete", "base": runtime_base, "size": 0x3000},
        ]
        if not omit_transfer:
            events.append({"seq": 4, "type": "control_transfer", "phase": "post_unpack", "from_va": runtime_base + 0x1100, "to_va": candidate_va, "target_protection": "RX"})
            events.append({"seq": 5, "type": "memory_map", "base": runtime_base, "size": 0x3000, "protection": "RX"})
            events.append({"seq": 6, "type": "instruction", "address": candidate_va})
        else:
            events.append({"seq": 5, "type": "memory_map", "base": runtime_base, "size": 0x3000, "protection": "RX"})
            events.append({"seq": 6, "type": "instruction", "address": candidate_va})
        trace = {
            "broker_id": "lab-broker-01",
            "session_id": "session-test-01",
            "sample_sha256": sample_hash,
            "plan_sha256": plan_hash,
            "complete": True,
            "event_loss_count": event_loss_count,
            "events": events,
        }
        trace_data = _canonical(trace)
        trace_path.write_bytes(trace_data)
        dump_hash = hashlib.sha256(dump_data).hexdigest()
        private_key = Ed25519PrivateKey.generate()
        key_path.write_bytes(
            private_key.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
        )
        attestation: dict[str, object] = {
            "schema_version": "1",
            "algorithm": "Ed25519",
            "broker_id": "lab-broker-01",
            "session_id": "session-test-01",
            "approval": {"approved": True, "plan_sha256": plan_hash},
            "plan_sha256": plan_hash,
            "sample_sha256": sample_hash,
            "trace_sha256": hashlib.sha256(trace_data).hexdigest(),
            "dump_sha256": dump_hash,
            "dump_kind": "reconstructed_pe",
            "trace_complete": True,
            "event_loss_count": event_loss_count,
            "event_count": len(events),
            "runtime_image_base": runtime_base,
            "image_size": 0x3000,
            "candidate_va": candidate_va,
        }
        attestation["signature"] = base64.b64encode(private_key.sign(_canonical(attestation))).decode()
        attestation_path.write_bytes(_canonical(attestation))
        return {
            "sample": sample,
            "dump": dump,
            "plan": plan_path,
            "trace": trace_path,
            "attestation": attestation_path,
            "key": key_path,
            "plan_hash": plan_hash,
        }

    def _verify(self, bundle: dict[str, Path | str], *, plan_hash: str | None = None) -> dict[str, object]:
        return verify_runtime_oep_evidence(
            bundle["sample"], bundle["plan"], bundle["trace"], bundle["dump"],
            bundle["attestation"], bundle["key"],
            trusted_broker_id="lab-broker-01",
            confirm_plan_sha256=plan_hash or str(bundle["plan_hash"]),
        )

    def test_verifies_complete_signed_isolated_trace_and_dump(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            result = self._verify(self._bundle(Path(temporary)))
        self.assertEqual(result["status"], "verified")
        self.assertTrue(result["runtime_verified"])
        self.assertEqual(result["candidate"]["rva"], 0x1000)  # type: ignore[index]
        self.assertIn("Runtime OEP: VERIFIED", result["oep_display"])
        self.assertIn("0x10001000", result["oep_display"])

    def test_rejects_wrong_plan_confirmation_and_tampered_trace(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            bundle = self._bundle(Path(temporary))
            wrong_plan = self._verify(bundle, plan_hash="0" * 64)
            bundle["trace"].write_text("{}", encoding="utf-8")
            tampered = self._verify(bundle)
        self.assertEqual(wrong_plan["status"], "rejected")
        self.assertEqual(tampered["status"], "rejected")
        self.assertFalse(tampered["runtime_verified"])

    def test_keeps_result_inconclusive_on_event_loss_or_missing_transfer(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            event_loss = self._verify(self._bundle(Path(temporary), event_loss_count=1))
        with tempfile.TemporaryDirectory() as temporary:
            no_transfer = self._verify(self._bundle(Path(temporary), omit_transfer=True))
        self.assertEqual(event_loss["status"], "inconclusive")
        self.assertEqual(no_transfer["status"], "inconclusive")
        self.assertIn("NOT VERIFIED", event_loss["oep_display"])

    def test_dump_oep_must_match_executed_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            mismatch = self._verify(self._bundle(Path(temporary), dump_entry_rva=0x1001))
        self.assertEqual(mismatch["status"], "inconclusive")
        self.assertFalse(mismatch["runtime_verified"])


if __name__ == "__main__":
    unittest.main()
