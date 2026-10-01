from __future__ import annotations

# ruff: noqa: E402 -- tests add the sibling scripts directory before imports.

import hashlib
import json
import struct
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

from re_core.adapters import OperationClass, ida_profile
from re_core.analyzers import StaticAnalyzer, bitdump, hexdump, search_hex, search_text
from re_core.comparison import compare_files
from re_core.disassembly import DisassemblyError, disassemble_bytes
from re_core.patching import (
    PatchError,
    apply_patch_plan,
    create_patch_plan,
    load_patch_plan,
    save_patch_plan,
)
from re_core.reporting import write_reports
from re_core.sandbox import create_sandbox_plan
from re_core.session import HostEndpoint, host_snapshot


def build_test_pe() -> bytes:
    data = bytearray(0x600)
    data[0:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\x00\x00"
    struct.pack_into(
        "<HHIIIHH",
        data,
        0x84,
        0x14C,
        2,
        0x12345678,
        0,
        0,
        0xE0,
        0x0102,
    )
    optional = 0x98
    struct.pack_into("<H", data, optional, 0x10B)
    struct.pack_into("<I", data, optional + 16, 0x1000)
    struct.pack_into("<I", data, optional + 28, 0x400000)
    struct.pack_into("<I", data, optional + 56, 0x3000)
    struct.pack_into("<I", data, optional + 92, 16)
    struct.pack_into("<II", data, optional + 104, 0x2000, 0x100)

    section_table = optional + 0xE0
    struct.pack_into(
        "<8sIIIIIIHHI",
        data,
        section_table,
        b".text\x00\x00\x00",
        0x100,
        0x1000,
        0x200,
        0x200,
        0,
        0,
        0,
        0,
        0x60000020,
    )
    struct.pack_into(
        "<8sIIIIIIHHI",
        data,
        section_table + 40,
        b".idata\x00\x00",
        0x200,
        0x2000,
        0x200,
        0x400,
        0,
        0,
        0,
        0,
        0xC0000040,
    )
    data[0x220:0x22B] = b"HELLO_TEST\x00"
    struct.pack_into("<IIIII", data, 0x400, 0x2060, 0, 0, 0x2050, 0x2060)
    data[0x450:0x45D] = b"KERNEL32.dll\x00"
    struct.pack_into("<II", data, 0x460, 0x2070, 0)
    data[0x470:0x472] = b"\x00\x00"
    data[0x472:0x481] = b"VirtualAllocEx\x00"
    return bytes(data)


class AnalyzerTests(unittest.TestCase):
    def test_analyzer_respects_scan_limit_and_reports_partial_coverage(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            sample = Path(temp) / "large.bin"
            sample.write_bytes(b"MZ" + b"A" * 100)
            result = StaticAnalyzer(max_file_size=1024, max_scan_bytes=64).analyze(sample)
        self.assertEqual(result.summary["scanned_bytes"], 64)
        self.assertTrue(any("content scan limited" in item for item in result.limitations))

    def test_pe_sections_imports_strings_and_findings(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            sample = Path(temp) / "fixture.exe"
            sample.write_bytes(build_test_pe())
            result = StaticAnalyzer().analyze(sample)

        self.assertEqual(result.summary["format"], "PE")
        self.assertEqual(result.summary["architecture"], "x86")
        self.assertEqual([section.name for section in result.sections], [".text", ".idata"])
        self.assertEqual(result.imports[0].name, "KERNEL32.dll")
        self.assertIn("VirtualAllocEx", result.imports[0].symbols)
        self.assertIn("HELLO_TEST", {item.value for item in result.strings})
        self.assertIn(
            "capability.process-injection-primitives",
            {finding.id for finding in result.findings},
        )

    def test_hex_bit_and_search_views(self) -> None:
        data = b"\x4D\x5A\x90ABCabc"
        self.assertIn("00000000", hexdump(data))
        self.assertIn("01001101", bitdump(data[:1]))
        self.assertEqual(search_hex(data, "4D ?? 90"), [0])
        matches = search_text(data, "abc", ignore_case=True)
        self.assertEqual([match["offset"] for match in matches], [3, 6])

    def test_disassembly_provider_is_explicit(self) -> None:
        try:
            instructions = disassemble_bytes(
                b"\x90\xC3", architecture="x86", max_instructions=4
            )
        except DisassemblyError as error:
            self.assertIn("Capstone", str(error))
        else:
            self.assertEqual(instructions[0]["mnemonic"], "nop")


class PatchTests(unittest.TestCase):
    def test_sealed_out_of_place_patch(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            sample = root / "sample.bin"
            plan_path = root / "plan.json"
            output = root / "patched.bin"
            sample.write_bytes(b"\x01\x02\x03\x04")
            plan = create_patch_plan(
                sample,
                offset=1,
                expected="02 03",
                replacement="90 90",
                rationale="unit test",
            )
            save_patch_plan(plan, plan_path)
            loaded = load_patch_plan(plan_path)
            result = apply_patch_plan(
                sample,
                loaded,
                confirm_sha256=hashlib.sha256(sample.read_bytes()).hexdigest(),
                output=output,
            )
            self.assertEqual(output.read_bytes(), b"\x01\x90\x90\x04")
            self.assertNotEqual(result["source_sha256"], result["output_sha256"])
            self.assertEqual(sample.read_bytes(), b"\x01\x02\x03\x04")

    def test_patch_rejects_wrong_confirmation(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            sample = Path(temp) / "sample.bin"
            sample.write_bytes(b"\x01\x02")
            plan = create_patch_plan(
                sample, offset=0, expected="01", replacement="90"
            )
            with self.assertRaises(PatchError):
                apply_patch_plan(
                    sample,
                    plan,
                    confirm_sha256="0" * 64,
                    output=Path(temp) / "out.bin",
                )

    def test_patch_plan_cannot_overwrite_source(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            sample = Path(temp) / "sample.bin"
            sample.write_bytes(b"\x01")
            plan = create_patch_plan(
                sample, offset=0, expected="01", replacement="90"
            )
            with self.assertRaises(PatchError):
                save_patch_plan(plan, sample)


class IntegrationContractTests(unittest.TestCase):
    def test_adapter_fails_closed_and_classifies(self) -> None:
        profile = ida_profile(
            ["decompile", "patch", "unexpected_tool"],
            endpoint="http://127.0.0.1:8745/mcp",
        )
        self.assertTrue(profile.available()["decompile"])
        self.assertEqual(profile.classify("patch"), OperationClass.PATCH)
        self.assertEqual(profile.unknown_tools(), ["unexpected_tool"])
        with self.assertRaises(ValueError):
            ida_profile([], endpoint="http://192.0.2.10:8745/mcp")

    def test_sandbox_is_plan_only_and_network_blocked(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            sample = Path(temp) / "sample.bin"
            sample.write_bytes(b"safe fixture")
            plan = create_sandbox_plan(sample, provider="cape")
        self.assertEqual(plan["status"], "plan_only")
        self.assertFalse(plan["broker_capture_contract"]["submission_enabled"])
        self.assertFalse(plan["broker_capture_contract"]["continuous_capture"])
        self.assertTrue(plan["approval_required"])
        self.assertFalse(plan["runtime_oep"]["ready_for_broker_submission"])
        self.assertEqual(plan["policy"]["network"], "blocked")
        with tempfile.TemporaryDirectory() as temp:
            sample = Path(temp) / "sample.bin"
            sample.write_bytes(b"safe fixture")
            ready_plan = create_sandbox_plan(
                sample,
                provider="internal",
                image_digest="ab" * 32,
                snapshot_id="clean-snapshot",
            )
        self.assertTrue(ready_plan["runtime_oep"]["ready_for_broker_submission"])
        self.assertEqual(ready_plan["resource_limits"]["max_trace_bytes"], 32 * 1024 * 1024)
        with self.assertRaises(ValueError):
            create_sandbox_plan(sample, provider="internal", image_digest="invalid")

    def test_host_discovery_is_loopback_only(self) -> None:
        with self.assertRaises(ValueError):
            HostEndpoint("remote", "192.0.2.10", 8080, "forbidden")
        snapshot = host_snapshot(timeout=0.05)
        self.assertEqual(len(snapshot), 4)
        self.assertTrue(all(item["probe"] == "tcp-connect-only" for item in snapshot))

    def test_report_and_comparison(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            left = root / "left.exe"
            right = root / "right.exe"
            left.write_bytes(build_test_pe())
            modified = bytearray(build_test_pe())
            modified[0x220] = ord("Y")
            right.write_bytes(modified)
            analyzer = StaticAnalyzer()
            reports = write_reports(analyzer.analyze(left), root / "reports")
            comparison = compare_files(left, right)
            report_json = json.loads(
                Path(reports["json"]).read_text(encoding="utf-8")
            )
            self.assertEqual(report_json["summary"]["format"], "PE")
            self.assertFalse(comparison["identical"])
            self.assertGreater(comparison["byte_diff"]["total_changed_bytes"], 0)


if __name__ == "__main__":
    unittest.main()
