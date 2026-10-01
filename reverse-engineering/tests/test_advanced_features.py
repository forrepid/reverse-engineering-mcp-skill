from __future__ import annotations

# ruff: noqa: E402 -- tests add the sibling scripts directory before imports.

import hashlib
import struct
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

from re_core.advanced_pe import _parse_cfg_metadata, analyze_pe_deep
from re_core.analyzers import parse_pe
from re_core.feature_catalog import build_feature_workflow, feature_catalog
from re_core.file_types import classify_file
from re_core.selection import (
    build_dump_plan,
    build_host_selection_plan,
    build_source_operation_plan,
    inspect_file_region,
    inspect_text_lines,
)
from re_core.source_edit import (
    apply_source_edit_plan,
    create_source_edit_plan,
)
from re_core.transforms import (
    entropy_windows,
    scan_single_byte_xor,
    transform_region_to_file,
)
from re_mcp_server import server_status
from test_core import build_test_pe


class FileTaxonomyTests(unittest.TestCase):
    def test_sparse_large_file_uses_bounded_late_window(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            sample = Path(temporary) / "large.bin"
            with sample.open("wb") as stream:
                stream.write(b"\x00" * (9 * 1024 * 1024))
                stream.write(b"WIBU-SYSTEMS\x00")
            result = classify_file(sample)
        self.assertIn("dongle", result.categories)
        self.assertTrue(any("sparse interior" in item for item in result.limitations))

    def test_windows_pe_and_dongle_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            sample = Path(temp) / "fixture.exe"
            sample.write_bytes(build_test_pe() + b"Sentinel LDK")
            result = classify_file(sample)
        self.assertEqual(result.primary_category, "win")
        self.assertEqual(result.subtype, "windows-executable")
        self.assertIn("binary", result.categories)
        self.assertIn("dongle", result.categories)

    def test_android_java_mac_script_assembly_visual_and_audio(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            apk = root / "app.apk"
            with zipfile.ZipFile(apk, "w") as archive:
                archive.writestr("AndroidManifest.xml", b"fixture")
                archive.writestr("classes.dex", b"dex\n035\0")
            java_class = root / "Example.class"
            java_class.write_bytes(b"\xCA\xFE\xBA\xBE\x00\x00\x00\x3D\x00\x01")
            macho = root / "fat.bin"
            macho.write_bytes(b"\xCA\xFE\xBA\xBE\x00\x00\x00\x01" + b"\0" * 32)
            script = root / "sample.py"
            script.write_text("#!/usr/bin/env python3\nprint('ok')\n", encoding="utf-8")
            assembly = root / "sample.asm"
            assembly.write_text("section .text\nglobal start\nstart:\n nop\n", encoding="utf-8")
            image = root / "sample.png"
            image.write_bytes(b"\x89PNG\r\n\x1a\n")
            audio = root / "sample.wav"
            audio.write_bytes(b"RIFF\x04\x00\x00\x00WAVE")

            self.assertEqual(classify_file(apk).primary_category, "android")
            self.assertEqual(classify_file(java_class).primary_category, "java")
            self.assertEqual(classify_file(macho).primary_category, "mac")
            self.assertEqual(classify_file(script).primary_category, "script")
            self.assertEqual(classify_file(assembly).primary_category, "assembly")
            self.assertEqual(classify_file(image).primary_category, "visual")
            self.assertEqual(classify_file(audio).primary_category, "audio")


class AdvancedPeTests(unittest.TestCase):
    def test_deep_analysis_rejects_above_scan_budget(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            sample = Path(temp) / "fixture.exe"
            sample.write_bytes(build_test_pe())
            with self.assertRaisesRegex(Exception, "configured scan limit"):
                analyze_pe_deep(sample, max_scan_bytes=256)

    def test_oep_boundaries_injection_and_obfuscation_record(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            sample = Path(temp) / "fixture.exe"
            sample.write_bytes(build_test_pe())
            result = analyze_pe_deep(sample)
        entry = result["declared_entry_point"]
        self.assertEqual(entry["rva"], 0x1000)
        self.assertEqual(entry["file_offset"], 0x200)
        self.assertEqual(entry["section"], ".text")
        self.assertFalse(entry["original_entry_point_verified"])
        self.assertIn("file_end", result["boundaries"])
        self.assertIn("score", result["obfuscation"])
        self.assertEqual(result["oep_result"]["status"], "not_verified")
        self.assertIsNone(result["oep_result"]["value"])
        self.assertIn("Runtime OEP: NOT VERIFIED", result["oep_result"]["display_text"])
        self.assertIn(
            "remote-thread",
            {item["technique"] for item in result["injection_indicators"]},
        )

    def test_static_oep_candidates_are_explicitly_unverified(self) -> None:
        original = build_test_pe()
        with tempfile.TemporaryDirectory() as temp:
            sample = Path(temp) / "candidate.exe"
            sample.write_bytes(original)
            result = analyze_pe_deep(sample)
            self.assertEqual(sample.read_bytes(), original)
        analysis = result["oep_analysis"]
        self.assertEqual(analysis["status"], "candidate_analysis_complete")
        self.assertFalse(analysis["runtime_verified"])
        declared = next(item for item in analysis["candidates"] if item["kind"] == "declared_entry_point")
        self.assertEqual(declared["status"], "reference_not_verified")
        executable = [item for item in analysis["candidates"] if item["kind"] == "executable_section_entry_hypothesis"]
        self.assertTrue(executable)
        self.assertEqual(executable[0]["section"], ".text")
        self.assertEqual(executable[0]["rva"], 0x1000)
        self.assertEqual(executable[0]["va"], 0x401000)
        self.assertEqual(executable[0]["file_offset"], 0x200)

    def test_oep_static_report_parses_file_backed_tls_callback_candidates(self) -> None:
        image = bytearray(build_test_pe())
        optional = 0x98
        directory_offset = optional + 96
        struct.pack_into("<II", image, directory_offset + 9 * 8, 0x2040, 24)
        image.extend(bytes(0x200))
        struct.pack_into("<I", image, 0x440 + 12, 0x402070)
        struct.pack_into("<II", image, 0x470, 0x401000, 0)
        with tempfile.TemporaryDirectory() as temp:
            sample = Path(temp) / "tls.exe"
            sample.write_bytes(image)
            analysis = analyze_pe_deep(sample)["oep_analysis"]
        tls = analysis["pre_entry_execution_signals"]["tls_directory"]
        self.assertEqual(tls["directory_rva"], 0x2040)
        self.assertTrue(tls["parsed"])
        self.assertTrue(tls["complete"])
        self.assertEqual(tls["callback_addresses"][0]["va"], 0x401000)
        self.assertEqual(tls["callback_addresses"][0]["rva"], 0x1000)
        self.assertEqual(tls["callback_addresses"][0]["file_offset"], 0x200)
        self.assertEqual(tls["callback_addresses"][0]["status"], "static_callback_candidate")

    def test_tls_callback_parser_fails_closed_for_unmapped_array_and_unterminated_limit(self) -> None:
        image = bytearray(build_test_pe())
        optional = 0x98
        directory_offset = optional + 96
        struct.pack_into("<II", image, directory_offset + 9 * 8, 0x2040, 24)
        struct.pack_into("<I", image, 0x440 + 12, 0x405000)
        with tempfile.TemporaryDirectory() as temp:
            sample = Path(temp) / "tls-unmapped.exe"
            sample.write_bytes(image)
            unmapped = analyze_pe_deep(sample)["oep_analysis"]["pre_entry_execution_signals"]["tls_directory"]
        self.assertFalse(unmapped["complete"])
        self.assertEqual(unmapped["callback_addresses"], [])
        self.assertIn("file-backed", unmapped["reason"])

    def test_oep_static_report_correlates_imports_packer_markers_and_cfg_metadata(self) -> None:
        image = bytearray(build_test_pe())
        optional = 0x98
        directory_offset = optional + 96
        struct.pack_into("<II", image, directory_offset + 10 * 8, 0x1080, 92)
        struct.pack_into("<I", image, 0x280, 92)
        struct.pack_into("<I", image, 0x280 + 80, 0x4010E0)
        struct.pack_into("<I", image, 0x280 + 84, 1)
        struct.pack_into("<I", image, 0x280 + 88, 0x500)
        struct.pack_into("<I", image, 0x2E0, 0x1000)
        image.extend(b"UPX!")
        with tempfile.TemporaryDirectory() as temp:
            sample = Path(temp) / "cfg-oep.exe"
            sample.write_bytes(image)
            result = analyze_pe_deep(sample)
        oep = result["oep_analysis"]
        cfg = oep["pre_entry_execution_signals"]["guard_cf_load_config"]
        self.assertTrue(cfg["parsed"])
        self.assertTrue(cfg["cfg_instrumented"])
        self.assertTrue(cfg["function_table_present"])
        self.assertTrue(cfg["entry_point_in_guard_cf_table"])
        signals = oep["correlation_signals"]
        self.assertIn("memory_allocation_or_protection", {item["category"] for item in signals["import_api_signals"]})
        self.assertEqual(signals["packer_marker_signals"][0]["name"], "UPX marker")
        self.assertFalse(oep["runtime_verified"])

    def test_cfg_metadata_rejects_inconsistent_size_and_unbounded_target_count(self) -> None:
        image = bytearray(build_test_pe())
        optional = 0x98
        directory_offset = optional + 96
        struct.pack_into("<II", image, directory_offset + 10 * 8, 0x1080, 92)
        struct.pack_into("<I", image, 0x280, 40)
        with tempfile.TemporaryDirectory() as temp:
            sample = Path(temp) / "bad-cfg.exe"
            sample.write_bytes(image)
            cfg = analyze_pe_deep(sample)["oep_analysis"]["pre_entry_execution_signals"]["guard_cf_load_config"]
        self.assertFalse(cfg["parsed"])
        self.assertIn("inconsistent", cfg["reason"])

        image = bytearray(build_test_pe())
        struct.pack_into("<I", image, 0x280, 92)
        struct.pack_into("<I", image, 0x280 + 80, 0x4010E0)
        struct.pack_into("<I", image, 0x280 + 84, 4097)
        struct.pack_into("<I", image, 0x280 + 88, 0x500)
        pe = parse_pe(bytes(image))
        pe["data_directories"]["load_config"] = {"address": 0x1080, "size": 92}
        bounded = _parse_cfg_metadata(bytes(image), pe)
        self.assertTrue(bounded["parsed"])
        self.assertIn("exceeds parse limit", bounded["reason"])

    def test_cfg_metadata_uses_pe32_plus_load_config_offsets(self) -> None:
        image = bytearray(build_test_pe())
        optional = 0x98
        directory_offset = optional + 96
        struct.pack_into("<II", image, directory_offset + 10 * 8, 0x1080, 176)
        struct.pack_into("<I", image, 0x280, 176)
        struct.pack_into("<Q", image, 0x280 + 128, 0x1400010E0)
        struct.pack_into("<Q", image, 0x280 + 136, 1)
        struct.pack_into("<I", image, 0x280 + 144, 0x500)
        struct.pack_into("<I", image, 0x2E0, 0x1000)
        pe = parse_pe(bytes(image))
        pe["bits"] = 64
        pe["image_base"] = 0x140000000
        cfg = _parse_cfg_metadata(bytes(image), pe)
        self.assertTrue(cfg["parsed"])
        self.assertTrue(cfg["entry_point_in_guard_cf_table"])
        self.assertEqual(cfg["function_table_rva"], 0x10E0)

    def test_static_oep_candidates_report_non_executable_declared_ep_conflict(self) -> None:
        image = bytearray(build_test_pe())
        optional = 0x98
        struct.pack_into("<I", image, optional + 16, 0x2000)
        with tempfile.TemporaryDirectory() as temp:
            sample = Path(temp) / "invalid-ep.exe"
            sample.write_bytes(image)
            result = analyze_pe_deep(sample)
        declared = next(item for item in result["oep_analysis"]["candidates"] if item["kind"] == "declared_entry_point")
        self.assertTrue(any("not executable" in item for item in declared["evidence"]))
        self.assertEqual(declared["status"], "reference_not_verified")

    def test_static_oep_candidate_does_not_map_virtual_zero_fill_to_file_bytes(self) -> None:
        image = bytearray(build_test_pe())
        section_table = 0x80 + 4 + 20 + 0xE0
        struct.pack_into("<I", image, section_table + 16, 0x40)
        struct.pack_into("<I", image, section_table + 20, 0x5F0)
        struct.pack_into("<I", image, section_table + 8, 0x700)
        struct.pack_into("<I", image, section_table + 40 + 20, 0x800)
        with tempfile.TemporaryDirectory() as temp:
            sample = Path(temp) / "zero-fill.exe"
            sample.write_bytes(image)
            analysis = analyze_pe_deep(sample)["oep_analysis"]
        candidate = next(
            item for item in analysis["candidates"]
            if item["kind"] == "executable_section_entry_hypothesis" and item["section"] == ".text"
        )
        self.assertIsNone(candidate["file_offset"])

    def test_static_oep_candidates_suppress_offsets_for_overlapping_sections(self) -> None:
        image = bytearray(build_test_pe())
        section_table = 0x80 + 4 + 20 + 0xE0
        struct.pack_into("<I", image, section_table + 40 + 12, 0x1000)
        with tempfile.TemporaryDirectory() as temp:
            sample = Path(temp) / "overlap.exe"
            sample.write_bytes(image)
            analysis = analyze_pe_deep(sample)["oep_analysis"]
        self.assertFalse(analysis["address_map_valid"])
        self.assertTrue(all(item["file_offset"] is None for item in analysis["candidates"]))
        self.assertTrue(all(item["confidence"] == "low" for item in analysis["candidates"]))


class SelectionAndTransformTests(unittest.TestCase):
    def test_region_text_selection_and_host_plans(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            sample = root / "sample.bin"
            sample.write_bytes(b"ABC\x00https://example.test\x00XYZ")
            source = root / "sample.py"
            source.write_text(
                "import os\n\ndef alpha():\n    # TODO decrypt AES\n    return 'https://example.test'\n",
                encoding="utf-8",
            )
            region = inspect_file_region(sample, offset=0, length=sample.stat().st_size)
            text = inspect_text_lines(source, start_line=1, end_line=5)
        self.assertIn("https://example.test", {item["value"] for item in region["strings"]})
        self.assertIn("alpha", text["features"]["function_candidates"])
        self.assertEqual(text["features"]["todo_fixme_count"], 1)
        ida = build_host_selection_plan(
            host="ida", database="db", address=0x401000, end=0x401040
        )
        ghidra = build_host_selection_plan(host="ghidra", address=0x401000)
        self.assertIn("get_bytes", {item["tool"] for item in ida["requests"]})
        self.assertIn(
            "decompile_function_by_address",
            {item["tool"] for item in ghidra["requests"]},
        )
        self.assertEqual(
            build_source_operation_plan(
                host="ghidra", operation="process-inject", address=0x401000
            )["status"],
            "blocked-by-default",
        )
        self.assertTrue(
            build_dump_plan(
                host="ida",
                kind="runtime",
                address=0x401000,
                length=4096,
                database="db",
            )["requires_isolated_target"]
        )

    def test_xor_entropy_and_confirmed_transform(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            plaintext = b"hello world this is readable text"
            encoded = bytes(byte ^ 0x42 for byte in plaintext)
            sample = root / "encoded.bin"
            output = root / "decoded.bin"
            sample.write_bytes(encoded)
            scan = scan_single_byte_xor(sample, offset=0, length=len(encoded), limit=5)
            transformed = transform_region_to_file(
                sample,
                offset=0,
                length=len(encoded),
                operation="xor",
                key=0x42,
                output=output,
                confirm_sha256=hashlib.sha256(encoded).hexdigest(),
            )
            entropy_sample = root / "entropy.bin"
            entropy_sample.write_bytes(bytes(range(256)) * 16)
            entropy = entropy_windows(entropy_sample, window=4096, threshold=7.5)
            self.assertEqual(output.read_bytes(), plaintext)
        self.assertIn(0x42, {item["key"] for item in scan["candidates"]})
        self.assertFalse(transformed["source_modified"])
        self.assertEqual(len(entropy["matches"]), 1)

    def test_sealed_out_of_place_source_edit(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "source.py"
            output = root / "updated.py"
            source.write_text("import os\n\ndef alpha():\n    return 1\n", encoding="utf-8")
            original = source.read_bytes()
            plan = create_source_edit_plan(
                source,
                mode="replace",
                start_line=3,
                end_line=3,
                replacement_text="def beta():\n",
                rationale="fixture rename",
            )
            result = apply_source_edit_plan(
                source,
                plan,
                confirm_sha256=hashlib.sha256(original).hexdigest(),
                output=output,
            )
            self.assertIn("def beta", output.read_text(encoding="utf-8"))
            self.assertEqual(source.read_bytes(), original)
            self.assertFalse(result["source_modified"])


class FeatureAndMcpTests(unittest.TestCase):
    def test_feature_catalog_has_two_exact_25_contract_generations(self) -> None:
        catalog = feature_catalog()
        self.assertEqual(catalog["count"], 50)
        self.assertEqual(len({item["id"] for item in catalog["features"]}), 50)
        self.assertEqual(feature_catalog(generation=1)["count"], 25)
        second = feature_catalog(generation=2)
        self.assertEqual(second["count"], 25)
        self.assertTrue(all(item["generation"] == 2 for item in second["features"]))
        workflow = build_feature_workflow("selection-context", host="ida", database="db")
        self.assertIn("get_bytes", workflow["tool_sequence"])

    def test_companion_server_is_read_only_by_default(self) -> None:
        status = server_status()
        self.assertEqual(status["transport"], "stdio")
        self.assertFalse(status["writes_exposed"])
        self.assertFalse(status["unsafe_tools_exposed"])
        self.assertEqual(status["environment"]["required_count"], 0)
        self.assertEqual(len(status["environment"]["variables"]), 13)
        self.assertEqual(status["default_mode"], "read_only")

    def test_companion_registers_static_oep_tool_without_runtime_tooling(self) -> None:
        server = __import__("re_mcp_server").build_server()
        tool_names = {tool.name for tool in server._tool_manager.list_tools()}
        self.assertIn("oep_static_candidates", tool_names)
        self.assertIn("oep_runtime_plan", tool_names)
        self.assertFalse(any(name in tool_names for name in (
            "oep_runtime_start", "oep_runtime_trace", "oep_runtime_dump", "oep_runtime_export"
        )))
        self.assertEqual(len(tool_names), server_status()["tool_count"])

    def test_runtime_oep_plan_tool_is_plan_only_and_carries_broker_gate(self) -> None:
        server = __import__("re_mcp_server").build_server()
        with tempfile.TemporaryDirectory() as temporary:
            sample = Path(temporary) / "authorized-fixture.bin"
            sample.write_bytes(b"fixture; never executed")
            tool = server._tool_manager.get_tool("oep_runtime_plan")
            plan = tool.fn(str(sample), provider="internal")
        self.assertEqual(plan["status"], "plan_only")
        self.assertFalse(plan["broker_capture_contract"]["submission_enabled"])
        self.assertFalse(plan["broker_capture_contract"]["continuous_capture"])
        self.assertIsNone(plan["runtime_oep"]["display_value"])


if __name__ == "__main__":
    unittest.main()
