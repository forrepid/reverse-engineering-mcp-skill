from __future__ import annotations

# ruff: noqa: E402 -- tests add the sibling scripts directory before imports.

import hashlib
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

from re_core.advanced_pe import analyze_pe_deep
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
        self.assertIn(
            "remote-thread",
            {item["technique"] for item in result["injection_indicators"]},
        )


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
        self.assertEqual(len(status["environment"]["variables"]), 9)


if __name__ == "__main__":
    unittest.main()
