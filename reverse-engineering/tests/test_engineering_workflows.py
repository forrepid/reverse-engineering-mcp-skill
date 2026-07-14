from __future__ import annotations

import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from re_core.advanced_workflows import execute_local_feature
from re_core.adapters import ghidra_profile, ida_profile
from re_core.external import ProviderError, normalize_provider_id, provider_status, run_provider
from re_core.feature_catalog import build_feature_workflow, validate_feature_catalog
from re_core.environment import load_runtime_environment
from re_core.readiness import build_readiness_report


class EngineeringWorkflowTests(unittest.TestCase):
    def test_catalog_and_provider_ids_are_canonical(self) -> None:
        self.assertTrue(validate_feature_catalog()["valid"])
        self.assertEqual(normalize_provider_id("Detect It Easy"), "die")
        hosts = {item["id"]: item for item in provider_status() if item["kind"] == "host"}
        self.assertFalse(hosts["ida"]["available"])
        self.assertTrue(hosts["ida"]["requires_host_discovery"])

    def test_capability_unavailable_is_reachable(self) -> None:
        workflow = build_feature_workflow(
            "selection-context",
            host="ida",
            discovered_tools=("get_bytes",),
            discovered_resources=(),
        )
        self.assertEqual(workflow["status"], "capability-unavailable")
        self.assertIn("lookup_funcs", workflow["missing_tools"])

    def test_current_idalib_signature_tools_are_classified(self) -> None:
        tools = (
            "find_xref_signatures",
            "force_recompile",
            "make_signature",
            "make_signature_for_function",
            "make_signature_for_range",
        )
        self.assertEqual(ida_profile(tools, endpoint="").unknown_tools(), [])

    def test_patched_ghidra_health_tool_is_classified(self) -> None:
        profile = ghidra_profile(("ghidra_health",), endpoint="")
        self.assertEqual(profile.unknown_tools(), [])
        self.assertTrue(profile.available()["health"])

    def test_local_protocol_and_archive_audit_are_non_mutating(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sample = root / "sample.bin"
            original = b"server=https://example.invalid/api\x00User-Agent: fixture"
            sample.write_bytes(original)
            protocol = execute_local_feature(
                "protocol-artifact-map", sample, max_scan_bytes=4096
            )
            self.assertTrue(protocol["executed"])
            self.assertFalse(protocol["mutation_performed"])
            self.assertEqual(sample.read_bytes(), original)
            self.assertTrue(protocol["result"]["uri_candidates"])

            archive = root / "unsafe.zip"
            with zipfile.ZipFile(archive, "w") as output:
                output.writestr("../escape.txt", "fixture")
            audit = execute_local_feature("archive-safety-audit", archive)
            self.assertEqual(audit["result"]["risk_candidates"]["path_traversal"], 1)
            self.assertFalse(audit["result"]["extraction_performed"])

    def test_readiness_does_not_claim_missing_hosts(self) -> None:
        report = build_readiness_report(load_runtime_environment({}))
        self.assertTrue(report["summary"]["local_companion_ready"])
        self.assertFalse(report["summary"]["ghidra_config_ready"])
        self.assertFalse(report["summary"]["live_host_claim"])

    def test_readiness_rejects_non_loopback_ghidra_health(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            home = root / "ghidra"
            (home / "support").mkdir(parents=True)
            (home / "Ghidra" / "Extensions" / "GhidraMCP" / "lib").mkdir(
                parents=True
            )
            (home / "ghidraRun.bat").write_text("fixture", encoding="utf-8")
            (home / "support" / "analyzeHeadless.bat").write_text(
                "fixture", encoding="utf-8"
            )
            (home / "Ghidra" / "application.properties").write_text(
                "application.version=12.1.2\n", encoding="utf-8"
            )
            plugin = home / "Ghidra" / "Extensions" / "GhidraMCP"
            (plugin / "extension.properties").write_text(
                "ghidraVersion=12.1.2\n", encoding="utf-8"
            )
            (plugin / "lib" / "GhidraMCP.jar").write_bytes(b"fixture")
            bridge = root / "bridge_mcp_ghidra.py"
            bridge.write_text("# fixture\n", encoding="utf-8")
            report = build_readiness_report(
                load_runtime_environment({}),
                ghidra_home=home,
                ghidra_bridge=bridge,
                ghidra_server="http://example.com:8080/",
            )
            self.assertFalse(report["ghidra"]["server_loopback"])
            self.assertFalse(report["summary"]["ghidra_config_ready"])

    def test_disabled_provider_is_not_available_or_runnable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = root / "providers.json"
            config.write_text(
                json.dumps(
                    {
                        "schema_version": "0.5.0",
                        "providers": {"lief": {"enabled": False}},
                    }
                ),
                encoding="utf-8",
            )
            status = {item["id"]: item for item in provider_status(config)}["lief"]
            self.assertFalse(status["available"])
            self.assertFalse(status["runnable"])
            sample = root / "sample.bin"
            sample.write_bytes(b"fixture")
            with self.assertRaises(ProviderError):
                run_provider("lief", sample, config_path=config)


if __name__ == "__main__":
    unittest.main()
