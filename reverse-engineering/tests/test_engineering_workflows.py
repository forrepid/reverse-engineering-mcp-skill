from __future__ import annotations

import json
import shutil
import threading
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from re_core.advanced_workflows import AdvancedWorkflowError, execute_local_feature
from re_core.adapters import ghidra_profile, ida_profile
from re_core.external import ProviderError, normalize_provider_id, provider_status, run_provider
from re_core.feature_catalog import build_feature_workflow, validate_feature_catalog
from re_core.environment import load_runtime_environment
from re_core.readiness import build_readiness_report
from re_core.broker_config import BrokerConfigError, load_broker_config
from re_core.broker_config import probe_broker_health
from re_core.mock_broker import LoopbackMockBroker


class EngineeringWorkflowTests(unittest.TestCase):
    def test_dependency_inventory_obeys_runtime_file_and_scan_budgets(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            sample = Path(temporary) / "sample.bin"
            sample.write_bytes(b"A" * 256)
            with self.assertRaisesRegex(AdvancedWorkflowError, "exceeds configured limit 64"):
                execute_local_feature("dependency-risk-map", sample, max_file_bytes=64)
            result = execute_local_feature(
                "dependency-risk-map",
                sample,
                max_file_bytes=512,
                max_scan_bytes=32,
            )
        self.assertTrue(
            any("content scan limited to first 32 of 256 bytes" in item
                for item in result["result"]["limitations"])
        )

    def test_catalog_and_provider_ids_are_canonical(self) -> None:
        self.assertTrue(validate_feature_catalog()["valid"])
        self.assertEqual(normalize_provider_id("Detect It Easy"), "die")
        hosts = {item["id"]: item for item in provider_status() if item["kind"] == "host"}
        self.assertFalse(hosts["ida"]["available"])
        self.assertTrue(hosts["ida"]["requires_host_discovery"])

    def test_readiness_reports_runtime_broker_capture_as_unconfigured(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            settings = Path(temporary) / "settings"
            with patch("re_core.environment.settings_path", return_value=settings):
                runtime = load_runtime_environment({"RE_MCP_MODE": "read_only"})
                report = build_readiness_report(runtime)
        broker = report["runtime_oep_broker"]
        self.assertEqual(broker["status"], "not_configured")
        self.assertFalse(broker["continuous_capture"])
        self.assertFalse(broker["submission_enabled"])

    def test_broker_config_requires_pins_and_rejects_remote_http(self) -> None:
        with self.assertRaises(BrokerConfigError):
            load_broker_config({"RE_BROKER_PROVIDER": "cape", "RE_BROKER_BASE_URL": "http://example.org"})
        with self.assertRaises(BrokerConfigError):
            load_broker_config({
                "RE_BROKER_PROVIDER": "cape",
                "RE_BROKER_BASE_URL": "http://127.0.0.1:8000/apiv2",
                "RE_BROKER_ID": "lab-01",
            })

    def test_broker_config_accepts_loopback_url_and_does_not_expose_token(self) -> None:
        config = load_broker_config({
            "RE_BROKER_PROVIDER": "cape",
            "RE_BROKER_BASE_URL": "http://127.0.0.1:8000/apiv2/",
            "RE_BROKER_ID": "lab-01",
            "RE_BROKER_TOKEN": "secret-token",
            "RE_BROKER_PUBLIC_KEY": "ab" * 32,
        })
        status = config.public_status()
        self.assertTrue(config.configured)
        self.assertEqual(config.base_url, "http://127.0.0.1:8000/apiv2")
        self.assertTrue(status["token_configured"])
        self.assertNotIn("secret-token", str(status))
        self.assertFalse(status["submission_enabled"])

    def test_loopback_mock_broker_health_works_and_never_accepts_submission(self) -> None:
        server = LoopbackMockBroker(0)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            config = load_broker_config({
                "RE_BROKER_PROVIDER": "mock",
                "RE_BROKER_BASE_URL": f"http://127.0.0.1:{server.server_port}",
                "RE_BROKER_ID": "mock-broker",
            })
            self.assertEqual(config.public_status()["status"], "test_only")
            health = probe_broker_health(config)
            self.assertEqual(health["status"], "test_only")
            self.assertTrue(health["reachable"])
            self.assertFalse(health["capture_supported"])
            self.assertFalse(config.public_status()["submission_enabled"])
            with self.assertRaises(HTTPError) as error:
                urlopen(Request(config.base_url + "/submit", data=b"", method="POST"))
            self.assertEqual(error.exception.code, 405)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=1)

    def test_capability_unavailable_is_reachable(self) -> None:
        workflow = build_feature_workflow(
            "selection-context",
            host="ida",
            discovered_tools=("get_bytes",),
            discovered_resources=(),
        )
        self.assertEqual(workflow["status"], "capability-unavailable")
        self.assertIn("lookup_funcs", workflow["missing_tools"])

    def test_host_profile_blocks_patch_and_unknown_operations(self) -> None:
        profile = ida_profile(("list_funcs", "patch", "idb_save", "mystery"), endpoint="")
        report = profile.policy_report("read_only")
        self.assertIn("list_funcs", report["available_tools_in_profile"])  # type: ignore[arg-type]
        self.assertIn("patch", report["blocked_or_unknown_tools"])  # type: ignore[arg-type]
        self.assertIn("mystery", report["blocked_or_unknown_tools"])  # type: ignore[arg-type]
        read_write = profile.policy_report("read_write")
        self.assertIn("list_funcs", read_write["available_tools_in_profile"])  # type: ignore[arg-type]
        self.assertIn("idb_save", read_write["available_tools_in_profile"])  # type: ignore[arg-type]
        self.assertIn("patch", read_write["blocked_or_unknown_tools"])  # type: ignore[arg-type]
        self.assertIn("mystery", read_write["blocked_or_unknown_tools"])  # type: ignore[arg-type]

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

    def test_archive_ratio_is_checked_per_zip_member(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            archive = Path(temporary) / "ratio.zip"
            with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as output:
                output.writestr("compressible.bin", b"A" * 100_000)
            with self.assertRaisesRegex(Exception, "member exceeds expansion-ratio"):
                execute_local_feature("archive-safety-audit", archive, max_archive_member_ratio=5)

    def test_archive_limits_preflight_source_and_zip_index_before_materializing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            archive = Path(temporary) / "many.zip"
            with zipfile.ZipFile(archive, "w") as output:
                output.writestr("one.txt", "one")
                output.writestr("two.txt", "two")
                output.writestr("three.txt", "three")
            with self.assertRaisesRegex(AdvancedWorkflowError, "source exceeds file limit"):
                execute_local_feature("archive-safety-audit", archive, max_file_bytes=8)
            with patch("zipfile.ZipFile.infolist", side_effect=AssertionError("must not materialize")):
                with self.assertRaisesRegex(AdvancedWorkflowError, "exceeds member limit 2"):
                    execute_local_feature(
                        "archive-safety-audit",
                        archive,
                        max_archive_members=2,
                    )
                with self.assertRaisesRegex(AdvancedWorkflowError, "central directory exceeds scan limit"):
                    execute_local_feature(
                        "archive-safety-audit",
                        archive,
                        max_scan_bytes=1,
                    )

    def test_large_byte_diff_caps_hex_details(self) -> None:
        from re_core.comparison import _byte_diff_files

        with tempfile.TemporaryDirectory() as temporary:
            left = Path(temporary) / "left"
            right = Path(temporary) / "right"
            left.write_bytes(b"A" * 20_000)
            right.write_bytes(b"B" * 20_000)
            diff = _byte_diff_files(left, right)
        self.assertEqual(diff["total_changed_bytes"], 20_000)
        self.assertLessEqual(len(diff["ranges"][0]["left"].split()), 4096)
        self.assertTrue(diff["details_truncated"])

    def test_readiness_does_not_claim_missing_hosts(self) -> None:
        report = build_readiness_report(load_runtime_environment({}))
        self.assertTrue(report["summary"]["local_companion_ready"])
        self.assertFalse(report["summary"]["ghidra_config_ready"])
        self.assertFalse(report["summary"]["live_host_claim"])

    def test_optional_ida_probe_reports_tools_without_opening_a_database(self) -> None:
        executable = shutil.which("idalib-mcp") or shutil.which("idalib-mcp.exe")
        if not executable:
            self.skipTest("idalib-mcp is not installed")
        from re_core.readiness import _probe_idalib_health

        report = _probe_idalib_health(Path(executable), timeout=15)
        self.assertTrue(report["verified"], report)
        self.assertGreater(report["tool_count"], 0)
        self.assertIn("idb_open", report["tool_names"])
        self.assertFalse(report.get("idb_open_called", False))

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
