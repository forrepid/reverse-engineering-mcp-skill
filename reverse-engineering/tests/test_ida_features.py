from __future__ import annotations

# ruff: noqa: E402 -- tests add the sibling scripts directory before imports.

import sys
import tempfile
import unittest
from pathlib import Path


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

from re_core.ida_installation import build_idalib_profile, detect_ida_installation
from re_core.ida_live import (
    attach_active_idb,
    build_context_requests,
    collect_current_context,
    create_project_deeplink,
    wait_for_autoanalysis,
)
from re_core.inventory import build_binary_inventory
from re_core.mcp_supervisor import (
    IdalibMcpSupervisor,
    McpSupervisorError,
    build_mcp_launch_plan,
)
from re_core.patch_impact import preview_patch_impact
from re_core.patching import create_patch_plan
from re_core.snapshots import SnapshotError, build_restore_plan, create_idb_snapshot
from test_core import build_test_pe


class IdaInstallationTests(unittest.TestCase):
    def _fake_installation(self, root: Path) -> Path:
        ida = root / "ida.exe"
        ida.write_bytes(b"MZ-fake-ida")
        (root / "idat.exe").write_bytes(b"MZ-fake-idat")
        (root / "idalib.dll").write_bytes(b"fake-idalib")
        (root / "idalib32.dll").write_bytes(b"fake-idalib32")
        (root / "idapyswitch.exe").write_bytes(b"MZ-fake-switch")
        plugins = root / "plugins"
        plugins.mkdir()
        (plugins / "idapython3.dll").write_bytes(b"fake-idapython")
        python_dir = root / "idalib" / "python"
        python_dir.mkdir(parents=True)
        (python_dir / "py-activate-idalib.py").write_text("# fixture", encoding="utf-8")
        (python_dir / "idapro-0.0.9-py3-none-any.whl").write_bytes(b"fixture")
        (root / "untrusted-keygen.exe").write_bytes(b"do-not-run")
        return ida

    def test_profiles_installation_without_execution(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            ida = self._fake_installation(Path(temp))
            report = detect_ida_installation(ida)
            profile = build_idalib_profile(ida, python_executable=sys.executable)
        self.assertTrue(report.ready)
        self.assertEqual(len(report.suspicious_executables), 1)
        self.assertFalse(profile["automatic_execution"])
        self.assertIn("activate", profile["commands_preview_only"])

    def test_mcp_launch_plan_is_loopback_and_allowlisted(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            executable = Path(temp) / "idalib-mcp.exe"
            executable.write_bytes(b"fixture")
            plan = build_mcp_launch_plan(
                transport="http", executable=executable, max_workers=2
            )
            self.assertTrue(plan.available)
            self.assertFalse(plan.shell)
            self.assertEqual(len(plan.executable_sha256), 64)
            self.assertEqual(plan.session_model, "persistent-per-database-worker")
            self.assertNotIn("--isolated-contexts", plan.command)
            self.assertIn("--max-workers", plan.command)
            supervisor = IdalibMcpSupervisor(plan, Path(temp) / "mcp.log")
            with self.assertRaises(McpSupervisorError):
                supervisor.start(confirm_sha256="0" * 64)
            with self.assertRaises(McpSupervisorError):
                build_mcp_launch_plan(executable=executable, host="192.0.2.10")

            wrong = Path(temp) / "other.exe"
            wrong.write_bytes(b"fixture")
            with self.assertRaises(McpSupervisorError):
                build_mcp_launch_plan(executable=wrong)


class IdaLiveTests(unittest.TestCase):
    def test_discovered_gui_requires_explicit_adoption(self) -> None:
        calls: list[tuple[str, dict[str, object]]] = []

        def call_tool(name: str, arguments: dict[str, object]) -> object:
            calls.append((name, arguments))
            if name == "idb_list":
                return {
                    "sessions": [
                        {
                            "session_id": "",
                            "backend": "gui",
                            "is_active": True,
                            "input_path": "C:/fixtures/opened.exe",
                        }
                    ]
                }
            if name == "idb_open":
                return {
                    "success": True,
                    "session": {
                        "session_id": "adopted-gui",
                        "backend": "gui",
                        "is_active": True,
                    },
                }
            raise AssertionError(name)

        selected = attach_active_idb(call_tool, adopt_discovered=True)
        self.assertEqual(selected["session_id"], "adopted-gui")
        self.assertEqual(selected["discovery_tool"], "idb_list+idb_open")
        open_call = next(arguments for name, arguments in calls if name == "idb_open")
        self.assertEqual(open_call["mode"], "prefer_gui")

    def test_selects_active_gui_session_and_plans_read_only_context(self) -> None:
        sessions = {
            "sessions": [
                {"session_id": "headless", "backend": "idalib"},
                {
                    "session_id": "gui-current",
                    "backend": "gui",
                    "is_active": True,
                    "is_current_context": True,
                },
            ]
        }

        def call_tool(name: str, arguments: dict[str, object]) -> object:
            if name == "idalib_list":
                return sessions
            return {"tool": name, "arguments": arguments}

        selected = attach_active_idb(call_tool)
        requests = build_context_requests(
            database=selected["session_id"], address=0x401000, byte_count=32
        )
        context = collect_current_context(
            call_tool, database=selected["session_id"], address=0x401000
        )
        self.assertEqual(selected["session_id"], "gui-current")
        self.assertTrue(selected["read_only_default"])
        self.assertTrue(all(request.tool not in {"patch", "rename"} for request in requests))
        self.assertFalse(context["mutation_performed"])

    def test_autoanalysis_gate_and_project_deeplink(self) -> None:
        statuses = iter([{"state": "processing"}, {"state": "complete"}])
        result = wait_for_autoanalysis(
            lambda: next(statuses), timeout=1.0, interval=0.05
        )
        link = create_project_deeplink(
            database="sample.i64", address=0x401000, view="pseudocode"
        )
        self.assertTrue(result["ready"])
        self.assertEqual(result["polls"], 2)
        self.assertTrue(link.startswith("re-idb://open?"))
        self.assertIn("0x401000", link)


class SnapshotAndImpactTests(unittest.TestCase):
    def test_snapshot_requires_saved_confirmation_and_verifies_restore(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "sample.i64"
            source.write_bytes(b"saved-idb-fixture")
            with self.assertRaises(SnapshotError):
                create_idb_snapshot(source, root / "snapshots", confirm_saved=False)
            snapshot = create_idb_snapshot(
                source,
                root / "snapshots",
                confirm_saved=True,
                label="before-rename",
            )
            restore = build_restore_plan(snapshot["manifest"], source)
            self.assertEqual(restore["status"], "planned-not-restored")
            self.assertFalse(restore["automatic_execution"])
            self.assertEqual(snapshot["source_sha256"], snapshot["snapshot_sha256"])

    def test_patch_impact_is_in_memory_and_identifies_section(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            sample = Path(temp) / "fixture.exe"
            original = build_test_pe()
            sample.write_bytes(original)
            plan = create_patch_plan(
                sample,
                offset=0x220,
                expected="48",
                replacement="59",
                rationale="fixture-only",
            )
            impact = preview_patch_impact(sample, plan)
            self.assertEqual(impact["status"], "preview-only-not-written")
            self.assertFalse(impact["mutation_performed"])
            self.assertEqual(impact["changes"][0]["section"]["name"], ".text")
            self.assertNotEqual(impact["source_sha256"], impact["projected_sha256"])
            self.assertEqual(sample.read_bytes(), original)

    def test_binary_inventory_marks_completeness_limits(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            sample = Path(temp) / "fixture.exe"
            sample.write_bytes(build_test_pe())
            inventory = build_binary_inventory(sample)
        self.assertEqual(inventory["inventory_type"], "binary-dependency-evidence")
        self.assertFalse(inventory["compliance"]["cyclonedx"])
        self.assertEqual(inventory["dependencies"][0]["name"], "KERNEL32.dll")
        self.assertTrue(inventory["limitations"])


if __name__ == "__main__":
    unittest.main()
