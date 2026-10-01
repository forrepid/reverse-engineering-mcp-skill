from __future__ import annotations

import importlib.util
from typing import Any
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

from verify_ghidra_mcp import _verify_http_auth


ROOT = Path(__file__).resolve().parents[1]
BRIDGE = ROOT / "assets" / "ghidra-mcp" / "bridge_mcp_ghidra.py"
READ_ONLY = {
    "ghidra_health", "list_methods", "list_classes", "decompile_function",
    "list_segments", "list_imports", "list_exports", "list_namespaces",
    "list_data_items", "search_functions_by_name", "get_function_by_address",
    "get_current_address", "get_current_function", "list_functions",
    "disassemble_function", "xrefs_to", "xrefs_from", "function_xrefs",
    "list_strings",
}
READ_WRITE = READ_ONLY | {
    "rename_function", "rename_function_by_address", "rename_data",
    "rename_variable", "set_comment", "set_decompiler_comment",
    "set_disassembly_comment", "set_function_prototype", "set_local_variable_type",
}
sys.path.insert(0, str(ROOT / "scripts"))


class ToolManager:
    def __init__(self) -> None:
        self._tools = {"list_methods": object(), "rename_function": object()}


class FakeMcp:
    def __init__(self) -> None:
        self._tool_manager = ToolManager()


class GhidraBridgeTests(unittest.TestCase):
    def test_live_verifier_rejects_legacy_unauthenticated_host(self) -> None:
        with patch(
            "verify_ghidra_mcp._http_status",
            side_effect=[(200, "status=ok"), (200, "status=ok"), (200, "status=ok")],
        ):
            with self.assertRaisesRegex(RuntimeError, "expected 401/401/200, got 200/200/200"):
                _verify_http_auth("http://127.0.0.1:8080/", "test-token")

    def test_live_verifier_accepts_only_401_401_200_auth_contract(self) -> None:
        with patch(
            "verify_ghidra_mcp._http_status",
            side_effect=[(401, ""), (401, ""), (200, "status=ok\\nprogram=demo.exe")],
        ):
            self.assertEqual(
                _verify_http_auth("http://127.0.0.1:8080/", "test-token"),
                {"missing_token": 401, "wrong_token": 401, "valid_token": 200},
            )

    def test_read_only_profile_removes_mutating_tools(self) -> None:
        spec = importlib.util.spec_from_file_location("reviewed_ghidra_bridge", BRIDGE)
        if spec is None or spec.loader is None:
            self.fail("bridge module cannot be loaded")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        fake_mcp = FakeMcp()
        fake_mcp._tool_manager._tools.update({name: object() for name in READ_ONLY})
        module.mcp = fake_mcp  # type: ignore[attr-defined]
        module._filter_tools("read_only")  # type: ignore[attr-defined]
        self.assertIn("list_methods", fake_mcp._tool_manager._tools)
        self.assertNotIn("rename_function", fake_mcp._tool_manager._tools)

    def test_read_write_profile_exposes_only_read_and_annotation_tools(self) -> None:
        spec = importlib.util.spec_from_file_location("reviewed_ghidra_bridge_rw", BRIDGE)
        if spec is None or spec.loader is None:
            self.fail("bridge module cannot be loaded")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        fake_mcp = FakeMcp()
        fake_mcp._tool_manager._tools.update({name: object() for name in READ_WRITE})
        fake_mcp._tool_manager._tools.update({"patch_bytes": object(), "execute_script": object()})
        module.mcp = fake_mcp  # type: ignore[attr-defined]
        module._filter_tools("read_write")  # type: ignore[attr-defined]
        self.assertIn("rename_function", fake_mcp._tool_manager._tools)
        self.assertIn("list_methods", fake_mcp._tool_manager._tools)
        self.assertNotIn("patch_bytes", fake_mcp._tool_manager._tools)
        self.assertNotIn("execute_script", fake_mcp._tool_manager._tools)

    def test_http_client_attaches_bearer_token(self) -> None:
        spec = importlib.util.spec_from_file_location("reviewed_ghidra_bridge", BRIDGE)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        class Response:
            ok = True
            text = "status=ok\n"
            encoding = ""

        class Client:
            def get(self, url: str, **kwargs: Any) -> Response:
                self.kwargs = kwargs
                return Response()

        client = Client()
        with patch.dict("os.environ", {"RE_GHIDRA_TOKEN": "t" * 40}):
            module.requests = client  # type: ignore[attr-defined]
            module.safe_get("health")  # type: ignore[attr-defined]
        self.assertEqual(client.kwargs["headers"]["Authorization"], "Bearer " + "t" * 40)


if __name__ == "__main__":
    unittest.main()
