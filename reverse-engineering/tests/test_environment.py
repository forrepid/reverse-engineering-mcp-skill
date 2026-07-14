from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from re_core.environment import (
    EnvironmentConfigError,
    environment_contract,
    load_runtime_environment,
    parse_env_assignments,
    parse_env_file,
    resolve_config_environment,
)


class EnvironmentContractTests(unittest.TestCase):
    def test_contract_has_nine_visible_non_secret_defaults(self) -> None:
        payload = environment_contract({})
        self.assertEqual(payload["required_count"], 0)
        self.assertEqual(payload["secret_count"], 0)
        self.assertFalse(payload["automatic_dotenv_loading"])
        self.assertEqual(len(payload["variables"]), 9)
        self.assertEqual(payload["runtime"]["mode"], "read_only")

    def test_assignments_and_env_file_are_validated(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            env_file = Path(temporary) / ".env"
            env_file.write_text(
                "RE_MCP_LOG_LEVEL=INFO\nRE_MCP_MAX_REGION_BYTES=4096\n",
                encoding="utf-8",
            )
            self.assertEqual(parse_env_file(env_file)["RE_MCP_LOG_LEVEL"], "INFO")
            resolved = resolve_config_environment(
                env_file=env_file,
                assignments=("RE_MCP_LOG_LEVEL=ERROR",),
            )
            self.assertEqual(resolved["RE_MCP_LOG_LEVEL"], "ERROR")
            self.assertEqual(resolved["RE_MCP_MAX_REGION_BYTES"], "4096")

    def test_unknown_or_unsafe_values_fail_closed(self) -> None:
        with self.assertRaises(EnvironmentConfigError):
            parse_env_assignments(("API_KEY=secret",))
        with self.assertRaises(EnvironmentConfigError):
            load_runtime_environment({"RE_MCP_MODE": "patch_apply"})
        with self.assertRaises(EnvironmentConfigError):
            load_runtime_environment({"RE_MCP_MAX_REGION_BYTES": "not-a-number"})
        with self.assertRaises(EnvironmentConfigError):
            load_runtime_environment({"RE_MCP_UNKNOWN": "fail-closed"})

    def test_allowed_roots_restrict_file_access(self) -> None:
        with tempfile.TemporaryDirectory() as allowed_temporary:
            with tempfile.TemporaryDirectory() as outside_temporary:
                allowed = Path(allowed_temporary).resolve()
                inside = allowed / "inside.bin"
                outside = Path(outside_temporary).resolve() / "outside.bin"
                inside.write_bytes(b"inside")
                outside.write_bytes(b"outside")
                runtime = load_runtime_environment(
                    {"RE_MCP_ALLOWED_ROOTS": str(allowed)}
                )
                self.assertEqual(runtime.validate_file(inside), inside)
                with self.assertRaises(EnvironmentConfigError):
                    runtime.validate_file(outside)

    def test_path_list_uses_platform_separator(self) -> None:
        with tempfile.TemporaryDirectory() as first:
            with tempfile.TemporaryDirectory() as second:
                runtime = load_runtime_environment(
                    {"RE_MCP_ALLOWED_ROOTS": os.pathsep.join((first, second))}
                )
                self.assertEqual(len(runtime.allowed_roots), 2)


if __name__ == "__main__":
    unittest.main()
