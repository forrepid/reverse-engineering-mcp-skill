from __future__ import annotations

import json
import sys
import tempfile
import tomllib
import unittest
from pathlib import Path

from re_core.client_configs import (
    CLIENTS,
    ClientConfigError,
    client_profiles,
    render_all_client_configs,
    render_client_config,
)


ROOT = Path(__file__).resolve().parents[1]
COMPANION = ROOT / "scripts" / "re_mcp_server.py"


class ClientProfileTests(unittest.TestCase):
    def test_eight_requested_clients_have_distinct_profiles(self) -> None:
        payload = client_profiles()
        self.assertEqual(payload["count"], 8)
        self.assertEqual(
            {item.id for item in CLIENTS},
            {
                "codex",
                "claude-code",
                "qwen-code",
                "vscode",
                "visual-studio",
                "zed",
                "antigravity",
                "kimi",
            },
        )

    def test_every_rendered_config_has_the_companion_server(self) -> None:
        for profile in CLIENTS:
            with self.subTest(client=profile.id):
                rendered = render_client_config(
                    profile.id,
                    python_executable=sys.executable,
                    companion_script=COMPANION,
                )
                if profile.format == "toml":
                    payload = tomllib.loads(rendered)
                    servers = payload["mcp_servers"]
                else:
                    payload = json.loads(rendered)
                    servers = payload[profile.root_key]
                self.assertIn("reverse-engineering-companion", servers)
                self.assertEqual(
                    servers["reverse-engineering-companion"]["command"],
                    str(Path(sys.executable).resolve()),
                )
                environment = servers["reverse-engineering-companion"]["env"]
                self.assertEqual(environment["RE_MCP_MODE"], "read_only")
                self.assertEqual(environment["RE_MCP_LOG_LEVEL"], "WARNING")
                self.assertEqual(len(environment), 9)


class ClientConfigGenerationTests(unittest.TestCase):
    def test_generates_all_configs_and_idalib_without_installing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            idalib = root / "idalib-mcp.exe"
            idalib.write_bytes(b"")
            output = root / "configs"
            payload = render_all_client_configs(
                output,
                python_executable=sys.executable,
                companion_script=COMPANION,
                idalib_mcp=idalib,
            )
            self.assertEqual(payload["status"], "generated-not-installed")
            self.assertFalse(payload["automatic_installation"])
            self.assertEqual(len(payload["outputs"]), 8)
            self.assertEqual(len(list(output.iterdir())), 9)
            manifest = json.loads(
                (output / "manifest.json").read_text(encoding="utf-8")
            )
            self.assertEqual(
                manifest["servers"],
                ["reverse-engineering-companion", "ida-pro-idalib"],
            )
            self.assertEqual(
                manifest["companion_environment"]["RE_MCP_MAX_REGION_BYTES"],
                "1048576",
            )
            with self.assertRaises(ClientConfigError):
                render_all_client_configs(
                    output,
                    python_executable=sys.executable,
                    companion_script=COMPANION,
                    idalib_mcp=idalib,
                )

    def test_environment_overrides_are_allowlisted_and_rendered(self) -> None:
        rendered = render_client_config(
            "claude-code",
            python_executable=sys.executable,
            companion_script=COMPANION,
            env_assignments=(
                "RE_MCP_LOG_LEVEL=INFO",
                "RE_MCP_MAX_REGION_BYTES=2048",
            ),
        )
        environment = json.loads(rendered)["mcpServers"][
            "reverse-engineering-companion"
        ]["env"]
        self.assertEqual(environment["RE_MCP_LOG_LEVEL"], "INFO")
        self.assertEqual(environment["RE_MCP_MAX_REGION_BYTES"], "2048")

    def test_rejects_unreviewed_idalib_basename(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            wrong = Path(temporary) / "server.exe"
            wrong.write_bytes(b"")
            with self.assertRaises(ClientConfigError):
                render_client_config(
                    "codex",
                    python_executable=sys.executable,
                    companion_script=COMPANION,
                    idalib_mcp=wrong,
                )

    def test_ghidra_bridge_is_rendered_and_must_be_loopback(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            bridge = Path(temporary) / "bridge_mcp_ghidra.py"
            bridge.write_text("# fixture\n", encoding="utf-8")
            rendered = render_client_config(
                "codex",
                python_executable=sys.executable,
                companion_script=COMPANION,
                ghidra_bridge=bridge,
            )
            server = tomllib.loads(rendered)["mcp_servers"]["ghidra-mcp"]
            self.assertEqual(server["args"][-1], "http://127.0.0.1:8080/")
            with self.assertRaises(ClientConfigError):
                render_client_config(
                    "codex",
                    python_executable=sys.executable,
                    companion_script=COMPANION,
                    ghidra_bridge=bridge,
                    ghidra_server="http://example.com:8080/",
                )


if __name__ == "__main__":
    unittest.main()
