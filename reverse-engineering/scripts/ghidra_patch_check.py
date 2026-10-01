from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path


def main() -> int:
    project = Path(__file__).resolve().parents[1]
    patch = project / "assets" / "ghidra-mcp" / "GhidraMCP-12.1.2.patch"
    source = Path(r"C:\Users\beessy\Tools\GhidraMCP")
    with tempfile.TemporaryDirectory(prefix="ghidra-patch-check-") as temporary:
        checkout = Path(temporary) / "GhidraMCP"
        subprocess.run(
            ["git", "clone", "--quiet", str(source), str(checkout)], check=True
        )
        subprocess.run(
            ["git", "-C", str(checkout), "checkout", "--quiet", "27f316f80139e2d5dec882519a1bdf4aa46ac04c"],
            check=True,
        )
        subprocess.run(["git", "-C", str(checkout), "apply", "--check", "--ignore-space-change", str(patch)], check=True)
        subprocess.run(["git", "-C", str(checkout), "apply", "--ignore-space-change", str(patch)], check=True)
        subprocess.run(["git", "-C", str(checkout), "diff", "--check"], check=True)
        shutil.copy2(
            project / "assets" / "ghidra-mcp" / "bridge_mcp_ghidra.py",
            checkout / "bridge_mcp_ghidra.py",
        )
        if "ghidra.mcp.token" not in (checkout / "src/main/java/com/lauriewired/GhidraMCPPlugin.java").read_text(encoding="utf-8"):
            raise RuntimeError("token authentication patch missing")
        if "setAuthenticator" not in (checkout / "src/main/java/com/lauriewired/GhidraMCPPlugin.java").read_text(encoding="utf-8"):
            raise RuntimeError("route authentication filter missing")
        bridge = (checkout / "bridge_mcp_ghidra.py").read_text(encoding="utf-8")
        if "def ghidra_health" not in bridge or '"Authorization": f"Bearer {token}"' not in bridge:
            raise RuntimeError("authenticated Ghidra bridge changes missing")
        if "def _filter_tools(profile: str)" not in bridge or '"read_write"' not in bridge:
            raise RuntimeError("Ghidra read-only/read-write profile enforcement missing")
        plugin = (checkout / "src/main/java/com/lauriewired/GhidraMCPPlugin.java").read_text(encoding="utf-8")
        auth_test = (checkout / "src/test/java/com/lauriewired/AppTest.java").read_text(encoding="utf-8")
        if "static Authenticator bearerAuthenticator(String token)" not in plugin:
            raise RuntimeError("testable bearer authenticator missing")
        if "testBearerAuthenticatorRejectsMissingAndWrongTokensAndAcceptsValidToken" not in auth_test:
            raise RuntimeError("behavioral bearer-auth test missing")
        print("patch applies cleanly to pinned upstream commit")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
