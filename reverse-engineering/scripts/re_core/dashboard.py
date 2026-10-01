from __future__ import annotations

import argparse
import json
import mimetypes
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from .broker_config import BrokerConfigError, load_broker_config
from .broker_discovery import discover_local_brokers
from .event_journal import read_oep_events


STATIC_ROOT = Path(__file__).with_name("dashboard_static")
STATIC_FILES = {
    "/": "index.html",
    "/index.html": "index.html",
    "/app.js": "app.js",
    "/styles.css": "styles.css",
    "/manifest.webmanifest": "manifest.webmanifest",
    "/sw.js": "sw.js",
    "/icon.svg": "icon.svg",
}


class DashboardHandler(BaseHTTPRequestHandler):
    server_version = "RE-OEP-Dashboard/1.0"

    def do_GET(self) -> None:  # noqa: N802 - stdlib handler API
        parsed = urlparse(self.path)
        if parsed.path == "/api/events":
            params = parse_qs(parsed.query)
            try:
                limit = int(params.get("limit", ["100"])[0])
            except ValueError:
                self._json(400, {"error": "limit must be an integer"})
                return
            try:
                events = read_oep_events(limit, directory=self.server.event_dir)  # type: ignore[attr-defined]
            except ValueError as error:
                self._json(400, {"error": str(error)})
                return
            self._json(200, {"events": events, "server_time_utc": _utc_now()})
            return
        if parsed.path == "/api/summary":
            events = read_oep_events(100, directory=self.server.event_dir)  # type: ignore[attr-defined]
            try:
                broker = load_broker_config().public_status()
            except BrokerConfigError:
                broker = {"status": "invalid_configuration"}
            latest_verified = next(
                (
                    item
                    for item in events
                    if item.get("operation") == "oep_runtime_verify"
                    and isinstance(item.get("values"), dict)
                    and item["values"].get("runtime_verified") is True
                ),
                None,
            )
            self._json(
                200,
                {
                    "server_time_utc": _utc_now(),
                    "latest_activity": events[0] if events else None,
                    "latest_verified_oep": latest_verified,
                    "broker": broker,
                    "local_broker_candidates": discover_local_brokers(),
                    "audit_policy": {
                        "local_event_writes": True,
                        "binary_or_host_mutation": False,
                        "network_scope": "loopback-only dashboard; discovery uses loopback TCP connect only",
                    },
                },
            )
            return
        filename = STATIC_FILES.get(parsed.path)
        if filename is None:
            self.send_error(404)
            return
        content = (STATIC_ROOT / filename).read_bytes()
        content_type = mimetypes.guess_type(filename)[0] or "application/octet-stream"
        if filename.endswith(".webmanifest"):
            content_type = "application/manifest+json"
        self._send(200, content, content_type, cache="no-cache")

    def do_POST(self) -> None:  # noqa: N802 - stdlib handler API
        self.send_error(405, "dashboard API is read-only")

    def do_PUT(self) -> None:  # noqa: N802 - stdlib handler API
        self.send_error(405, "dashboard API is read-only")

    def _json(self, status: int, payload: dict[str, Any]) -> None:
        content = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self._send(status, content, "application/json; charset=utf-8", cache="no-store")

    def _send(self, status: int, content: bytes, content_type: str, *, cache: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Cache-Control", cache)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'self'; connect-src 'self'; img-src 'self'; style-src 'self'; script-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
        self.end_headers()
        self.wfile.write(content)

    def log_message(self, format: str, *args: Any) -> None:
        return


class DashboardServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, port: int = 8766, event_dir: str | Path | None = None) -> None:
        super().__init__(("127.0.0.1", port), DashboardHandler)
        self.event_dir = Path(event_dir) if event_dir is not None else None


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def main() -> int:
    parser = argparse.ArgumentParser(description="Serve the loopback-only OEP PWA dashboard")
    parser.add_argument("--port", type=int, default=8766)
    args = parser.parse_args()
    server = DashboardServer(args.port)
    print(f"OEP dashboard: http://127.0.0.1:{server.server_port}/")
    print("Loopback-only, read-only UI/API; CTRL+C stops it.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
