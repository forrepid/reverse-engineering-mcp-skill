"""Loopback-only health endpoint for adapter wiring tests; never captures files."""

from __future__ import annotations

import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any


class MockBrokerHandler(BaseHTTPRequestHandler):
    server_version = "RE-Mock-Broker/1.0"

    def do_GET(self) -> None:  # noqa: N802 - stdlib handler API
        if self.path not in {"/", "/health"}:
            self.send_error(404)
            return
        body = json.dumps(
            {
                "broker_id": "mock-broker",
                "provider": "mock",
                "mode": "test_only",
                "health": "ok",
                "capture_supported": False,
                "sample_submission_supported": False,
                "signing_supported": False,
            }
        ).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:  # noqa: N802 - stdlib handler API
        self.send_error(405, "test mock never accepts submissions")

    def do_PUT(self) -> None:  # noqa: N802 - stdlib handler API
        self.send_error(405, "test mock is read-only")

    def log_message(self, format: str, *args: Any) -> None:
        return


class LoopbackMockBroker(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, port: int = 8765) -> None:
        super().__init__(("127.0.0.1", port), MockBrokerHandler)


def main() -> int:
    parser = argparse.ArgumentParser(description="Start a test-only, no-capture loopback broker")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()
    server = LoopbackMockBroker(args.port)
    print(f"Test-only mock broker listening at http://127.0.0.1:{server.server_port}/")
    print("Health checks only; all sample/task submissions are rejected.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
