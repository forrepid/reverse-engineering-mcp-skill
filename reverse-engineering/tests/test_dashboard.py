from __future__ import annotations

import json
import threading
import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from re_core.broker_discovery import LOCAL_BROKER_CANDIDATES
from re_core.dashboard import DashboardServer
from re_core.event_journal import append_oep_event, read_oep_events


class DashboardTests(unittest.TestCase):
    def test_event_journal_timestamps_and_filters_secrets_and_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            event = append_oep_event(
                "oep_runtime_verify",
                "Signed runtime evidence checked",
                "verified",
                {
                    "runtime_verified": True,
                    "runtime_oep_va": 0x401000,
                    "display_text": "Runtime OEP: VERIFIED",
                    "sample_path": "C:/private/sample.exe",
                    "token": "not-for-journal",
                },
                directory=temporary,
            )
            read_back = read_oep_events(directory=temporary)
        self.assertTrue(event["timestamp_utc"].endswith("Z"))
        datetime.fromisoformat(event["timestamp_utc"].replace("Z", "+00:00"))
        self.assertEqual(read_back[0]["event_id"], event["event_id"])
        self.assertNotIn("sample_path", read_back[0]["values"])
        self.assertNotIn("token", read_back[0]["values"])

    def test_dashboard_is_loopback_only_read_only_and_serves_live_json(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            events = Path(temporary) / "events"
            append_oep_event(
                "oep_static_candidates",
                "Static OEP candidates computed",
                "not_verified",
                {"declared_ep_va": 0x401000, "display_text": "Runtime OEP: NOT VERIFIED"},
                directory=events,
            )
            server = DashboardServer(0, event_dir=events)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            base_url = f"http://127.0.0.1:{server.server_port}"
            try:
                with urlopen(base_url + "/api/events?limit=10") as response:
                    payload = json.loads(response.read())
                self.assertEqual(payload["events"][0]["status"], "not_verified")
                with urlopen(base_url + "/") as response:
                    self.assertIn(b"Runtime OEP Dashboard", response.read())
                with self.assertRaises(HTTPError) as error:
                    urlopen(Request(base_url + "/api/events", data=b"{}", method="POST"))
                self.assertEqual(error.exception.code, 405)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=1)
        self.assertEqual(server.server_address[0], "127.0.0.1")

    def test_discovery_candidates_are_loopback_and_unverified(self) -> None:
        self.assertTrue(LOCAL_BROKER_CANDIDATES)
        self.assertTrue(all(item["host"] == "127.0.0.1" for item in LOCAL_BROKER_CANDIDATES))


if __name__ == "__main__":
    unittest.main()
