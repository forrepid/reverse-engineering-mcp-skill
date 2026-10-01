from __future__ import annotations

import socket
from typing import Any, TypedDict


# Official project docs describe these common local UI/API ports. They are
# candidates only: a listening port is never treated as broker identity.
class BrokerCandidate(TypedDict):
    provider: str
    host: str
    port: int
    base_url: str


LOCAL_BROKER_CANDIDATES: tuple[BrokerCandidate, ...] = (
    {"provider": "cape", "host": "127.0.0.1", "port": 8000, "base_url": "http://127.0.0.1:8000/apiv2/"},
    {"provider": "drakvuf", "host": "127.0.0.1", "port": 5000, "base_url": "http://127.0.0.1:5000/"},
    {"provider": "cape-distributed", "host": "127.0.0.1", "port": 9003, "base_url": "http://127.0.0.1:9003/"},
)


def discover_local_brokers(*, timeout_seconds: float = 0.15) -> list[dict[str, Any]]:
    """Probe only three documented loopback ports using TCP connect; no requests/data sent."""
    if not 0.01 <= timeout_seconds <= 1:
        raise ValueError("loopback probe timeout must be between 0.01 and 1 second")
    results = []
    for candidate in LOCAL_BROKER_CANDIDATES:
        try:
            with socket.create_connection(
                (candidate["host"], candidate["port"]), timeout=timeout_seconds
            ):
                reachable = True
        except OSError:
            reachable = False
        results.append(
            {
                **candidate,
                "reachable": reachable,
                "identity_verified": False,
                "probe": "loopback TCP connect only",
                "note": "A reachable port is only a candidate; verify service identity, TLS/auth, broker ID, and signing-key pin separately.",
            }
        )
    return results
