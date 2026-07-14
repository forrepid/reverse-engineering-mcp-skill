from __future__ import annotations

import socket
import time
from dataclasses import asdict, dataclass
from typing import Iterator

from .models import utc_now


@dataclass(frozen=True)
class HostEndpoint:
    name: str
    host: str
    port: int
    purpose: str

    def __post_init__(self) -> None:
        if self.host not in {"127.0.0.1", "::1", "localhost"}:
            raise ValueError("v0 host discovery is loopback-only")
        if not 1 <= self.port <= 65535:
            raise ValueError("invalid TCP port")


DEFAULT_ENDPOINTS = (
    HostEndpoint("ida-gui-mcp", "127.0.0.1", 13337, "IDA GUI MCP"),
    HostEndpoint("idalib-mcp", "127.0.0.1", 8745, "Headless idalib MCP"),
    HostEndpoint("ghidra-plugin", "127.0.0.1", 8080, "GhidraMCP plugin"),
    HostEndpoint("ghidra-mcp-bridge", "127.0.0.1", 8081, "Ghidra MCP bridge"),
)


def probe_endpoint(endpoint: HostEndpoint, timeout: float = 0.25) -> dict[str, object]:
    if not 0.05 <= timeout <= 5.0:
        raise ValueError("probe timeout must be between 0.05 and 5 seconds")
    started = time.perf_counter()
    online = False
    error = ""
    try:
        with socket.create_connection(
            (endpoint.host, endpoint.port), timeout=timeout
        ):
            online = True
    except OSError as caught:
        error = caught.__class__.__name__
    elapsed_ms = round((time.perf_counter() - started) * 1000, 2)
    return {
        **asdict(endpoint),
        "online": online,
        "probe": "tcp-connect-only",
        "latency_ms": elapsed_ms,
        "error_class": error,
        "observed_at": utc_now(),
    }


def host_snapshot(
    endpoints: tuple[HostEndpoint, ...] = DEFAULT_ENDPOINTS,
    *,
    timeout: float = 0.25,
) -> list[dict[str, object]]:
    return [probe_endpoint(endpoint, timeout=timeout) for endpoint in endpoints]


def watch_host_transitions(
    endpoints: tuple[HostEndpoint, ...] = DEFAULT_ENDPOINTS,
    *,
    interval: float = 2.0,
    duration: float = 0.0,
    timeout: float = 0.25,
) -> Iterator[dict[str, object]]:
    if not 0.25 <= interval <= 60:
        raise ValueError("watch interval must be between 0.25 and 60 seconds")
    if duration < 0:
        raise ValueError("duration cannot be negative")
    previous: dict[str, bool] = {}
    started = time.monotonic()
    while True:
        for status in host_snapshot(endpoints, timeout=timeout):
            name = str(status["name"])
            online = bool(status["online"])
            if name not in previous or previous[name] != online:
                yield {
                    "event": "host-online" if online else "host-offline",
                    **status,
                }
            previous[name] = online
        if duration and time.monotonic() - started >= duration:
            return
        time.sleep(interval)
