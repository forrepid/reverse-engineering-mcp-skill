from __future__ import annotations

import os
import json
import re
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Mapping
from urllib.parse import urlparse


class BrokerConfigError(ValueError):
    """Invalid or unsafe isolated-analysis broker configuration."""


BROKER_ENV = {
    "RE_BROKER_PROVIDER": "none",
    "RE_BROKER_BASE_URL": "",
    "RE_BROKER_ID": "",
    "RE_BROKER_TOKEN": "",
    "RE_BROKER_PUBLIC_KEY": "",
    "RE_BROKER_ALLOW_REMOTE_HTTPS": "false",
}
_ALLOWED_PROVIDERS = {"none", "mock", "cape", "drakvuf", "vmray", "internal"}
_HEX_DIGEST = re.compile(r"^(?:sha256:)?[0-9a-fA-F]{64}$")


@dataclass(frozen=True)
class BrokerConfig:
    provider: str
    base_url: str | None
    broker_id: str | None
    token: str | None
    public_key: str | None
    allow_remote_https: bool

    @property
    def configured(self) -> bool:
        if self.provider == "mock":
            return bool(self.base_url and self.broker_id)
        return bool(
            self.provider != "none"
            and self.base_url
            and self.broker_id
            and self.public_key
        )

    def public_status(self) -> dict[str, Any]:
        configured = self.configured
        return {
            "provider": self.provider,
            "status": (
                "test_only"
                if configured and self.provider == "mock"
                else "configured_unverified" if configured else "not_configured"
            ),
            "base_url": self.base_url,
            "broker_id": self.broker_id,
            "token_configured": bool(self.token),
            "public_key_sha256_pin": self.public_key,
            "allow_remote_https": self.allow_remote_https,
            "continuous_capture": False,
            "submission_enabled": False,
            "live_capture_ready": False,
            "required_outputs": [
                "normalized_trace.json",
                "reconstructed_pe_dump",
                "ed25519_attestation.json",
            ],
        }


def load_broker_config(environ: Mapping[str, str] | None = None) -> BrokerConfig:
    source = os.environ if environ is None else environ
    values = {key: source.get(key, default).strip() for key, default in BROKER_ENV.items()}
    provider = values["RE_BROKER_PROVIDER"].lower()
    if provider not in _ALLOWED_PROVIDERS:
        raise BrokerConfigError("RE_BROKER_PROVIDER must be none, mock, cape, drakvuf, vmray, or internal")
    remote_value = values["RE_BROKER_ALLOW_REMOTE_HTTPS"].lower()
    if remote_value not in {"true", "false"}:
        raise BrokerConfigError("RE_BROKER_ALLOW_REMOTE_HTTPS must be true or false")
    allow_remote = remote_value == "true"
    raw_url = values["RE_BROKER_BASE_URL"]
    base_url: str | None = None
    if raw_url:
        parsed = urlparse(raw_url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise BrokerConfigError("RE_BROKER_BASE_URL must be an absolute HTTP(S) URL")
        loopback = parsed.hostname.lower() in {"localhost", "127.0.0.1", "::1"}
        if provider == "mock" and not loopback:
            raise BrokerConfigError("the test-only mock broker must bind to a loopback URL")
        if not loopback and not (allow_remote and parsed.scheme == "https"):
            raise BrokerConfigError("broker URL must be loopback, or HTTPS with RE_BROKER_ALLOW_REMOTE_HTTPS=true")
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise BrokerConfigError("broker URL must not contain credentials, query, or fragment")
        if parsed.scheme == "http" and not loopback:
            raise BrokerConfigError("remote broker connections require HTTPS")
        base_url = raw_url.rstrip("/")
    broker_id = values["RE_BROKER_ID"] or None
    if broker_id is not None and (len(broker_id) > 128 or not re.fullmatch(r"[A-Za-z0-9._:-]+", broker_id)):
        raise BrokerConfigError("RE_BROKER_ID contains unsupported characters or is too long")
    public_key = values["RE_BROKER_PUBLIC_KEY"].lower().removeprefix("sha256:") or None
    if public_key is not None and not _HEX_DIGEST.fullmatch(public_key):
        raise BrokerConfigError("RE_BROKER_PUBLIC_KEY must be a pinned Ed25519 public-key SHA-256 digest")
    if provider != "none" and not base_url:
        raise BrokerConfigError("a broker provider requires RE_BROKER_BASE_URL")
    if base_url and not broker_id:
        raise BrokerConfigError("a configured broker requires RE_BROKER_ID")
    if base_url and provider != "mock" and not public_key:
        raise BrokerConfigError("a configured broker requires an operator-pinned RE_BROKER_PUBLIC_KEY")
    return BrokerConfig(
        provider=provider,
        base_url=base_url,
        broker_id=broker_id,
        token=values["RE_BROKER_TOKEN"] or None,
        public_key=public_key,
        allow_remote_https=allow_remote,
    )


def probe_broker_health(config: BrokerConfig, *, timeout_seconds: float = 3.0) -> dict[str, Any]:
    """Probe the base URL only; never submits a task or sample."""
    if not config.configured or not config.base_url:
        return {"status": "not_configured", "reachable": False, "probe": None}
    headers = {"Accept": "application/json"}
    if config.token:
        headers["Authorization"] = f"Token {config.token}"
    request = urllib.request.Request(config.base_url + "/", headers=headers, method="GET")
    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
            body = response.read(64 * 1024 + 1)
            if len(body) > 64 * 1024:
                return {"status": "invalid_response", "reachable": True, "probe": "GET base URL only"}
            if config.provider == "mock":
                try:
                    payload = json.loads(body)
                except (json.JSONDecodeError, UnicodeDecodeError):
                    payload = None
                if (
                    not isinstance(payload, dict)
                    or payload.get("provider") != "mock"
                    or payload.get("mode") != "test_only"
                    or payload.get("broker_id") != config.broker_id
                    or payload.get("capture_supported") is not False
                    or payload.get("sample_submission_supported") is not False
                ):
                    return {
                        "status": "mock_identity_mismatch",
                        "reachable": True,
                        "probe": "GET base URL only",
                    }
            return {
                "status": "test_only" if config.provider == "mock" else "reachable",
                "reachable": 200 <= response.status < 300,
                "http_status": response.status,
                "probe": "GET base URL only",
                "capture_supported": False if config.provider == "mock" else None,
            }
    except urllib.error.HTTPError as error:
        # 401/403 proves a web service answered, not that it is authenticated.
        return {
            "status": "authentication_required" if error.code in {401, 403} else "http_error",
            "reachable": error.code in {401, 403},
            "http_status": error.code,
            "probe": "GET base URL only",
        }
    except (OSError, TimeoutError, ValueError) as error:
        return {
            "status": "unreachable",
            "reachable": False,
            "error": type(error).__name__,
            "probe": "GET base URL only",
        }
