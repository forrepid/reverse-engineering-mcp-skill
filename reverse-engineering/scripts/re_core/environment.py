from __future__ import annotations

import os
import json
import tempfile
import sys
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .broker_config import BROKER_ENV, load_broker_config


class EnvironmentConfigError(RuntimeError):
    """Raised when the companion MCP environment contract is invalid."""


@dataclass(frozen=True)
class EnvironmentVariable:
    name: str
    value_type: str
    default: str
    description: str
    required: bool = False
    sensitive: bool = False
    allowed_values: tuple[str, ...] = ()
    minimum: int | None = None
    maximum: int | None = None


ENVIRONMENT_VARIABLES: tuple[EnvironmentVariable, ...] = (
    EnvironmentVariable(
        "RE_MCP_MODE",
        "enum",
        "read_only",
        "Companion capability mode. The portable server accepts read_only only.",
        allowed_values=("read_only",),
    ),
    EnvironmentVariable(
        "RE_MCP_LOG_LEVEL",
        "enum",
        "WARNING",
        "Server diagnostic level written to stderr; stdout remains MCP protocol only.",
        allowed_values=("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"),
    ),
    EnvironmentVariable(
        "RE_MCP_MAX_FILE_BYTES",
        "integer",
        "536870912",
        "Largest local artifact accepted by companion tools, in bytes.",
        minimum=1,
        maximum=4 * 1024 * 1024 * 1024,
    ),
    EnvironmentVariable(
        "RE_MCP_MAX_REGION_BYTES",
        "integer",
        "1048576",
        "Largest byte range accepted by bounded selection or XOR analysis.",
        minimum=1,
        maximum=16 * 1024 * 1024,
    ),
    EnvironmentVariable(
        "RE_MCP_MAX_SCAN_BYTES",
        "integer",
        "67108864",
        "Largest range accepted by entropy scans or static/runtime dump plans.",
        minimum=256,
        maximum=512 * 1024 * 1024,
    ),
    EnvironmentVariable(
        "RE_MCP_ALLOWED_ROOTS",
        "path-list",
        "",
        "Optional os.pathsep-separated allowlist of directories containing authorized samples.",
    ),
    EnvironmentVariable(
        "RE_MCP_PROVIDER_CONFIG",
        "file-path",
        "",
        "Optional reviewed JSON file containing provider executable overrides and non-secret options.",
    ),
    EnvironmentVariable(
        "RE_MCP_PROVIDER_TIMEOUT_SECONDS",
        "integer",
        "120",
        "Default timeout for an explicitly requested static provider process.",
        minimum=1,
        maximum=900,
    ),
    EnvironmentVariable(
        "RE_MCP_MAX_PROVIDER_OUTPUT_BYTES",
        "integer",
        "4194304",
        "Maximum captured stdout and stderr bytes per provider stream.",
        minimum=1024,
        maximum=64 * 1024 * 1024,
    ),
    EnvironmentVariable("RE_MCP_MAX_ARCHIVE_MEMBERS", "integer", "100000", "Maximum archive members inspected.", minimum=1, maximum=1_000_000),
    EnvironmentVariable("RE_MCP_MAX_ARCHIVE_EXPANDED_BYTES", "integer", "4294967296", "Maximum cumulative declared archive expansion, in bytes.", minimum=1, maximum=64 * 1024 * 1024 * 1024),
    EnvironmentVariable("RE_MCP_MAX_ARCHIVE_MEMBER_RATIO", "integer", "1000", "Maximum per-member expansion ratio; integer ratio.", minimum=1, maximum=100_000),
    EnvironmentVariable("RE_MCP_ARCHIVE_TIMEOUT_SECONDS", "integer", "30", "Maximum wall time for archive metadata auditing.", minimum=1, maximum=900),
)

_VARIABLE_BY_NAME = {item.name: item for item in ENVIRONMENT_VARIABLES}

_SETTING_TO_ENV = {
    "max_file_bytes": "RE_MCP_MAX_FILE_BYTES",
    "max_region_bytes": "RE_MCP_MAX_REGION_BYTES",
    "max_scan_bytes": "RE_MCP_MAX_SCAN_BYTES",
    "provider_timeout_seconds": "RE_MCP_PROVIDER_TIMEOUT_SECONDS",
    "max_provider_output_bytes": "RE_MCP_MAX_PROVIDER_OUTPUT_BYTES",
    "max_archive_members": "RE_MCP_MAX_ARCHIVE_MEMBERS",
    "max_archive_expanded_bytes": "RE_MCP_MAX_ARCHIVE_EXPANDED_BYTES",
    "max_archive_member_ratio": "RE_MCP_MAX_ARCHIVE_MEMBER_RATIO",
    "archive_timeout_seconds": "RE_MCP_ARCHIVE_TIMEOUT_SECONDS",
}
SETTINGS_KEYS = _SETTING_TO_ENV


def settings_path() -> Path:
    """Return the per-user persistent settings file location."""
    if os.name == "nt":
        base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData/Local"))
    elif sys_platform := sys.platform:
        if sys_platform == "darwin":
            base = Path.home() / "Library/Application Support"
        else:
            base = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
    return base / "reverse-engineering-companion" / "settings.json"


def read_saved_settings(path: str | Path | None = None) -> dict[str, str]:
    target = Path(path) if path is not None else settings_path()
    if not target.exists():
        return {}
    if target.stat().st_size > 64 * 1024:
        raise EnvironmentConfigError("saved settings file exceeds the 64 KiB limit")
    try:
        payload = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise EnvironmentConfigError(f"cannot read saved settings: {error}") from error
    if not isinstance(payload, dict) or payload.get("schema_version") != "1":
        raise EnvironmentConfigError("saved settings have an unsupported schema")
    values = payload.get("values")
    if not isinstance(values, dict):
        raise EnvironmentConfigError("saved settings values must be an object")
    unknown = sorted(set(values) - set(_SETTING_TO_ENV))
    if unknown:
        raise EnvironmentConfigError("unknown saved setting(s): " + ", ".join(unknown))
    return {key: str(value) for key, value in values.items()}


def save_setting(key: str, value: str | int, path: str | Path | None = None) -> Path:
    if key not in _SETTING_TO_ENV:
        raise EnvironmentConfigError("unknown setting; expected: " + ", ".join(_SETTING_TO_ENV))
    target = Path(path) if path is not None else settings_path()
    current = read_saved_settings(target)
    name = _SETTING_TO_ENV[key]
    parsed = _integer(name, str(value))
    candidate = dict(current)
    candidate[key] = str(parsed)
    validate_values = {_SETTING_TO_ENV[item]: val for item, val in candidate.items()}
    for env_name, env_value in os.environ.items():
        if env_name in _SETTING_TO_ENV.values():
            validate_values[env_name] = env_value
    _validate_limit_values(validate_values)
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix="settings-", suffix=".tmp", dir=target.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump({"schema_version": "1", "values": candidate}, stream, indent=2)
            stream.write("\n")
        os.replace(temporary, target)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return target


def _validate_limit_values(values: Mapping[str, str]) -> None:
    parsed = {
        name: _integer(name, value)
        for name, value in values.items()
        if name in _SETTING_TO_ENV.values()
    }
    file_limit = parsed.get("RE_MCP_MAX_FILE_BYTES", int(_VARIABLE_BY_NAME["RE_MCP_MAX_FILE_BYTES"].default))
    if parsed.get("RE_MCP_MAX_REGION_BYTES", int(_VARIABLE_BY_NAME["RE_MCP_MAX_REGION_BYTES"].default)) > file_limit:
        raise EnvironmentConfigError("RE_MCP_MAX_REGION_BYTES cannot exceed RE_MCP_MAX_FILE_BYTES")
    if parsed.get("RE_MCP_MAX_SCAN_BYTES", int(_VARIABLE_BY_NAME["RE_MCP_MAX_SCAN_BYTES"].default)) > file_limit:
        raise EnvironmentConfigError("RE_MCP_MAX_SCAN_BYTES cannot exceed RE_MCP_MAX_FILE_BYTES")


@dataclass(frozen=True)
class RuntimeEnvironment:
    mode: str
    log_level: str
    max_file_bytes: int
    max_region_bytes: int
    max_scan_bytes: int
    allowed_roots: tuple[Path, ...]
    provider_config: Path | None
    provider_timeout_seconds: int
    max_provider_output_bytes: int
    max_archive_members: int
    max_archive_expanded_bytes: int
    max_archive_member_ratio: int
    archive_timeout_seconds: int

    def as_env(self) -> dict[str, str]:
        return {
            "RE_MCP_MODE": self.mode,
            "RE_MCP_LOG_LEVEL": self.log_level,
            "RE_MCP_MAX_FILE_BYTES": str(self.max_file_bytes),
            "RE_MCP_MAX_REGION_BYTES": str(self.max_region_bytes),
            "RE_MCP_MAX_SCAN_BYTES": str(self.max_scan_bytes),
            "RE_MCP_ALLOWED_ROOTS": os.pathsep.join(
                str(root) for root in self.allowed_roots
            ),
            "RE_MCP_PROVIDER_CONFIG": (
                str(self.provider_config) if self.provider_config is not None else ""
            ),
            "RE_MCP_PROVIDER_TIMEOUT_SECONDS": str(self.provider_timeout_seconds),
            "RE_MCP_MAX_PROVIDER_OUTPUT_BYTES": str(self.max_provider_output_bytes),
            "RE_MCP_MAX_ARCHIVE_MEMBERS": str(self.max_archive_members),
            "RE_MCP_MAX_ARCHIVE_EXPANDED_BYTES": str(self.max_archive_expanded_bytes),
            "RE_MCP_MAX_ARCHIVE_MEMBER_RATIO": str(self.max_archive_member_ratio),
            "RE_MCP_ARCHIVE_TIMEOUT_SECONDS": str(self.archive_timeout_seconds),
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "mode": self.mode,
            "log_level": self.log_level,
            "max_file_bytes": self.max_file_bytes,
            "max_region_bytes": self.max_region_bytes,
            "max_scan_bytes": self.max_scan_bytes,
            "allowed_roots": [str(root) for root in self.allowed_roots],
            "root_restriction_enabled": bool(self.allowed_roots),
            "provider_config": (
                str(self.provider_config) if self.provider_config is not None else None
            ),
            "provider_timeout_seconds": self.provider_timeout_seconds,
            "max_provider_output_bytes": self.max_provider_output_bytes,
            "max_archive_members": self.max_archive_members,
            "max_archive_expanded_bytes": self.max_archive_expanded_bytes,
            "max_archive_member_ratio": self.max_archive_member_ratio,
            "archive_timeout_seconds": self.archive_timeout_seconds,
        }

    def validate_file(self, path: str | Path) -> Path:
        resolved = Path(path).expanduser().resolve()
        if not resolved.is_file():
            raise EnvironmentConfigError(f"not a regular file: {resolved}")
        if self.allowed_roots and not any(
            resolved.is_relative_to(root) for root in self.allowed_roots
        ):
            raise EnvironmentConfigError(
                f"file is outside RE_MCP_ALLOWED_ROOTS: {resolved}"
            )
        size = resolved.stat().st_size
        if size > self.max_file_bytes:
            raise EnvironmentConfigError(
                f"file size {size} exceeds RE_MCP_MAX_FILE_BYTES={self.max_file_bytes}"
            )
        return resolved

    def validate_region(self, length: int) -> None:
        if length < 1 or length > self.max_region_bytes:
            raise EnvironmentConfigError(
                "region length must be between 1 and "
                f"RE_MCP_MAX_REGION_BYTES={self.max_region_bytes}"
            )

    def validate_scan(self, length: int) -> None:
        if length < 1 or length > self.max_scan_bytes:
            raise EnvironmentConfigError(
                "scan length must be between 1 and "
                f"RE_MCP_MAX_SCAN_BYTES={self.max_scan_bytes}"
            )


def _integer(name: str, value: str) -> int:
    try:
        parsed = int(value, 10)
    except ValueError as error:
        raise EnvironmentConfigError(f"{name} must be a base-10 integer") from error
    spec = _VARIABLE_BY_NAME[name]
    if spec.minimum is not None and parsed < spec.minimum:
        raise EnvironmentConfigError(f"{name} must be at least {spec.minimum}")
    if spec.maximum is not None and parsed > spec.maximum:
        raise EnvironmentConfigError(f"{name} must be at most {spec.maximum}")
    return parsed


def _known_values(values: Mapping[str, str]) -> dict[str, str]:
    unknown = sorted(set(values) - set(_VARIABLE_BY_NAME))
    if unknown:
        raise EnvironmentConfigError(
            "unknown companion environment variable(s): " + ", ".join(unknown)
        )
    merged = {item.name: item.default for item in ENVIRONMENT_VARIABLES}
    merged.update({name: str(value) for name, value in values.items()})
    return merged


def load_runtime_environment(
    environ: Mapping[str, str] | None = None,
) -> RuntimeEnvironment:
    source = os.environ if environ is None else environ
    unknown = sorted(
        name
        for name in source
        if name.startswith("RE_MCP_") and name not in _VARIABLE_BY_NAME
    )
    if unknown:
        raise EnvironmentConfigError(
            "unknown companion environment variable(s): " + ", ".join(unknown)
        )
    saved = read_saved_settings()
    selected = {
        _SETTING_TO_ENV[key]: value
        for key, value in saved.items()
        if _SETTING_TO_ENV[key] not in source
    }
    selected.update({name: source[name] for name in _VARIABLE_BY_NAME if name in source})
    values = _known_values(selected)
    _validate_limit_values({name: values[name] for name in _SETTING_TO_ENV.values()})
    mode = values["RE_MCP_MODE"].strip().lower()
    if mode != "read_only":
        raise EnvironmentConfigError("RE_MCP_MODE must be read_only")
    log_level = values["RE_MCP_LOG_LEVEL"].strip().upper()
    if log_level not in _VARIABLE_BY_NAME["RE_MCP_LOG_LEVEL"].allowed_values:
        raise EnvironmentConfigError(
            "RE_MCP_LOG_LEVEL must be DEBUG, INFO, WARNING, ERROR, or CRITICAL"
        )
    max_file_bytes = _integer(
        "RE_MCP_MAX_FILE_BYTES", values["RE_MCP_MAX_FILE_BYTES"].strip()
    )
    max_region_bytes = _integer(
        "RE_MCP_MAX_REGION_BYTES", values["RE_MCP_MAX_REGION_BYTES"].strip()
    )
    max_scan_bytes = _integer(
        "RE_MCP_MAX_SCAN_BYTES", values["RE_MCP_MAX_SCAN_BYTES"].strip()
    )
    if max_region_bytes > max_file_bytes:
        raise EnvironmentConfigError(
            "RE_MCP_MAX_REGION_BYTES cannot exceed RE_MCP_MAX_FILE_BYTES"
        )
    if max_scan_bytes > max_file_bytes:
        raise EnvironmentConfigError(
            "RE_MCP_MAX_SCAN_BYTES cannot exceed RE_MCP_MAX_FILE_BYTES"
        )
    roots: list[Path] = []
    raw_roots = values["RE_MCP_ALLOWED_ROOTS"].strip()
    if raw_roots:
        for raw_root in raw_roots.split(os.pathsep):
            root = Path(raw_root).expanduser().resolve()
            if not root.is_dir():
                raise EnvironmentConfigError(
                    f"RE_MCP_ALLOWED_ROOTS entry is not a directory: {root}"
                )
            if root not in roots:
                roots.append(root)
    provider_config: Path | None = None
    raw_provider_config = values["RE_MCP_PROVIDER_CONFIG"].strip()
    if raw_provider_config:
        provider_config = Path(raw_provider_config).expanduser().resolve()
        if not provider_config.is_file():
            raise EnvironmentConfigError(
                f"RE_MCP_PROVIDER_CONFIG is not a file: {provider_config}"
            )
        if provider_config.suffix.lower() != ".json":
            raise EnvironmentConfigError("RE_MCP_PROVIDER_CONFIG must be a JSON file")
        if provider_config.stat().st_size > 64 * 1024:
            raise EnvironmentConfigError("RE_MCP_PROVIDER_CONFIG exceeds 64 KiB")
    provider_timeout_seconds = _integer(
        "RE_MCP_PROVIDER_TIMEOUT_SECONDS",
        values["RE_MCP_PROVIDER_TIMEOUT_SECONDS"].strip(),
    )
    max_provider_output_bytes = _integer(
        "RE_MCP_MAX_PROVIDER_OUTPUT_BYTES",
        values["RE_MCP_MAX_PROVIDER_OUTPUT_BYTES"].strip(),
    )
    max_archive_members = _integer("RE_MCP_MAX_ARCHIVE_MEMBERS", values["RE_MCP_MAX_ARCHIVE_MEMBERS"].strip())
    max_archive_expanded_bytes = _integer("RE_MCP_MAX_ARCHIVE_EXPANDED_BYTES", values["RE_MCP_MAX_ARCHIVE_EXPANDED_BYTES"].strip())
    max_archive_member_ratio = _integer("RE_MCP_MAX_ARCHIVE_MEMBER_RATIO", values["RE_MCP_MAX_ARCHIVE_MEMBER_RATIO"].strip())
    archive_timeout_seconds = _integer("RE_MCP_ARCHIVE_TIMEOUT_SECONDS", values["RE_MCP_ARCHIVE_TIMEOUT_SECONDS"].strip())
    return RuntimeEnvironment(
        mode=mode,
        log_level=log_level,
        max_file_bytes=max_file_bytes,
        max_region_bytes=max_region_bytes,
        max_scan_bytes=max_scan_bytes,
        allowed_roots=tuple(roots),
        provider_config=provider_config,
        provider_timeout_seconds=provider_timeout_seconds,
        max_provider_output_bytes=max_provider_output_bytes,
        max_archive_members=max_archive_members,
        max_archive_expanded_bytes=max_archive_expanded_bytes,
        max_archive_member_ratio=max_archive_member_ratio,
        archive_timeout_seconds=archive_timeout_seconds,
    )


def parse_env_assignments(assignments: Sequence[str]) -> dict[str, str]:
    values: dict[str, str] = {}
    for assignment in assignments:
        if "=" not in assignment:
            raise EnvironmentConfigError(
                f"environment assignment must use NAME=VALUE: {assignment}"
            )
        name, value = assignment.split("=", 1)
        name = name.strip()
        if name not in _VARIABLE_BY_NAME:
            raise EnvironmentConfigError(f"unknown companion environment variable: {name}")
        values[name] = value
    return values


def parse_env_file(path: str | Path) -> dict[str, str]:
    env_path = Path(path).expanduser().resolve()
    if not env_path.is_file():
        raise EnvironmentConfigError(f"environment file does not exist: {env_path}")
    if env_path.stat().st_size > 64 * 1024:
        raise EnvironmentConfigError("environment file exceeds the 64 KiB limit")
    values: dict[str, str] = {}
    for line_number, raw_line in enumerate(
        env_path.read_text(encoding="utf-8-sig").splitlines(), start=1
    ):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].lstrip()
        if "=" not in line:
            raise EnvironmentConfigError(
                f"invalid environment line {line_number}; expected NAME=VALUE"
            )
        name, value = line.split("=", 1)
        name = name.strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        if name not in _VARIABLE_BY_NAME and name not in BROKER_ENV:
            raise EnvironmentConfigError(
                f"unknown environment variable on line {line_number}: {name}"
            )
        values[name] = value
    return values


def resolve_config_environment(
    *,
    assignments: Sequence[str] = (),
    env_file: str | Path | None = None,
) -> dict[str, str]:
    values = {
        _SETTING_TO_ENV[key]: value for key, value in read_saved_settings().items()
    }
    file_values = parse_env_file(env_file) if env_file is not None else {}
    broker_values = {name: value for name, value in file_values.items() if name in BROKER_ENV}
    if broker_values:
        try:
            load_broker_config(broker_values)
        except ValueError as error:
            raise EnvironmentConfigError(f"invalid broker configuration: {error}") from error
    values.update({name: value for name, value in file_values.items() if name in _VARIABLE_BY_NAME})
    values.update(parse_env_assignments(assignments))
    resolved = load_runtime_environment(values).as_env()
    for name in _VARIABLE_BY_NAME:
        resolved[name] = values.get(name, resolved[name])
    return resolved


def environment_contract(
    environ: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    source = os.environ if environ is None else environ
    runtime = load_runtime_environment(source)
    effective = runtime.as_env()
    saved = read_saved_settings()
    variables: list[dict[str, Any]] = []
    for spec in ENVIRONMENT_VARIABLES:
        record = asdict(spec)
        record["allowed_values"] = list(spec.allowed_values)
        setting_key = next((key for key, name in _SETTING_TO_ENV.items() if name == spec.name), None)
        record["effective_value"] = (
            source[spec.name]
            if spec.name in source
            else saved[setting_key]
            if setting_key is not None and setting_key in saved
            else effective[spec.name]
        )
        record["source"] = (
            "environment" if spec.name in source
            else "saved_settings" if setting_key in saved
            else "default"
        )
        variables.append(record)
    return {
        "schema_version": "0.5.0",
        "prefix": "RE_MCP_",
        "required_count": sum(item.required for item in ENVIRONMENT_VARIABLES),
        "secret_count": sum(item.sensitive for item in ENVIRONMENT_VARIABLES),
        "automatic_dotenv_loading": False,
        "saved_settings_path": str(settings_path()),
        "precedence": "process environment > saved settings > defaults",
        "saved_settings": saved,
        "runtime": runtime.to_dict(),
        "variables": variables,
        "notes": [
            "No environment variable is required for the read-only companion.",
        "Only the documented allowlisted RE_MCP_* variables are accepted by config generation and runtime.",
            "Use client env fields or set variables before starting a direct stdio process.",
            "The server never enumerates or returns unrelated process environment variables.",
        ],
    }
