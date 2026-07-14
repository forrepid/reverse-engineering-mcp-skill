from __future__ import annotations

import os
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


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
)

_VARIABLE_BY_NAME = {item.name: item for item in ENVIRONMENT_VARIABLES}


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
    selected = {
        name: source[name] for name in _VARIABLE_BY_NAME if name in source
    }
    values = _known_values(selected)
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
        if name not in _VARIABLE_BY_NAME:
            raise EnvironmentConfigError(
                f"unknown companion environment variable on line {line_number}: {name}"
            )
        values[name] = value
    return values


def resolve_config_environment(
    *,
    assignments: Sequence[str] = (),
    env_file: str | Path | None = None,
) -> dict[str, str]:
    values = parse_env_file(env_file) if env_file is not None else {}
    values.update(parse_env_assignments(assignments))
    return load_runtime_environment(values).as_env()


def environment_contract(
    environ: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    source = os.environ if environ is None else environ
    runtime = load_runtime_environment(source)
    effective = runtime.as_env()
    variables: list[dict[str, Any]] = []
    for spec in ENVIRONMENT_VARIABLES:
        record = asdict(spec)
        record["allowed_values"] = list(spec.allowed_values)
        record["effective_value"] = effective[spec.name]
        record["source"] = "environment" if spec.name in source else "default"
        variables.append(record)
    return {
        "schema_version": "0.5.0",
        "prefix": "RE_MCP_",
        "required_count": sum(item.required for item in ENVIRONMENT_VARIABLES),
        "secret_count": sum(item.sensitive for item in ENVIRONMENT_VARIABLES),
        "automatic_dotenv_loading": False,
        "runtime": runtime.to_dict(),
        "variables": variables,
        "notes": [
            "No environment variable is required for the read-only companion.",
            "Only the nine allowlisted RE_MCP_* variables are accepted by config generation and runtime.",
            "Use client env fields or set variables before starting a direct stdio process.",
            "The server never enumerates or returns unrelated process environment variables.",
        ],
    }
