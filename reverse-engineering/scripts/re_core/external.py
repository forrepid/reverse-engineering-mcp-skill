from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


class ProviderError(RuntimeError):
    """Raised when an optional provider cannot run under the safe policy."""


@dataclass(frozen=True)
class ProviderSpec:
    id: str
    display_name: str
    kind: str
    aliases: tuple[str, ...] = ()
    executables: tuple[str, ...] = ()
    modules: tuple[str, ...] = ()
    version_args: tuple[str, ...] = ("--version",)
    scan_args: tuple[str, ...] = ()
    requires_rule_path: bool = False
    note: str = ""


def _spec(
    provider_id: str,
    display_name: str,
    kind: str,
    **kwargs: Any,
) -> ProviderSpec:
    return ProviderSpec(provider_id, display_name, kind, **kwargs)


# Provider ids are canonical, lower-case machine identifiers. Host plugins and
# tools that require output directories or interactive projects are detected
# but deliberately not launched by the read-only companion.
PROVIDERS: dict[str, ProviderSpec] = {
    "die": _spec(
        "die",
        "Detect It Easy",
        "executable",
        aliases=("detect it easy", "detect-it-easy"),
        executables=("diec", "diec.exe"),
        scan_args=("-j", "{sample}"),
    ),
    "yara-x": _spec(
        "yara-x",
        "YARA-X",
        "executable",
        aliases=("yarax",),
        executables=("yr", "yr.exe"),
        scan_args=("scan", "--output-format=ndjson", "{rule_path}", "{sample}"),
        requires_rule_path=True,
        note="A reviewed local rule file is required.",
    ),
    "capa": _spec(
        "capa",
        "capa",
        "executable",
        executables=("capa", "capa.exe"),
        scan_args=("-j", "{sample}"),
    ),
    "floss": _spec(
        "floss",
        "FLOSS",
        "executable",
        executables=("floss", "floss.exe"),
        scan_args=("--json", "{sample}"),
    ),
    "exiftool": _spec(
        "exiftool",
        "ExifTool",
        "executable",
        executables=("exiftool", "exiftool.exe"),
        scan_args=("-json", "-G", "-n", "{sample}"),
    ),
    "osslsigncode": _spec(
        "osslsigncode",
        "osslsigncode",
        "executable",
        executables=("osslsigncode", "osslsigncode.exe"),
        scan_args=("verify", "-in", "{sample}"),
    ),
    "codesign": _spec(
        "codesign",
        "Apple codesign",
        "executable",
        executables=("codesign",),
        scan_args=("-d", "--verbose=4", "{sample}"),
        note="Available on macOS only; diagnostic output is commonly written to stderr.",
    ),
    "syft": _spec(
        "syft",
        "Syft",
        "executable",
        executables=("syft", "syft.exe"),
        scan_args=("{sample}", "-o", "syft-json"),
        note="Package fingerprinting is not proof of a complete SBOM.",
    ),
    "lief": _spec(
        "lief", "LIEF", "python", modules=("lief",), note="In-process format parser."
    ),
    "pefile": _spec(
        "pefile", "pefile", "python", modules=("pefile",), note="PE parser."
    ),
    "capstone": _spec(
        "capstone",
        "Capstone",
        "python",
        aliases=("capstone-python",),
        modules=("capstone",),
        note="In-process linear disassembly provider.",
    ),
    "angr": _spec(
        "angr",
        "angr",
        "python-detect-only",
        modules=("angr",),
        note="Resource-intensive analysis requires a separately bounded workflow.",
    ),
    "binwalk": _spec(
        "binwalk",
        "binwalk",
        "detect-only",
        executables=("binwalk", "binwalk.exe"),
        note="Extraction and recursive plugins are not launched by companion MCP.",
    ),
    "unblob": _spec(
        "unblob",
        "unblob",
        "detect-only",
        executables=("unblob", "unblob.exe"),
        note="Extraction writes artifacts and requires an explicit output workflow.",
    ),
    "jadx": _spec(
        "jadx",
        "JADX",
        "detect-only",
        executables=("jadx", "jadx.exe", "jadx.bat"),
        note="Decompiler output requires a reviewed output directory.",
    ),
    "apktool": _spec(
        "apktool",
        "Apktool",
        "detect-only",
        executables=("apktool", "apktool.bat", "apktool.exe"),
        note="Decode/rebuild writes artifacts and is not a companion scan.",
    ),
    "vineflower": _spec(
        "vineflower",
        "Vineflower",
        "manual",
        note="Configure a reviewed JAR and output directory in a separate Java workflow.",
    ),
    "cfr": _spec(
        "cfr",
        "CFR",
        "manual",
        note="Configure a reviewed JAR and output directory in a separate Java workflow.",
    ),
    "bindiff": _spec(
        "bindiff",
        "BinDiff",
        "host",
        note="Requires compatible IDA/Ghidra exports and a separately installed provider.",
    ),
    "diaphora": _spec(
        "diaphora",
        "Diaphora",
        "host",
        note="Requires reviewed IDA scripts and normalized database exports.",
    ),
    "ghidra": _spec("ghidra", "Ghidra", "host"),
    "ida": _spec("ida", "IDA Pro", "host"),
    "ghidra-pcode": _spec("ghidra-pcode", "Ghidra P-code", "host"),
    "ghidra-classtypeinfo": _spec(
        "ghidra-classtypeinfo", "Ghidra ClassTypeInfo", "host"
    ),
    "retdec-signatures": _spec(
        "retdec-signatures",
        "RetDec signatures",
        "manual",
        note="Signature data requires a compatible reviewed consumer.",
    ),
}


_PROVIDER_ALIASES = {
    alias.casefold(): provider_id
    for provider_id, spec in PROVIDERS.items()
    for alias in (provider_id, spec.display_name, *spec.aliases)
}


def normalize_provider_id(value: str) -> str:
    provider_id = _PROVIDER_ALIASES.get(value.strip().casefold())
    if provider_id is None:
        raise ProviderError(
            "unknown provider; expected one of: " + ", ".join(sorted(PROVIDERS))
        )
    return provider_id


def load_provider_config(path: str | Path | None) -> dict[str, dict[str, Any]]:
    if path is None or str(path).strip() == "":
        return {}
    config_path = Path(path).expanduser().resolve()
    if not config_path.is_file():
        raise ProviderError(f"provider config does not exist: {config_path}")
    if config_path.stat().st_size > 64 * 1024:
        raise ProviderError("provider config exceeds 64 KiB")
    try:
        payload = json.loads(config_path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError) as error:
        raise ProviderError(f"invalid provider config JSON: {error}") from error
    if not isinstance(payload, dict) or payload.get("schema_version") != "0.5.0":
        raise ProviderError("provider config schema_version must be 0.5.0")
    records = payload.get("providers", {})
    if not isinstance(records, dict):
        raise ProviderError("provider config providers must be an object")
    normalized: dict[str, dict[str, Any]] = {}
    for raw_id, raw_record in records.items():
        provider_id = normalize_provider_id(str(raw_id))
        if not isinstance(raw_record, dict):
            raise ProviderError(f"provider record must be an object: {provider_id}")
        unknown = sorted(set(raw_record) - {"enabled", "executable", "rule_paths"})
        if unknown:
            raise ProviderError(
                f"unknown provider config key(s) for {provider_id}: "
                + ", ".join(unknown)
            )
        record: dict[str, Any] = {"enabled": bool(raw_record.get("enabled", True))}
        executable_value = str(raw_record.get("executable", "")).strip()
        if executable_value:
            executable = Path(executable_value).expanduser().resolve()
            if not executable.is_file():
                raise ProviderError(
                    f"configured provider executable is not a file: {executable}"
                )
            allowed = {name.casefold() for name in PROVIDERS[provider_id].executables}
            if executable.name.casefold() not in allowed:
                raise ProviderError(
                    f"configured executable basename is not allowlisted for {provider_id}"
                )
            record["executable"] = str(executable)
        rule_paths = raw_record.get("rule_paths", [])
        if not isinstance(rule_paths, list) or not all(
            isinstance(value, str) for value in rule_paths
        ):
            raise ProviderError(f"rule_paths must be a string array: {provider_id}")
        resolved_rules: list[str] = []
        for value in rule_paths:
            rule = Path(value).expanduser().resolve()
            if not rule.is_file():
                raise ProviderError(f"configured rule path is not a file: {rule}")
            resolved_rules.append(str(rule))
        if resolved_rules:
            record["rule_paths"] = resolved_rules
        normalized[provider_id] = record
    return normalized


def _resolve_executable(
    spec: ProviderSpec, config: dict[str, dict[str, Any]]
) -> str | None:
    record = config.get(spec.id, {})
    if record.get("enabled") is False:
        return None
    configured = record.get("executable")
    if configured:
        return str(configured)
    for name in spec.executables:
        resolved = shutil.which(name)
        if resolved:
            return resolved
    return None


def _resolve_module(spec: ProviderSpec) -> str | None:
    for module in spec.modules:
        if importlib.util.find_spec(module) is not None:
            return module
    return None


def provider_status(
    config_path: str | Path | None = None,
) -> list[dict[str, Any]]:
    config = load_provider_config(config_path)
    status: list[dict[str, Any]] = []
    for provider_id, spec in PROVIDERS.items():
        record = config.get(provider_id, {})
        enabled = record.get("enabled", True)
        executable = (
            _resolve_executable(spec, config)
            if spec.executables and enabled
            else None
        )
        module = _resolve_module(spec) if spec.modules and enabled else None
        # Host integrations cannot be inferred from a provider label.  They only
        # become available after MCP discovery in the active IDA/Ghidra session.
        available = executable is not None or module is not None
        runnable = (
            spec.kind == "executable"
            and executable is not None
            and bool(spec.scan_args)
        ) or (spec.kind == "python" and module is not None and provider_id == "lief")
        status.append(
            {
                "id": provider_id,
                "display_name": spec.display_name,
                "kind": spec.kind,
                "available": available,
                "runnable": runnable,
                "enabled": enabled,
                "executable": executable,
                "module": module,
                "configured_rule_paths": list(record.get("rule_paths", [])),
                "requires_rule_path": spec.requires_rule_path,
                "requires_host_discovery": spec.kind == "host",
                "note": spec.note or None,
            }
        )
    return status


def _run(
    arguments: list[str],
    *,
    timeout_seconds: int,
    max_output_bytes: int,
) -> dict[str, Any]:
    creationflags = 0
    if os.name == "nt":
        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    process = subprocess.Popen(
        arguments,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=False,
        creationflags=creationflags,
    )

    def drain(stream: Any) -> tuple[bytes, str, int]:
        kept = bytearray()
        digest = hashlib.sha256()
        total = 0
        for chunk in iter(lambda: stream.read(64 * 1024), b""):
            total += len(chunk)
            digest.update(chunk)
            if len(kept) < max_output_bytes:
                kept.extend(chunk[: max_output_bytes - len(kept)])
        return bytes(kept), digest.hexdigest(), total

    assert process.stdout is not None
    assert process.stderr is not None
    with ThreadPoolExecutor(max_workers=2, thread_name_prefix="provider-capture") as pool:
        stdout_future = pool.submit(drain, process.stdout)
        stderr_future = pool.submit(drain, process.stderr)
        try:
            returncode = process.wait(timeout=timeout_seconds)
        except subprocess.TimeoutExpired as error:
            process.kill()
            process.wait()
            stdout_future.result()
            stderr_future.result()
            raise ProviderError(
                f"provider timed out after {timeout_seconds}s"
            ) from error
        stdout, stdout_sha256, stdout_size = stdout_future.result()
        stderr, stderr_sha256, stderr_size = stderr_future.result()
    return {
        "returncode": returncode,
        "stdout": stdout.decode("utf-8", errors="replace"),
        "stderr": stderr.decode("utf-8", errors="replace"),
        "stdout_sha256": stdout_sha256,
        "stderr_sha256": stderr_sha256,
        "stdout_bytes": stdout_size,
        "stderr_bytes": stderr_size,
        "stdout_truncated": stdout_size > max_output_bytes,
        "stderr_truncated": stderr_size > max_output_bytes,
    }


def _parse_provider_output(provider_id: str, output: str) -> Any:
    try:
        return json.loads(output)
    except json.JSONDecodeError:
        if provider_id == "yara-x":
            records: list[Any] = []
            for line in output.splitlines():
                if not line.strip():
                    continue
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    return None
            return records
    return None


def _run_lief(sample: Path) -> dict[str, Any]:
    try:
        # Load dynamically: LIEF's large cyclic stub graph is not part of this
        # module's type contract and can exhaust static-analysis workers.
        lief: Any = importlib.import_module("lief")
    except ImportError as error:
        raise ProviderError("LIEF Python module is not installed") from error
    # File-object parsing avoids native Windows path-encoding failures for
    # authorized samples stored under non-ASCII directories.
    with sample.open("rb") as stream:
        binary = lief.parse(stream)
    if binary is None:
        raise ProviderError("LIEF could not parse the sample")
    sections = [
        {
            "name": str(section.name),
            "size": int(section.size),
            "virtual_address": int(section.virtual_address),
        }
        for section in list(binary.sections)[:4096]
    ]
    libraries = [str(value) for value in list(getattr(binary, "libraries", []))[:4096]]
    return {
        "format": binary.format.name if hasattr(binary, "format") else type(binary).__name__,
        "entrypoint": int(getattr(binary, "entrypoint", 0)),
        "imagebase": int(getattr(binary, "imagebase", 0)),
        "sections": sections,
        "libraries": libraries,
        "limitations": [
            "Provider output is a bounded structural summary, not a trust verdict."
        ],
    }


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run_provider(
    provider: str,
    sample: str | Path,
    *,
    rule_path: str | Path | None = None,
    config_path: str | Path | None = None,
    timeout_seconds: int = 120,
    max_output_bytes: int = 4 * 1024 * 1024,
) -> dict[str, Any]:
    provider_id = normalize_provider_id(provider)
    spec = PROVIDERS[provider_id]
    config = load_provider_config(config_path)
    if config.get(provider_id, {}).get("enabled") is False:
        raise ProviderError(f"provider is disabled by configuration: {provider_id}")
    sample_path = Path(sample).expanduser().resolve()
    if not sample_path.is_file():
        raise ProviderError(f"sample is not a regular file: {sample_path}")
    if not 1 <= timeout_seconds <= 900:
        raise ProviderError("timeout_seconds must be between 1 and 900")
    if not 1024 <= max_output_bytes <= 64 * 1024 * 1024:
        raise ProviderError("max_output_bytes must be between 1024 and 67108864")

    if spec.kind == "python" and provider_id == "lief":
        parsed = _run_lief(sample_path)
        return {
            "provider": asdict(spec),
            "sample": str(sample_path),
            "sample_sha256": _sha256_file(sample_path),
            "parsed_json": parsed,
            "security": {
                "in_process": True,
                "automatic_upload": False,
                "sample_execution": False,
            },
        }

    if spec.kind != "executable" or not spec.scan_args:
        raise ProviderError(
            f"provider is detection/host/manual only and has no companion scan: {provider_id}"
        )
    executable = _resolve_executable(spec, config)
    if not executable:
        raise ProviderError(f"provider executable is not installed: {provider_id}")

    effective_rule: Path | None = None
    if spec.requires_rule_path:
        raw_rule = str(rule_path).strip() if rule_path is not None else ""
        if not raw_rule:
            configured = config.get(provider_id, {}).get("rule_paths", [])
            raw_rule = str(configured[0]) if configured else ""
        if not raw_rule:
            raise ProviderError(f"provider requires a reviewed rule_path: {provider_id}")
        effective_rule = Path(raw_rule).expanduser().resolve()
        if not effective_rule.is_file():
            raise ProviderError(f"rule_path is not a regular file: {effective_rule}")

    version = _run(
        [executable, *spec.version_args],
        timeout_seconds=min(timeout_seconds, 15),
        max_output_bytes=min(max_output_bytes, 64 * 1024),
    )
    replacements = {
        "sample": str(sample_path),
        "rule_path": str(effective_rule) if effective_rule is not None else "",
    }
    arguments = [
        executable,
        *(token.format(**replacements) for token in spec.scan_args),
    ]
    scan = _run(
        arguments,
        timeout_seconds=timeout_seconds,
        max_output_bytes=max_output_bytes,
    )
    parsed = _parse_provider_output(provider_id, scan["stdout"])
    return {
        "provider": asdict(spec),
        "executable": executable,
        "version_output": version["stdout"].strip() or version["stderr"].strip(),
        "arguments": [Path(arguments[0]).name, *arguments[1:]],
        "sample": str(sample_path),
        "sample_sha256": _sha256_file(sample_path),
        "rule_path": str(effective_rule) if effective_rule is not None else None,
        "result": scan,
        "parsed_json": parsed,
        "security": {
            "shell": False,
            "automatic_upload": False,
            "sample_execution": False,
            "timeout_seconds": timeout_seconds,
            "max_output_bytes": max_output_bytes,
        },
    }
