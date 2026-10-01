from __future__ import annotations

import hashlib
import re
import struct
import tarfile
import time
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any, Iterable

from .advanced_pe import AdvancedPeError, analyze_pe_deep
from .analyzers import AnalysisError, StaticAnalyzer, calculate_entropy
from .comparison import compare_files
from .file_types import classify_file
from .inventory import build_binary_inventory


class AdvancedWorkflowError(RuntimeError):
    """Raised when a bounded local engineering workflow cannot be completed."""


ANTI_ANALYSIS_MARKERS = {
    b"isdebuggerpresent": "debugger API",
    b"checkremotedebuggerpresent": "remote debugger API",
    b"ntqueryinformationprocess": "native process query",
    b"outputdebugstring": "debug output API",
    b"vmware": "VMware marker",
    b"vbox": "VirtualBox marker",
    b"qemu": "QEMU marker",
    b"wine_get_version": "Wine marker",
    b"sandboxie": "Sandboxie marker",
    b"wireshark": "analysis-tool marker",
    b"procmon": "analysis-tool marker",
}

PERSISTENCE_MARKERS = {
    b"currentversion\\run": "Windows Run key",
    b"currentversion\\runonce": "Windows RunOnce key",
    b"schtasks": "scheduled task command",
    b"createservice": "service creation API",
    b"startservice": "service start API",
    b"launchagents": "macOS LaunchAgents path",
    b"launchdaemons": "macOS LaunchDaemons path",
    b"/etc/cron": "cron path",
    b"systemd/system": "systemd unit path",
}

PROTOCOL_MARKERS = {
    b"http://": "HTTP URI",
    b"https://": "HTTPS URI",
    b"ftp://": "FTP URI",
    b"ws://": "WebSocket URI",
    b"wss://": "secure WebSocket URI",
    b"user-agent:": "HTTP User-Agent header",
    b"content-type:": "HTTP Content-Type header",
    b"mqtt": "MQTT marker",
    b"amqp": "AMQP marker",
    b"grpc": "gRPC marker",
    b"dns": "DNS marker",
}

CONFIG_MARKERS = (
    b"config",
    b"server",
    b"host",
    b"port",
    b"token",
    b"campaign",
    b"mutex",
    b"user-agent",
    b"endpoint",
)

EMBEDDED_MAGIC = {
    b"MZ": "PE",
    b"\x7fELF": "ELF",
    b"PK\x03\x04": "ZIP",
    b"%PDF-": "PDF",
    b"\x89PNG\r\n\x1a\n": "PNG",
    b"\xff\xd8\xff": "JPEG",
    b"dex\n": "DEX",
    b"\xca\xfe\xba\xbe": "Java-class-or-MachO-fat",
    b"\xcf\xfa\xed\xfe": "Mach-O-64",
}


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_bounded(path: Path, max_scan_bytes: int) -> tuple[bytes, bool]:
    if max_scan_bytes < 1:
        raise AdvancedWorkflowError("max_scan_bytes must be positive")
    with path.open("rb") as stream:
        data = stream.read(max_scan_bytes + 1)
    return data[:max_scan_bytes], len(data) > max_scan_bytes


def _identity(path: Path) -> dict[str, Any]:
    return {
        "path": str(path),
        "size": path.stat().st_size,
        "sha256": _sha256_file(path),
    }


def _marker_map(data: bytes, markers: dict[bytes, str], limit: int = 1000) -> list[dict[str, Any]]:
    lowered = data.lower()
    results: list[dict[str, Any]] = []
    for marker, description in markers.items():
        start = 0
        needle = marker.lower()
        while len(results) < limit:
            offset = lowered.find(needle, start)
            if offset < 0:
                break
            results.append(
                {
                    "description": description,
                    "marker": marker.decode("latin-1", errors="replace"),
                    "offset": offset,
                    "offset_hex": f"0x{offset:X}",
                }
            )
            start = offset + max(1, len(needle))
    return sorted(results, key=lambda item: item["offset"])


def anti_analysis_fingerprint(path: Path, *, max_scan_bytes: int) -> dict[str, Any]:
    data, truncated = _read_bounded(path, max_scan_bytes)
    markers = _marker_map(data, ANTI_ANALYSIS_MARKERS)
    pe_indicators: dict[str, Any] | None = None
    if data.startswith(b"MZ"):
        try:
            deep = analyze_pe_deep(path)
            pe_indicators = {
                "anti_debug_imports": deep["markers"]["anti_debug_imports"],
                "obfuscation": deep["obfuscation"],
            }
        except AdvancedPeError:
            pe_indicators = None
    return {
        "markers": markers,
        "pe_indicators": pe_indicators,
        "assessment": "candidate-indicators-only",
        "scan_truncated": truncated,
    }


def persistence_indicator_map(path: Path, *, max_scan_bytes: int) -> dict[str, Any]:
    data, truncated = _read_bounded(path, max_scan_bytes)
    return {
        "indicators": _marker_map(data, PERSISTENCE_MARKERS),
        "assessment": "static-reference-not-runtime-proof",
        "scan_truncated": truncated,
    }


def protocol_artifact_map(path: Path, *, max_scan_bytes: int) -> dict[str, Any]:
    data, truncated = _read_bounded(path, max_scan_bytes)
    artifacts = _marker_map(data, PROTOCOL_MARKERS)
    ascii_uris = []
    uri_pattern = re.compile(rb"(?:https?|ftp|wss?)://[^\x00-\x20\x7f]{3,512}", re.I)
    for match in uri_pattern.finditer(data):
        ascii_uris.append(
            {
                "offset": match.start(),
                "offset_hex": f"0x{match.start():X}",
                "value": match.group(0).decode("latin-1", errors="replace"),
            }
        )
        if len(ascii_uris) >= 1000:
            break
    return {
        "protocol_markers": artifacts,
        "uri_candidates": ascii_uris,
        "scan_truncated": truncated,
    }


def config_blob_carver(path: Path, *, max_scan_bytes: int) -> dict[str, Any]:
    data, truncated = _read_bounded(path, max_scan_bytes)
    lowered = data.lower()
    candidates: list[dict[str, Any]] = []
    seen: set[tuple[int, int]] = set()
    for marker in CONFIG_MARKERS:
        start = 0
        while len(candidates) < 500:
            offset = lowered.find(marker, start)
            if offset < 0:
                break
            left = max(0, offset - 64)
            right = min(len(data), offset + len(marker) + 192)
            key = (left, right)
            if key not in seen:
                raw = data[left:right]
                printable = sum(32 <= value <= 126 or value in {9, 10, 13} for value in raw)
                if raw and printable / len(raw) >= 0.65:
                    candidates.append(
                        {
                            "offset": left,
                            "offset_hex": f"0x{left:X}",
                            "length": len(raw),
                            "trigger": marker.decode("ascii"),
                            "preview": raw.decode("latin-1", errors="replace"),
                            "entropy": round(calculate_entropy(raw), 4),
                        }
                    )
                    seen.add(key)
            start = offset + len(marker)
    return {
        "candidates": candidates,
        "candidate_count": len(candidates),
        "scan_truncated": truncated,
        "automatic_decryption_performed": False,
    }


def recursive_embedded_map(path: Path, *, max_scan_bytes: int) -> dict[str, Any]:
    data, truncated = _read_bounded(path, max_scan_bytes)
    records: list[dict[str, Any]] = []
    for magic, kind in EMBEDDED_MAGIC.items():
        start = 1  # offset zero is the outer artifact, not an embedded child
        while len(records) < 5000:
            offset = data.find(magic, start)
            if offset < 0:
                break
            records.append(
                {
                    "format": kind,
                    "offset": offset,
                    "offset_hex": f"0x{offset:X}",
                    "magic_hex": magic.hex(" ").upper(),
                }
            )
            start = offset + 1
    return {
        "embedded_candidates": sorted(records, key=lambda item: item["offset"]),
        "scan_truncated": truncated,
        "extraction_performed": False,
        "recursive_execution_performed": False,
    }


def _unsafe_member(name: str) -> bool:
    normalized = name.replace("\\", "/")
    pure = PurePosixPath(normalized)
    return pure.is_absolute() or ".." in pure.parts or bool(re.match(r"^[A-Za-z]:", normalized))


def _zip_directory_limits(
    path: Path, *, max_members: int, max_index_bytes: int
) -> tuple[int, int]:
    """Read only the fixed ZIP end records before ZipFile materializes ZipInfo objects."""
    size = path.stat().st_size
    tail_size = min(size, 22 + 65_535 + 20)
    with path.open("rb") as stream:
        stream.seek(size - tail_size)
        tail = stream.read(tail_size)
        signature = b"PK\x05\x06"
        end = tail.rfind(signature)
        while end >= 0:
            if end + 22 <= len(tail):
                comment_size = struct.unpack_from("<H", tail, end + 20)[0]
                if end + 22 + comment_size == len(tail):
                    break
            end = tail.rfind(signature, 0, end)
        if end < 0:
            raise AdvancedWorkflowError("ZIP end-of-central-directory record is invalid")
        disk, directory_disk, disk_entries, entries, index_size, index_offset = struct.unpack_from(
            "<4H2I", tail, end + 4
        )
        if disk or directory_disk or disk_entries != entries:
            raise AdvancedWorkflowError("multi-disk ZIP archives are not supported")
        if (
            entries == 0xFFFF
            or index_size == 0xFFFFFFFF
            or index_offset == 0xFFFFFFFF
        ):
            locator = end - 20
            if locator < 0 or tail[locator : locator + 4] != b"PK\x06\x07":
                raise AdvancedWorkflowError("ZIP64 locator is missing")
            zip64_offset = struct.unpack_from("<Q", tail, locator + 8)[0]
            if zip64_offset > size - 56:
                raise AdvancedWorkflowError("ZIP64 end record lies outside the archive")
            stream.seek(zip64_offset)
            record = stream.read(56)
            if len(record) != 56 or record[:4] != b"PK\x06\x06":
                raise AdvancedWorkflowError("ZIP64 end record is invalid")
            disk, directory_disk = struct.unpack_from("<2I", record, 16)
            disk_entries, entries, index_size = struct.unpack_from("<3Q", record, 24)
            if disk or directory_disk or disk_entries != entries:
                raise AdvancedWorkflowError("multi-disk ZIP64 archives are not supported")
    if entries > max_members:
        raise AdvancedWorkflowError(f"archive exceeds member limit {max_members}")
    if index_size > max_index_bytes:
        raise AdvancedWorkflowError(
            f"archive central directory exceeds scan limit {max_index_bytes} bytes"
        )
    return entries, index_size


def archive_safety_audit(
    path: Path,
    *,
    max_members: int = 100_000,
    max_expanded_bytes: int = 4 * 1024 * 1024 * 1024,
    max_member_ratio: float = 1000.0,
    timeout_seconds: float = 30.0,
    max_archive_bytes: int = 512 * 1024 * 1024,
    max_index_bytes: int = 64 * 1024 * 1024,
) -> dict[str, Any]:
    if (max_members < 1 or max_expanded_bytes < 1 or max_member_ratio < 1
            or timeout_seconds <= 0 or max_archive_bytes < 1 or max_index_bytes < 1):
        raise AdvancedWorkflowError("archive safety limits must be positive")
    started = time.monotonic()
    source_size = path.stat().st_size
    if source_size > max_archive_bytes:
        raise AdvancedWorkflowError(
            f"archive source exceeds file limit {max_archive_bytes} bytes"
        )

    def enforce_budget(member_count: int, expanded: int, stored: int) -> None:
        if member_count > max_members:
            raise AdvancedWorkflowError(f"archive exceeds member limit {max_members}")
        if expanded > max_expanded_bytes:
            raise AdvancedWorkflowError(f"archive exceeds expanded-byte limit {max_expanded_bytes}")
        if expanded / max(stored, 1) > max_member_ratio:
            raise AdvancedWorkflowError(f"archive exceeds expansion-ratio limit {max_member_ratio:g}")
        if time.monotonic() - started > timeout_seconds:
            raise AdvancedWorkflowError(f"archive audit exceeded time limit {timeout_seconds:g}s")

    members: list[dict[str, Any]] = []
    totals = {"member_count": 0, "stored_bytes": 0, "expanded_bytes": 0}
    kind = "unsupported"
    try:
        if zipfile.is_zipfile(path):
            kind = "zip"
            declared_members, index_size = _zip_directory_limits(
                path, max_members=max_members, max_index_bytes=max_index_bytes
            )
            with zipfile.ZipFile(path) as archive:
                infos = archive.infolist()
                if len(infos) != declared_members:
                    raise AdvancedWorkflowError("ZIP central-directory member count mismatch")
                if index_size > max_index_bytes:
                    raise AdvancedWorkflowError("ZIP central directory exceeds scan limit")
                enforce_budget(len(infos), 0, 1)
                for zip_info in infos:
                    totals["member_count"] += 1
                    totals["stored_bytes"] += zip_info.compress_size
                    totals["expanded_bytes"] += zip_info.file_size
                    member_ratio = zip_info.file_size / max(zip_info.compress_size, 1)
                    if member_ratio > max_member_ratio:
                        raise AdvancedWorkflowError(
                            f"archive member exceeds expansion-ratio limit {max_member_ratio:g}"
                        )
                    enforce_budget(
                        totals["member_count"], totals["expanded_bytes"],
                        max(totals["stored_bytes"], 1),
                    )
                    if len(members) < 2000:
                        members.append(
                            {
                                "name": zip_info.filename,
                                "stored_bytes": zip_info.compress_size,
                                "expanded_bytes": zip_info.file_size,
                                "ratio": round(
                                    zip_info.file_size / max(zip_info.compress_size, 1), 2
                                ),
                                "path_traversal_candidate": _unsafe_member(
                                    zip_info.filename
                                ),
                                "encrypted": bool(zip_info.flag_bits & 0x1),
                            }
                        )
        elif tarfile.is_tarfile(path):
            kind = "tar"
            with tarfile.open(path, mode="r:*") as tar_archive:
                for tar_info in tar_archive:
                    totals["member_count"] += 1
                    if totals["member_count"] > max_members:
                        raise AdvancedWorkflowError(f"archive exceeds member limit {max_members}")
                    totals["expanded_bytes"] += max(0, tar_info.size)
                    enforce_budget(totals["member_count"], totals["expanded_bytes"], max(path.stat().st_size, 1))
                    if len(members) < 2000:
                        members.append(
                            {
                                "name": tar_info.name,
                                "expanded_bytes": tar_info.size,
                                "path_traversal_candidate": _unsafe_member(
                                    tar_info.name
                                ),
                                "link": tar_info.issym() or tar_info.islnk(),
                                "link_target": (
                                    tar_info.linkname
                                    if tar_info.issym() or tar_info.islnk()
                                    else None
                                ),
                            }
                        )
        else:
            raise AdvancedWorkflowError("sample is not a supported ZIP/TAR archive")
    except (OSError, struct.error, tarfile.TarError, zipfile.BadZipFile) as error:
        raise AdvancedWorkflowError(f"archive inspection failed: {error}") from error
    stored = totals["stored_bytes"] or path.stat().st_size
    total_ratio = totals["expanded_bytes"] / max(stored, 1)
    return {
        "archive_kind": kind,
        "totals": {**totals, "overall_expansion_ratio": round(total_ratio, 2)},
        "members": members,
        "members_truncated": totals["member_count"] > len(members),
        "audit_limits": {
            "max_archive_bytes": max_archive_bytes,
            "max_index_bytes": max_index_bytes,
            "max_members": max_members,
            "max_expanded_bytes": max_expanded_bytes,
            "max_member_ratio": max_member_ratio,
            "timeout_seconds": timeout_seconds,
            "elapsed_seconds": round(time.monotonic() - started, 3),
        },
        "risk_candidates": {
            "path_traversal": sum(item["path_traversal_candidate"] for item in members),
            "high_expansion_ratio": total_ratio >= 100,
            "very_large_expansion": totals["expanded_bytes"] >= 4 * 1024 * 1024 * 1024,
        },
        "extraction_performed": False,
    }


def _pe_signature_structure(data: bytes) -> dict[str, Any]:
    result = {
        "format": "not-pe",
        "certificate_table_present": False,
        "certificate_file_offset": None,
        "certificate_size": 0,
        "within_file": False,
    }
    if len(data) < 0x40 or not data.startswith(b"MZ"):
        return result
    try:
        pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
        optional = pe_offset + 24
        magic = struct.unpack_from("<H", data, optional)[0]
        directory = optional + (96 if magic == 0x10B else 112 if magic == 0x20B else 0)
        if not directory:
            return {**result, "format": "PE-unknown-optional-header"}
        certificate_offset, certificate_size = struct.unpack_from("<II", data, directory + 4 * 8)
        return {
            "format": "PE",
            "certificate_table_present": bool(certificate_offset and certificate_size),
            "certificate_file_offset": certificate_offset or None,
            "certificate_size": certificate_size,
            "within_file": bool(
                certificate_offset
                and certificate_size
                and certificate_offset + certificate_size <= len(data)
            ),
        }
    except struct.error:
        return {**result, "format": "malformed-PE"}


def signature_trust_assessment(path: Path, *, max_scan_bytes: int) -> dict[str, Any]:
    data, truncated = _read_bounded(path, max_scan_bytes)
    structure = _pe_signature_structure(data)
    return {
        "structure": structure,
        "scan_truncated": truncated,
        "cryptographic_verification_performed": False,
        "trust_verdict": "unknown",
        "next_provider": "osslsigncode on PE or codesign on Apple artifacts",
    }


def debug_source_map(path: Path, *, max_scan_bytes: int) -> dict[str, Any]:
    data, truncated = _read_bounded(path, max_scan_bytes)
    patterns = {
        "pdb": re.compile(rb"[A-Za-z]:\\[^\x00\r\n]{1,1024}\.pdb", re.I),
        "source": re.compile(rb"(?:[A-Za-z]:\\|/)[^\x00\r\n]{1,1024}\.(?:c|cc|cpp|cxx|h|hpp|rs|go|swift)", re.I),
    }
    records: list[dict[str, Any]] = []
    for kind, pattern in patterns.items():
        for match in pattern.finditer(data):
            records.append(
                {
                    "kind": kind,
                    "offset": match.start(),
                    "offset_hex": f"0x{match.start():X}",
                    "value": match.group(0).decode("latin-1", errors="replace"),
                }
            )
            if len(records) >= 2000:
                break
    return {"paths": records, "scan_truncated": truncated}


def analysis_coverage_metrics(
    path: Path,
    *,
    host_coverage: dict[str, Any] | None = None,
    max_file_bytes: int = 512 * 1024 * 1024,
    max_scan_bytes: int = 64 * 1024 * 1024,
) -> dict[str, Any]:
    result = StaticAnalyzer(max_file_size=max_file_bytes, max_scan_bytes=max_scan_bytes, max_strings=5000).analyze(path)
    executable_sections = [section for section in result.sections if "X" in section.permissions]
    covered_executable_bytes = sum(section.raw_size for section in executable_sections)
    return {
        "format": result.summary.get("format"),
        "architecture": result.summary.get("architecture"),
        "sections_parsed": len(result.sections),
        "executable_sections": len(executable_sections),
        "executable_raw_bytes_mapped": covered_executable_bytes,
        "imports_parsed": sum(len(library.symbols) for library in result.imports),
        "strings_extracted": len(result.strings),
        "findings_emitted": len(result.findings),
        "limitations": result.limitations,
        "host_coverage": host_coverage,
        "claim": "local-parser-coverage; host capability coverage is reported only when live discovery is supplied",
    }


def evidence_bundle(path: Path, *, max_file_bytes: int = 512 * 1024 * 1024, max_scan_bytes: int = 64 * 1024 * 1024) -> dict[str, Any]:
    result = StaticAnalyzer(max_file_size=max_file_bytes, max_scan_bytes=max_scan_bytes, max_strings=1000).analyze(path)
    return {
        "bundle_schema": "0.5.0",
        "subject": result.to_dict(),
        "manifest": {
            "artifact_count": 1,
            "source_sha256": result.source.sha256,
            "mutation_performed": False,
            "automatic_upload": False,
        },
        "note": "Returned in-band; use the CLI report command for an explicit output directory.",
    }


LOCAL_FEATURES = {
    "file-taxonomy",
    "pe-oep-map",
    "boundary-overlay-map",
    "marker-extractor",
    "injection-detector",
    "obfuscation-score",
    "encrypted-region-map",
    "language-provenance",
    "dongle-license-map",
    "anti-analysis-fingerprint",
    "persistence-indicator-map",
    "protocol-artifact-map",
    "config-blob-carver",
    "recursive-embedded-carver",
    "resource-diff-visualizer",
    "archive-safety-audit",
    "signature-trust-assessment",
    "debug-source-map",
    "dependency-risk-map",
    "patch-regression-verifier",
    "analysis-coverage-metrics",
    "evidence-bundle-export",
}


def execute_local_feature(
    feature_id: str,
    sample: str | Path,
    *,
    second_sample: str | Path | None = None,
    max_scan_bytes: int = 64 * 1024 * 1024,
    max_archive_members: int = 100_000,
    max_archive_expanded_bytes: int = 4 * 1024 * 1024 * 1024,
    max_archive_member_ratio: int = 1000,
    archive_timeout_seconds: int = 30,
    host_coverage: dict[str, Any] | None = None,
    max_file_bytes: int = 512 * 1024 * 1024,
) -> dict[str, Any]:
    """Execute only allowlisted, non-mutating local feature implementations."""
    if feature_id not in LOCAL_FEATURES:
        raise AdvancedWorkflowError(
            f"feature has no safe local executor: {feature_id}; use a host plan or provider"
        )
    path = Path(sample).expanduser().resolve()
    if not path.is_file():
        raise AdvancedWorkflowError(f"sample is not a regular file: {path}")
    try:
        if feature_id == "file-taxonomy":
            payload = classify_file(path, max_file_size=max_file_bytes).to_dict()
        elif feature_id in {
            "pe-oep-map",
            "boundary-overlay-map",
            "marker-extractor",
            "injection-detector",
            "obfuscation-score",
            "encrypted-region-map",
            "language-provenance",
            "dongle-license-map",
        }:
            if path.stat().st_size > max_file_bytes:
                raise AdvancedWorkflowError(f"sample exceeds configured file limit {max_file_bytes}")
            deep = analyze_pe_deep(path, max_file_size=max_file_bytes, max_scan_bytes=max_scan_bytes)
            keys = {
                "pe-oep-map": ("declared_entry_point",),
                "boundary-overlay-map": ("boundaries", "sections"),
                "marker-extractor": ("markers",),
                "injection-detector": ("injection_indicators",),
                "obfuscation-score": ("obfuscation",),
                "encrypted-region-map": ("encryption_or_compression_candidates", "whole_file_entropy"),
                "language-provenance": ("language_candidates",),
                "dongle-license-map": ("markers",),
            }[feature_id]
            payload = {key: deep[key] for key in keys}
            if feature_id == "dongle-license-map":
                payload = {"dongle_license": deep["markers"]["dongle_license"]}
        elif feature_id == "anti-analysis-fingerprint":
            payload = anti_analysis_fingerprint(path, max_scan_bytes=max_scan_bytes)
        elif feature_id == "persistence-indicator-map":
            payload = persistence_indicator_map(path, max_scan_bytes=max_scan_bytes)
        elif feature_id == "protocol-artifact-map":
            payload = protocol_artifact_map(path, max_scan_bytes=max_scan_bytes)
        elif feature_id == "config-blob-carver":
            payload = config_blob_carver(path, max_scan_bytes=max_scan_bytes)
        elif feature_id == "recursive-embedded-carver":
            payload = recursive_embedded_map(path, max_scan_bytes=max_scan_bytes)
        elif feature_id == "archive-safety-audit":
            payload = archive_safety_audit(
                path,
                max_members=max_archive_members,
                max_expanded_bytes=max_archive_expanded_bytes,
                max_member_ratio=max_archive_member_ratio,
                timeout_seconds=archive_timeout_seconds,
                max_archive_bytes=max_file_bytes,
                max_index_bytes=max_scan_bytes,
            )
        elif feature_id == "signature-trust-assessment":
            payload = signature_trust_assessment(path, max_scan_bytes=max_scan_bytes)
        elif feature_id == "debug-source-map":
            payload = debug_source_map(path, max_scan_bytes=max_scan_bytes)
        elif feature_id == "dependency-risk-map":
            payload = build_binary_inventory(
                path,
                max_file_bytes=max_file_bytes,
                max_scan_bytes=max_scan_bytes,
            )
        elif feature_id == "analysis-coverage-metrics":
            payload = analysis_coverage_metrics(path, host_coverage=host_coverage, max_file_bytes=max_file_bytes, max_scan_bytes=max_scan_bytes)
        elif feature_id == "evidence-bundle-export":
            payload = evidence_bundle(path, max_file_bytes=max_file_bytes, max_scan_bytes=max_scan_bytes)
        else:
            if second_sample is None:
                raise AdvancedWorkflowError(f"{feature_id} requires second_sample")
            other = Path(second_sample).expanduser().resolve()
            if not other.is_file():
                raise AdvancedWorkflowError(f"second_sample is not a regular file: {other}")
            payload = compare_files(path, other, analyzer=StaticAnalyzer(max_file_size=max_file_bytes, max_scan_bytes=max_scan_bytes))
            if feature_id == "patch-regression-verifier":
                payload = {
                    "comparison": payload,
                    "checks": {
                        "identity_changed": not payload["identical"],
                        "format_or_architecture_changed": any(
                            key in payload["summary_changes"] for key in ("format", "architecture")
                        ),
                        "imports_changed": bool(
                            payload["imports"]["libraries_added"]
                            or payload["imports"]["libraries_removed"]
                            or payload["imports"]["symbol_changes"]
                        ),
                    },
                    "claim": "static-regression-check-not-runtime-test",
                }
    except (AdvancedPeError, AnalysisError, OSError, ValueError) as error:
        raise AdvancedWorkflowError(str(error)) from error
    return {
        "schema_version": "0.5.0",
        "feature_id": feature_id,
        "source": _identity(path),
        "result": payload,
        "executed": True,
        "mutation_performed": False,
        "sample_execution_performed": False,
    }


def local_feature_ids() -> Iterable[str]:
    return sorted(LOCAL_FEATURES)
