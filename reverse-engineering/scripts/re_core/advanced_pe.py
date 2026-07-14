from __future__ import annotations

import hashlib
import re
import struct
from dataclasses import asdict
from pathlib import Path
from typing import Any

from .analyzers import AnalysisError, calculate_entropy, format_bytes, parse_pe
from .file_types import DONGLE_MARKERS


class AdvancedPeError(RuntimeError):
    """Raised when a PE deep-triage record cannot be built safely."""


INJECTION_TECHNIQUES: dict[str, set[str]] = {
    "remote-thread": {
        "openprocess",
        "virtualallocex",
        "writeprocessmemory",
        "createremotethread",
        "ntcreatethreadex",
        "rtlcreateuserthread",
    },
    "apc": {"queueuserapc", "ntqueueapcthread", "setthreadcontext"},
    "process-hollowing": {
        "createprocessa",
        "createprocessw",
        "zwunmapviewofsection",
        "ntunmapviewofsection",
        "setthreadcontext",
        "resumethread",
    },
    "section-mapping": {
        "ntcreatesection",
        "ntmapviewofsection",
        "zwmapviewofsection",
    },
    "dll-loading": {"loadlibrarya", "loadlibraryw", "ldrloaddll"},
    "hooking": {"setwindowshookexa", "setwindowshookexw"},
    "memory-permission-transition": {"virtualprotect", "virtualprotectex", "ntprotectvirtualmemory"},
}

ANTI_DEBUG_APIS = {
    "isdebuggerpresent",
    "checkremotedebuggerpresent",
    "ntqueryinformationprocess",
    "debugactiveprocess",
    "outputdebugstringa",
    "outputdebugstringw",
}

PACKER_MARKERS = {
    b"upx!": "UPX marker",
    b"themida": "Themida marker",
    b"winlicense": "WinLicense marker",
    b"vmprotect": "VMProtect marker",
    b"aspack": "ASPack marker",
    b"mpress": "MPRESS marker",
    b"petite": "Petite marker",
}

LANGUAGE_MARKERS: dict[str, tuple[bytes, ...]] = {
    "dotnet": (b"BSJB", b"mscoree.dll", b"_CorExeMain"),
    "go": (b"Go build ID:", b"runtime.main", b"gopclntab"),
    "rust": (b"rust_eh_personality", b"std::panicking", b"rust_begin_unwind"),
    "delphi": (b"Software\\Borland\\Delphi", b"@ClassCreate", b"TObject"),
    "visual-basic-6": (b"MSVBVM60.DLL", b"__vba"),
    "python-pyinstaller": (b"PyInstaller", b"pyi-windows-manifest-filename", b"PYZ-00.pyz"),
    "autoit": (b"AutoIt v3", b"AU3!EA06"),
    "qt-cpp": (b"Qt5Core.dll", b"Qt6Core.dll", b"qt_version_tag"),
}


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _rva_to_file_offset(pe: dict[str, Any], rva: int, size: int) -> int | None:
    for section in pe["sections"]:
        span = max(section.virtual_size, section.raw_size)
        if section.virtual_address <= rva < section.virtual_address + span:
            offset = section.raw_offset + rva - section.virtual_address
            return offset if 0 <= offset < size else None
    return rva if 0 <= rva < size else None


def _entry_section(pe: dict[str, Any]) -> Any | None:
    entry_rva = pe["entry_point_rva"]
    for section in pe["sections"]:
        span = max(section.virtual_size, section.raw_size)
        if section.virtual_address <= entry_rva < section.virtual_address + span:
            return section
    return None


def _extract_pdb_paths(data: bytes, limit: int = 20) -> list[dict[str, Any]]:
    paths: list[dict[str, Any]] = []
    for match in re.finditer(b"RSDS", data):
        start = match.start() + 24
        if start >= len(data):
            continue
        end = data.find(b"\0", start, min(len(data), start + 1024))
        if end < 0:
            continue
        raw = data[start:end]
        if not raw:
            continue
        paths.append(
            {
                "offset": match.start(),
                "offset_hex": f"0x{match.start():X}",
                "path": raw.decode("utf-8", errors="replace"),
            }
        )
        if len(paths) >= limit:
            break
    return paths


def _raw_boundaries(pe: dict[str, Any], file_size: int) -> dict[str, Any]:
    sections = sorted(
        (item for item in pe["sections"] if item.raw_size > 0),
        key=lambda item: item.raw_offset,
    )
    gaps: list[dict[str, Any]] = []
    cursor = pe.get("size_of_headers", 0)
    for section in sections:
        if section.raw_offset > cursor:
            gaps.append(
                {
                    "start": cursor,
                    "start_hex": f"0x{cursor:X}",
                    "end": section.raw_offset,
                    "end_hex": f"0x{section.raw_offset:X}",
                    "size": section.raw_offset - cursor,
                }
            )
        cursor = max(cursor, section.raw_offset + section.raw_size)
    logical_end = min(cursor, file_size)
    certificate = pe.get("data_directories", {}).get("certificate")
    return {
        "file_start": 0,
        "headers_end": pe.get("size_of_headers", 0),
        "last_section_raw_end": logical_end,
        "file_end": file_size,
        "overlay_offset": pe.get("overlay_offset"),
        "overlay_size": pe.get("overlay_size", 0),
        "certificate_table": certificate,
        "inter_section_gaps": gaps,
    }


def _technique_matches(symbols: set[str]) -> list[dict[str, Any]]:
    matches: list[dict[str, Any]] = []
    for technique, required in INJECTION_TECHNIQUES.items():
        present = sorted(required & symbols)
        minimum = 2 if len(required) > 2 else 1
        if present:
            matches.append(
                {
                    "technique": technique,
                    "matched_imports": present,
                    "confidence": (
                        "low"
                        if len(present) < minimum
                        else "medium"
                        if len(present) < len(required)
                        else "high"
                    ),
                    "minimum_candidate_primitives": minimum,
                    "interpretation": "Imported primitives only; confirm reachable call sites and data flow.",
                }
            )
    return matches


def _obfuscation_score(
    pe: dict[str, Any],
    injection: list[dict[str, Any]],
    packer_markers: list[dict[str, Any]],
) -> dict[str, Any]:
    score = 0
    reasons: list[dict[str, Any]] = []

    def add(points: int, reason: str) -> None:
        nonlocal score
        score += points
        reasons.append({"points": points, "reason": reason})

    high_entropy = [item.name for item in pe["sections"] if item.entropy >= 7.2]
    if high_entropy:
        add(min(30, len(high_entropy) * 10), "high-entropy sections: " + ", ".join(high_entropy))
    rwx = [item.name for item in pe["sections"] if item.permissions == "RWX"]
    if rwx:
        add(20, "RWX sections: " + ", ".join(rwx))
    packer_names = [
        item.name
        for item in pe["sections"]
        if re.match(r"(?i)^(UPX\d*|\.vmp\d*|\.themida|aspack|mpress)$", item.name)
    ]
    if packer_names:
        add(25, "packer-like section names: " + ", ".join(packer_names))
    if packer_markers:
        add(20, "packer/protector byte markers")
    import_count = sum(len(item.symbols) for item in pe["imports"])
    if import_count < 8 and high_entropy:
        add(10, "few static imports combined with high entropy")
    entry = _entry_section(pe)
    if entry and "W" in entry.permissions:
        add(10, f"entry point lies in writable section {entry.name}")
    if pe.get("overlay_size", 0) > 1024 * 1024:
        add(5, "large overlay")
    if injection:
        add(5, "injection-related primitives require review")
    score = min(score, 100)
    label = "high" if score >= 60 else "medium" if score >= 30 else "low"
    return {
        "score": score,
        "level": label,
        "reasons": reasons,
        "claim": "triage-candidate-not-proof",
    }


def analyze_pe_deep(
    path: str | Path,
    *,
    max_file_size: int = 512 * 1024 * 1024,
) -> dict[str, Any]:
    sample = Path(path).resolve()
    if not sample.is_file():
        raise AdvancedPeError(f"sample is not a regular file: {sample}")
    size = sample.stat().st_size
    if size > max_file_size:
        raise AdvancedPeError(f"sample exceeds configured limit {max_file_size}")
    data = sample.read_bytes()
    try:
        pe = parse_pe(data)
    except (AnalysisError, struct.error) as error:
        raise AdvancedPeError(str(error)) from error

    entry_section = _entry_section(pe)
    entry_offset = _rva_to_file_offset(pe, pe["entry_point_rva"], len(data))
    entry_bytes = data[entry_offset : entry_offset + 32] if entry_offset is not None else b""
    symbols = {
        symbol.lower()
        for library in pe["imports"]
        for symbol in library.symbols
        if not symbol.startswith("<")
    }
    lowered = data.lower()
    packer_markers = [
        {
            "name": description,
            "offset": lowered.find(marker),
            "offset_hex": f"0x{lowered.find(marker):X}",
        }
        for marker, description in PACKER_MARKERS.items()
        if marker in lowered
    ]
    dongle = [
        {
            "name": description,
            "offset": lowered.find(marker),
            "offset_hex": f"0x{lowered.find(marker):X}",
            "confidence": "medium",
        }
        for marker, description in DONGLE_MARKERS.items()
        if marker in lowered
    ]
    language_candidates = []
    for language, language_markers in LANGUAGE_MARKERS.items():
        matched = [
            marker.decode("latin-1", errors="replace")
            for marker in language_markers
            if marker.lower() in lowered
        ]
        if matched:
            language_candidates.append(
                {
                    "language_or_runtime": language,
                    "markers": matched,
                    "confidence": "high" if len(matched) > 1 else "medium",
                }
            )
    injection = _technique_matches(symbols)
    encryption_candidates = [
        {
            "section": section.name,
            "raw_offset": section.raw_offset,
            "raw_offset_hex": f"0x{section.raw_offset:X}",
            "raw_size": section.raw_size,
            "entropy": section.entropy,
            "reason": "high entropy may indicate compression, encryption, or dense data",
        }
        for section in pe["sections"]
        if section.raw_size >= 64 and section.entropy >= 7.4
    ]
    rich_offset = data.find(b"Rich", 0, min(len(data), 0x1000))
    marker_evidence = {
        "rich_header_candidate": (
            {"offset": rich_offset, "offset_hex": f"0x{rich_offset:X}"}
            if rich_offset >= 0
            else None
        ),
        "pdb_paths": _extract_pdb_paths(data),
        "packer_protector": packer_markers,
        "anti_debug_imports": sorted(symbols & ANTI_DEBUG_APIS),
        "dongle_license": dongle,
    }
    obfuscation = _obfuscation_score(pe, injection, packer_markers)
    return {
        "schema_version": "0.5.0",
        "source": {
            "path": str(sample),
            "size": size,
            "sha256": _sha256(data),
        },
        "pe": {
            key: value
            for key, value in pe.items()
            if key not in {"sections", "imports"}
        },
        "sections": [asdict(item) for item in pe["sections"]],
        "imports": [asdict(item) for item in pe["imports"]],
        "declared_entry_point": {
            "rva": pe["entry_point_rva"],
            "rva_hex": f"0x{pe['entry_point_rva']:X}",
            "va": pe["entry_point_va"],
            "file_offset": entry_offset,
            "file_offset_hex": f"0x{entry_offset:X}" if entry_offset is not None else None,
            "section": entry_section.name if entry_section else None,
            "section_permissions": entry_section.permissions if entry_section else None,
            "bytes": format_bytes(entry_bytes),
            "oep_status": "declared-entry-point-only",
            "original_entry_point_verified": False,
            "note": "Packed or self-modifying programs may transfer to a different runtime OEP.",
        },
        "boundaries": _raw_boundaries(pe, size),
        "markers": marker_evidence,
        "injection_indicators": injection,
        "obfuscation": obfuscation,
        "encryption_or_compression_candidates": encryption_candidates,
        "language_candidates": language_candidates,
        "whole_file_entropy": round(calculate_entropy(data), 4),
        "limitations": [
            "Static indicators do not prove runtime behavior.",
            "Generic decryption and true runtime OEP recovery require an approved isolated trace or dump.",
        ],
        "mutation_performed": False,
    }
