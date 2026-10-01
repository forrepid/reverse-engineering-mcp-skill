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
        if section.virtual_address <= rva < section.virtual_address + section.virtual_size:
            delta = rva - section.virtual_address
            if delta >= section.raw_size:
                return None
            offset = section.raw_offset + delta
            return offset if 0 <= offset < min(size, section.raw_offset + section.raw_size) else None
    # Header RVAs are file-backed at the same offset; an unmapped gap/virtual
    # section tail is not a file offset and must not be guessed as one.
    header_end = int(pe.get("size_of_headers", 0))
    return rva if 0 <= rva < min(size, header_end) else None


def _entry_section(pe: dict[str, Any]) -> Any | None:
    entry_rva = pe["entry_point_rva"]
    for section in pe["sections"]:
        span = max(section.virtual_size, section.raw_size)
        if section.virtual_address <= entry_rva < section.virtual_address + span:
            return section
    return None


def _parse_tls_callbacks(
    data: bytes, pe: dict[str, Any], *, max_callbacks: int = 128
) -> dict[str, Any] | None:
    """Parse bounded PE TLS callback VAs without treating them as OEP proof."""
    tls = pe.get("data_directories", {}).get("tls")
    if not tls:
        return None
    image_base = int(pe.get("image_base") or 0)
    width = 8 if pe.get("bits") == 64 else 4
    directory_rva = int(tls.get("address") or 0)
    directory_size = int(tls.get("size") or 0)
    expected_size = 40 if width == 8 else 24
    directory_offset = _rva_to_file_offset(pe, directory_rva, len(data))
    result: dict[str, Any] = {
        "directory_rva": directory_rva,
        "directory_size": directory_size,
        "parsed": False,
        "complete": False,
        "callback_addresses": [],
        "termination_found": False,
        "reason": None,
    }
    if directory_size < expected_size:
        result["reason"] = "TLS directory is smaller than the architecture-specific structure"
        return result
    if directory_offset is None or directory_offset + expected_size > len(data):
        result["reason"] = "TLS directory does not map completely to file-backed bytes"
        return result
    callback_array_va_offset = 12 if width == 4 else 24
    callback_array_va = int.from_bytes(
        data[directory_offset + callback_array_va_offset : directory_offset + callback_array_va_offset + width],
        "little",
    )
    result["parsed"] = True
    if callback_array_va == 0:
        result["complete"] = True
        result["termination_found"] = True
        result["reason"] = "TLS directory has no callback array"
        return result
    if callback_array_va < image_base:
        result["reason"] = "TLS callback array VA is below image base"
        return result
    callback_array_rva = callback_array_va - image_base
    result["callback_array_rva"] = callback_array_rva
    array_offset = _rva_to_file_offset(pe, callback_array_rva, len(data))
    if array_offset is None:
        result["reason"] = "TLS callback array does not map to file-backed bytes"
        return result
    result["callback_array_file_offset"] = array_offset
    for index in range(max_callbacks):
        item_offset = array_offset + index * width
        if item_offset + width > len(data):
            result["reason"] = "TLS callback array reaches end of file before a terminator"
            return result
        callback_va = int.from_bytes(data[item_offset : item_offset + width], "little")
        if callback_va == 0:
            result["complete"] = True
            result["termination_found"] = True
            result["reason"] = "null terminator found"
            return result
        callback_rva = callback_va - image_base if callback_va >= image_base else None
        callback_offset = (
            _rva_to_file_offset(pe, callback_rva, len(data))
            if callback_rva is not None
            else None
        )
        callback_section = next(
            (
                section
                for section in pe["sections"]
                if callback_rva is not None
                and section.virtual_address <= callback_rva < section.virtual_address + max(section.virtual_size, section.raw_size)
            ),
            None,
        )
        result["callback_addresses"].append(
            {
                "va": callback_va,
                "rva": callback_rva,
                "file_offset": callback_offset,
                "section": callback_section.name if callback_section else None,
                "executable_section": bool(callback_section and "X" in callback_section.permissions),
                "status": "static_callback_candidate",
            }
        )
    result["reason"] = f"callback count exceeds configured limit ({max_callbacks})"
    return result


def _parse_cfg_metadata(data: bytes, pe: dict[str, Any], *, max_targets: int = 4096) -> dict[str, Any] | None:
    """Read bounded Load Config CFG metadata; it is not proof of control flow."""
    directory = pe.get("data_directories", {}).get("load_config")
    if not directory:
        return None
    is_64 = pe.get("bits") == 64
    width = 8 if is_64 else 4
    offsets = {"table": 128, "count": 136, "flags": 144} if is_64 else {"table": 80, "count": 84, "flags": 88}
    required_size = offsets["flags"] + 4
    rva = int(directory.get("address") or 0)
    declared_size = int(directory.get("size") or 0)
    file_offset = _rva_to_file_offset(pe, rva, len(data))
    result: dict[str, Any] = {
        "directory_rva": rva,
        "directory_size": declared_size,
        "parsed": False,
        "cfg_instrumented": None,
        "function_table_present": None,
        "function_table_entry_count": None,
        "entry_point_in_guard_cf_table": None,
        "reason": None,
    }
    if declared_size < required_size:
        result["reason"] = "load-config directory is too small for architecture-specific Guard CF fields"
        return result
    if file_offset is None or file_offset + min(declared_size, required_size) > len(data):
        result["reason"] = "load-config directory does not map to file-backed bytes"
        return result
    structure_size = int.from_bytes(data[file_offset : file_offset + 4], "little")
    if structure_size < required_size or structure_size > declared_size:
        result["reason"] = "load-config Size field is inconsistent with the directory bounds"
        return result
    table_va = int.from_bytes(data[file_offset + offsets["table"] : file_offset + offsets["table"] + width], "little")
    count = int.from_bytes(data[file_offset + offsets["count"] : file_offset + offsets["count"] + width], "little")
    flags = int.from_bytes(data[file_offset + offsets["flags"] : file_offset + offsets["flags"] + 4], "little")
    result.update(
        {
            "parsed": True,
            "guard_flags": flags,
            "guard_flags_hex": f"0x{flags:08X}",
            "cfg_instrumented": bool(flags & 0x100),
            "function_table_present": bool(flags & 0x400),
            "function_table_entry_count": count,
            "function_table_va": table_va or None,
            "reason": "Guard CF metadata parsed statically; runtime enforcement is not observed",
        }
    )
    if not (flags & 0x400):
        result["entry_point_in_guard_cf_table"] = None
        result["reason"] = "Guard CF function-table-present flag is not set; table pointers are not interpreted"
        return result
    if not count or not table_va:
        result["entry_point_in_guard_cf_table"] = False if not count else None
        return result
    if count > max_targets:
        result["reason"] = f"Guard CF target count exceeds parse limit ({max_targets})"
        return result
    image_base = int(pe.get("image_base") or 0)
    if table_va < image_base:
        result["reason"] = "Guard CF table VA is below image base"
        return result
    table_rva = table_va - image_base
    table_offset = _rva_to_file_offset(pe, table_rva, len(data))
    stride = 4 + ((flags & 0xF0000000) >> 28)
    table_bytes = count * stride
    if table_offset is None or table_bytes > len(data) - table_offset:
        result["reason"] = "Guard CF function table does not map completely to file-backed bytes"
        return result
    result["function_table_rva"] = table_rva
    result["function_table_file_offset"] = table_offset
    result["function_table_stride"] = stride
    previous_rva = -1
    entry_point_listed = False
    for index in range(count):
        item_offset = table_offset + index * stride
        target_rva = int.from_bytes(data[item_offset : item_offset + 4], "little") & 0xFFFFFFF0
        if target_rva < previous_rva:
            result["reason"] = "Guard CF function table RVAs are not monotonically sorted"
            result["entry_point_in_guard_cf_table"] = None
            return result
        previous_rva = target_rva
        entry_point_listed = entry_point_listed or target_rva == int(pe["entry_point_rva"])
    result["entry_point_in_guard_cf_table"] = entry_point_listed
    return result


def _oep_correlations(pe: dict[str, Any], packer_markers: list[dict[str, Any]]) -> dict[str, Any]:
    symbols = {
        symbol.lower()
        for library in pe.get("imports", [])
        for symbol in library.symbols
        if not symbol.startswith("<")
    }
    api_groups = {
        "memory_allocation_or_protection": {
            "virtualalloc", "virtualallocex", "virtualprotect", "virtualprotectex",
            "ntallocatevirtualmemory", "ntprotectvirtualmemory",
        },
        "dynamic_module_or_symbol_resolution": {
            "loadlibrarya", "loadlibraryw", "loadlibraryexa", "loadlibraryexw",
            "getprocaddress", "ldrloaddll", "ldrgetprocedureaddress",
        },
    }
    imported_api_signals = [
        {"category": category, "matched_imports": sorted(symbols & names), "interpretation": "import presence only; call sites and runtime use are unknown"}
        for category, names in api_groups.items()
        if symbols & names
    ]
    return {
        "import_api_signals": imported_api_signals,
        "packer_marker_signals": packer_markers,
        "high_entropy_executable_sections": [
            {"section": section.name, "entropy": section.entropy, "interpretation": "ambiguous: compression, packing, encryption, or dense code"}
            for section in pe.get("sections", [])
            if "X" in section.permissions and section.entropy >= 7.2
        ],
        "interpretation_limit": "independent static triage signals; no signal proves unpacking, OEP, or execution",
    }


def _oep_static_candidates(
    data: bytes, pe: dict[str, Any], entry_offset: int | None,
    packer_markers: list[dict[str, Any]],
) -> dict[str, Any]:
    """Rank PE OEP hypotheses; static evidence can never verify a runtime OEP."""
    candidates: list[dict[str, Any]] = []
    entry_rva = int(pe["entry_point_rva"])
    image_base = int(pe.get("image_base") or 0)
    entry_section = _entry_section(pe)
    declared_evidence: list[str] = ["PE Optional Header AddressOfEntryPoint"]
    if entry_section is not None:
        declared_evidence.append(f"mapped to section {entry_section.name}")
        if "X" in entry_section.permissions:
            declared_evidence.append("declared-entry section is executable")
        else:
            declared_evidence.append("declared-entry section is not executable")
        if entry_section.entropy >= 7.4:
            declared_evidence.append("declared-entry section has high entropy")
    else:
        declared_evidence.append("declared-entry RVA does not map to a section")
    candidates.append(
        {
            "kind": "declared_entry_point",
            "status": "reference_not_verified",
            "rva": entry_rva,
            "va": image_base + entry_rva if image_base else None,
            "file_offset": entry_offset if entry_section and "X" in entry_section.permissions else None,
            "section": entry_section.name if entry_section else None,
            "score": 0,
            "confidence": "reference",
            "evidence": declared_evidence,
            "contradictions": [],
        }
    )

    for section in pe["sections"]:
        if "X" not in section.permissions or max(section.virtual_size, section.raw_size) <= 0:
            continue
        points = 0
        evidence: list[str] = []
        if section.name.lower() in {".text", "code"}:
            points += 15
            evidence.append("conventional executable-code section name")
        if section.entropy < 7.2:
            points += 10
            evidence.append("section entropy is below the packing-candidate threshold")
        elif section.entropy >= 7.4:
            evidence.append("high entropy is ambiguous (compression, packing, encryption, or dense code)")
        section_end = section.virtual_address + max(section.virtual_size, section.raw_size)
        if section.virtual_address <= entry_rva < section_end:
            points += 20
            evidence.append("contains declared entry point")
        raw_size = min(section.raw_size, max(0, len(data) - section.raw_offset))
        if raw_size:
            prefix = data[section.raw_offset : section.raw_offset + min(raw_size, 64)]
            if any(prefix):
                points += 10
                evidence.append("raw section prefix is non-zero")
        first_raw_byte = section.virtual_address + section.raw_size
        candidate_rva = (
            first_raw_byte
            if section.virtual_size > section.raw_size
            else section.virtual_address
        )
        offset = _rva_to_file_offset(pe, candidate_rva, len(data))
        candidates.append(
            {
                "kind": "executable_section_entry_hypothesis",
                "status": "candidate",
                "rva": candidate_rva,
                "va": image_base + candidate_rva if image_base else None,
                "file_offset": offset,
                "section": section.name,
                "score": points,
                "confidence": "low" if points < 25 else "medium",
                "evidence": evidence,
                "contradictions": [],
            }
        )

    candidates.sort(
        key=lambda item: (
            item["kind"] == "declared_entry_point",
            item["score"],
            -(item["rva"] or 0),
        ),
        reverse=True,
    )
    tls_signal = _parse_tls_callbacks(data, pe)
    cfg_signal = _parse_cfg_metadata(data, pe)
    if tls_signal is not None:
        tls_signal["interpretation"] = "TLS callbacks may execute before AddressOfEntryPoint; addresses are static candidates only"
    return {
        "status": "candidate_analysis_complete",
        "method": "bounded_static_pe_heuristics",
        "runtime_verified": False,
        "candidates": candidates,
        "pre_entry_execution_signals": {
            "tls_directory": tls_signal,
            "guard_cf_load_config": cfg_signal,
            "note": "TLS callback presence is reported separately and is not itself an OEP determination",
        },
        "correlation_signals": _oep_correlations(pe, packer_markers),
        "limitations": [
            "Static heuristics rank hypotheses; they cannot verify the original runtime entry point.",
            "TLS callback addresses are statically decoded when safely file-backed; callback execution is not verified.",
            "CFG metadata and imports are static metadata, not evidence of runtime enforcement or reachable call sites.",
            "No program execution, host process access, debugger, or memory dump is performed.",
        ],
    }


def _validate_file_backed_rva_map(data: bytes, pe: dict[str, Any]) -> bool:
    """Reject ambiguous RVA overlap/out-of-bounds mappings before reporting offsets."""
    spans: list[tuple[int, int, Any]] = []
    for section in pe["sections"]:
        virtual_span = max(section.virtual_size, section.raw_size)
        if virtual_span < 0 or section.virtual_address + virtual_span > 0x1_0000_0000:
            return False
        if section.raw_size and (
            section.raw_offset < 0
            or section.raw_offset + section.raw_size > len(data)
        ):
            return False
        spans.append((section.virtual_address, section.virtual_address + virtual_span, section))
    spans.sort(key=lambda item: item[0])
    for previous, current in zip(spans, spans[1:], strict=False):
        if previous[1] > current[0]:
            return False
    return True


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
    max_scan_bytes: int = 64 * 1024 * 1024,
) -> dict[str, Any]:
    sample = Path(path).resolve()
    if not sample.is_file():
        raise AdvancedPeError(f"sample is not a regular file: {sample}")
    size = sample.stat().st_size
    if size > max_file_size:
        raise AdvancedPeError(f"sample exceeds configured limit {max_file_size}")
    deep_limit = min(max_scan_bytes, 64 * 1024 * 1024)
    if size > deep_limit:
        raise AdvancedPeError(f"sample exceeds deep-analysis working-set limit {deep_limit} bytes (configured scan limit {max_scan_bytes}); deep PE analysis requires a complete bounded image")
    data = sample.read_bytes()
    try:
        pe = parse_pe(data)
    except (AnalysisError, struct.error) as error:
        raise AdvancedPeError(str(error)) from error
    address_map_valid = _validate_file_backed_rva_map(data, pe)

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
    oep_analysis = _oep_static_candidates(data, pe, entry_offset, packer_markers)
    oep_analysis["address_map_valid"] = address_map_valid
    if not address_map_valid:
        oep_analysis["limitations"].append(
            "PE section RVA/raw ranges overlap or exceed file bounds; candidate offsets are ambiguous and are not verified"
        )
        for candidate in oep_analysis["candidates"]:
            candidate["file_offset"] = None
            candidate["confidence"] = "low"
            candidate["contradictions"].append("PE address map is structurally ambiguous")
    declared_rva = int(pe["entry_point_rva"])
    declared_va = int(pe["entry_point_va"])
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
            "rva": declared_rva,
            "rva_hex": f"0x{declared_rva:X}",
            "va": declared_va,
            "file_offset": entry_offset,
            "file_offset_hex": f"0x{entry_offset:X}" if entry_offset is not None else None,
            "section": entry_section.name if entry_section else None,
            "section_permissions": entry_section.permissions if entry_section else None,
            "bytes": format_bytes(entry_bytes),
            "oep_status": "declared-entry-point-only",
            "original_entry_point_verified": False,
            "note": "Packed or self-modifying programs may transfer to a different runtime OEP.",
        },
        "oep_result": {
            "display_label": "Runtime OEP",
            "value": None,
            "value_hex": None,
            "status": "not_verified",
            "runtime_verified": False,
            "declared_ep_rva": declared_rva,
            "declared_ep_va": declared_va,
            "display_text": (
                f"Runtime OEP: NOT VERIFIED; PE declared EP is RVA 0x{declared_rva:X} "
                f"/ VA 0x{declared_va:X} (reference only)"
            ),
            "note": "Static candidates are hypotheses; a runtime value appears only after signed isolated trace and dump verification.",
        },
        "oep_analysis": oep_analysis,
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
