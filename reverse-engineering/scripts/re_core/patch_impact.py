from __future__ import annotations

import hashlib
import struct
from pathlib import Path
from typing import Any

from .analyzers import AnalysisError, calculate_entropy, detect_format, parse_pe
from .disassembly import DisassemblyError, disassemble_bytes
from .patching import PatchPlan, _parse_exact_bytes


class PatchImpactError(RuntimeError):
    """Raised when a patch cannot be previewed without ambiguity."""


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _pe_integrity_fields(data: bytes) -> dict[str, Any]:
    result: dict[str, Any] = {
        "checksum_offset": None,
        "certificate_table": None,
    }
    if len(data) < 0x40 or not data.startswith(b"MZ"):
        return result
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if pe_offset + 24 > len(data) or data[pe_offset : pe_offset + 4] != b"PE\0\0":
        return result
    coff = pe_offset + 4
    optional_size = struct.unpack_from("<H", data, coff + 16)[0]
    optional = coff + 20
    if optional + optional_size > len(data) or optional_size < 68:
        return result
    magic = struct.unpack_from("<H", data, optional)[0]
    if magic == 0x10B:
        count_offset, directory_offset = optional + 92, optional + 96
    elif magic == 0x20B:
        count_offset, directory_offset = optional + 108, optional + 112
    else:
        return result
    result["checksum_offset"] = optional + 64
    if count_offset + 4 > optional + optional_size:
        return result
    count = struct.unpack_from("<I", data, count_offset)[0]
    certificate_entry = directory_offset + 4 * 8
    if count > 4 and certificate_entry + 8 <= optional + optional_size:
        file_offset, size = struct.unpack_from("<II", data, certificate_entry)
        if file_offset and size:
            result["certificate_table"] = {
                "file_offset": file_offset,
                "file_offset_hex": f"0x{file_offset:X}",
                "size": size,
            }
    return result


def _intersects(start: int, size: int, other_start: int, other_size: int) -> bool:
    return start < other_start + other_size and other_start < start + size


def _section_for_offset(
    sections: list[Any], offset: int, size: int
) -> dict[str, Any] | None:
    for section in sections:
        if _intersects(offset, size, section.raw_offset, section.raw_size):
            return {
                "name": section.name,
                "raw_offset": section.raw_offset,
                "raw_size": section.raw_size,
                "permissions": section.permissions,
                "entropy_before": section.entropy,
            }
    return None


def _pe_entrypoint_offset(pe: dict[str, Any]) -> int | None:
    entry_rva = pe.get("entry_point_rva")
    if not isinstance(entry_rva, int):
        return None
    for section in pe["sections"]:
        span = max(section.virtual_size, section.raw_size)
        if section.virtual_address <= entry_rva < section.virtual_address + span:
            return int(section.raw_offset + (entry_rva - section.virtual_address))
    return entry_rva if entry_rva >= 0 else None


def preview_patch_impact(
    source: str | Path,
    plan: PatchPlan,
    *,
    architecture: str | None = None,
    disassembly_window: int = 64,
) -> dict[str, Any]:
    """Apply a sealed patch in memory and report projected effects; never write it."""
    source_path = Path(source).resolve()
    if not source_path.is_file():
        raise PatchImpactError(f"source does not exist: {source_path}")
    if source_path.stat().st_size > 512 * 1024 * 1024:
        raise PatchImpactError("patch-impact input exceeds the 512 MiB safety limit")
    original = source_path.read_bytes()
    original_sha256 = _sha256(original)
    if plan.plan_digest != plan.calculate_digest():
        raise PatchImpactError("patch plan digest validation failed")
    if plan.source_sha256 != original_sha256 or plan.source_size != len(original):
        raise PatchImpactError("patch plan was created for a different source")
    if not 16 <= disassembly_window <= 4096:
        raise ValueError("disassembly_window must be between 16 and 4096")

    projected = bytearray(original)
    occupied: set[int] = set()
    format_name, detected_architecture = detect_format(original)
    pe: dict[str, Any] | None = None
    limitations: list[str] = []
    if format_name == "PE":
        try:
            pe = parse_pe(original)
        except (AnalysisError, struct.error) as error:
            limitations.append(f"PE structural impact is incomplete: {error}")
    integrity = _pe_integrity_fields(original)
    first_section_offset = (
        min((item.raw_offset for item in pe["sections"]), default=len(original))
        if pe
        else 0
    )
    entrypoint_offset = _pe_entrypoint_offset(pe) if pe else None
    changes: list[dict[str, Any]] = []

    for operation in sorted(plan.operations, key=lambda item: item.offset):
        expected = _parse_exact_bytes(operation.expected)
        replacement = _parse_exact_bytes(operation.replacement)
        if len(expected) != len(replacement):
            raise PatchImpactError("patch-impact supports length-preserving operations")
        if operation.offset < 0 or operation.offset + len(expected) > len(original):
            raise PatchImpactError("patch operation is outside the source file")
        span = set(range(operation.offset, operation.offset + len(expected)))
        if occupied & span:
            raise PatchImpactError("patch operations overlap")
        occupied |= span
        actual = bytes(projected[operation.offset : operation.offset + len(expected)])
        if actual != expected:
            raise PatchImpactError(
                f"expected bytes do not match at 0x{operation.offset:X}"
            )
        projected[operation.offset : operation.offset + len(expected)] = replacement

        section = (
            _section_for_offset(pe["sections"], operation.offset, len(expected))
            if pe
            else None
        )
        if section and pe is not None:
            matching = next(item for item in pe["sections"] if item.name == section["name"])
            changed_section = bytes(
                projected[matching.raw_offset : matching.raw_offset + matching.raw_size]
            )
            section["entropy_after"] = round(calculate_entropy(changed_section), 4)
        certificate = integrity.get("certificate_table")
        in_certificate = bool(
            certificate
            and _intersects(
                operation.offset,
                len(expected),
                certificate["file_offset"],
                certificate["size"],
            )
        )
        in_overlay = bool(
            pe
            and pe.get("overlay_offset") is not None
            and operation.offset >= pe["overlay_offset"]
        )
        changes.append(
            {
                "offset": operation.offset,
                "offset_hex": f"0x{operation.offset:X}",
                "length": len(expected),
                "before": operation.expected,
                "after": operation.replacement,
                "rationale": operation.rationale,
                "section": section,
                "inside_headers": bool(pe and operation.offset < first_section_offset),
                "touches_entry_point": bool(
                    entrypoint_offset is not None
                    and _intersects(
                        operation.offset,
                        len(expected),
                        entrypoint_offset,
                        1,
                    )
                ),
                "in_overlay": in_overlay,
                "inside_certificate_table": in_certificate,
            }
        )

    inferred = {"x86": "x86", "x86-64": "x64"}.get(detected_architecture)
    selected_architecture = architecture or inferred
    disassembly: list[dict[str, Any]] = []
    if selected_architecture:
        for change in changes:
            start = max(0, change["offset"] - 16)
            end = min(len(original), start + disassembly_window)
            try:
                disassembly.append(
                    {
                        "offset": start,
                        "offset_hex": f"0x{start:X}",
                        "architecture": selected_architecture,
                        "before": disassemble_bytes(
                            original[start:end],
                            architecture=selected_architecture,
                            base_address=start,
                            max_instructions=128,
                        ),
                        "after": disassemble_bytes(
                            bytes(projected[start:end]),
                            architecture=selected_architecture,
                            base_address=start,
                            max_instructions=128,
                        ),
                        "note": "Linear preview; confirm code boundaries in IDA/Ghidra.",
                    }
                )
            except DisassemblyError as error:
                limitations.append(str(error))
                break
    else:
        limitations.append("No supported architecture was selected for disassembly preview.")

    certificate_present = bool(integrity.get("certificate_table"))
    return {
        "schema_version": "0.5.0",
        "status": "preview-only-not-written",
        "source": str(source_path),
        "source_sha256": original_sha256,
        "projected_sha256": _sha256(bytes(projected)),
        "plan_digest": plan.plan_digest,
        "format": format_name,
        "architecture": detected_architecture,
        "whole_file_entropy": {
            "before": round(calculate_entropy(original), 4),
            "after": round(calculate_entropy(bytes(projected)), 4),
        },
        "changes": changes,
        "integrity": {
            **integrity,
            "entry_point_file_offset": entrypoint_offset,
            "authenticode_present": certificate_present,
            "authenticode_will_require_resigning": certificate_present,
            "pe_checksum_recalculation_recommended": format_name == "PE",
        },
        "disassembly": disassembly,
        "limitations": sorted(set(limitations)),
        "mutation_performed": False,
    }
