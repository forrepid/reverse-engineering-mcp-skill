from __future__ import annotations

import hashlib
import math
import platform
import re
import struct
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Iterable

from .models import (
    AnalysisResult,
    ExtractedString,
    FileIdentity,
    Finding,
    ImportLibrary,
    Section,
)


class AnalysisError(RuntimeError):
    """Raised when a sample cannot be analyzed safely."""


def parse_int(value: str | int) -> int:
    if isinstance(value, int):
        return value
    return int(value.strip(), 0)


def format_bytes(data: bytes) -> str:
    return " ".join(f"{byte:02X}" for byte in data)


def calculate_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    size = len(data)
    return -sum(
        (count / size) * math.log2(count / size) for count in counts.values()
    )


def hexdump(data: bytes, base_offset: int = 0, width: int = 16) -> str:
    if width < 4 or width > 64:
        raise ValueError("width must be between 4 and 64")
    lines: list[str] = []
    for index in range(0, len(data), width):
        chunk = data[index : index + width]
        hex_part = " ".join(f"{byte:02X}" for byte in chunk)
        ascii_part = "".join(chr(byte) if 32 <= byte <= 126 else "." for byte in chunk)
        lines.append(
            f"{base_offset + index:08X}  {hex_part:<{width * 3 - 1}}  |{ascii_part}|"
        )
    return "\n".join(lines)


def bitdump(data: bytes, base_offset: int = 0) -> str:
    return "\n".join(
        f"{base_offset + index:08X}  {byte:02X}  {byte:08b}"
        for index, byte in enumerate(data)
    )


def compile_hex_pattern(pattern: str) -> tuple[bytes, bytes]:
    tokens = pattern.strip().split()
    if not tokens:
        raise ValueError("hex pattern is empty")
    values = bytearray()
    masks = bytearray()
    for token in tokens:
        token = token.upper()
        if token in {"?", "??"}:
            values.append(0)
            masks.append(0)
            continue
        if not re.fullmatch(r"[0-9A-F]{2}", token):
            raise ValueError(f"invalid hex token: {token}")
        values.append(int(token, 16))
        masks.append(0xFF)
    return bytes(values), bytes(masks)


def search_hex(data: bytes, pattern: str, limit: int = 1000) -> list[int]:
    if limit < 1 or limit > 100_000:
        raise ValueError("limit must be between 1 and 100000")
    values, masks = compile_hex_pattern(pattern)
    length = len(values)
    matches: list[int] = []
    for offset in range(0, len(data) - length + 1):
        if all(
            masks[index] == 0 or data[offset + index] == values[index]
            for index in range(length)
        ):
            matches.append(offset)
            if len(matches) >= limit:
                break
    return matches


def search_text(
    data: bytes,
    pattern: str,
    *,
    encoding: str = "latin-1",
    ignore_case: bool = False,
    limit: int = 1000,
) -> list[dict[str, Any]]:
    if limit < 1 or limit > 100_000:
        raise ValueError("limit must be between 1 and 100000")
    flags = re.IGNORECASE if ignore_case else 0
    regex = re.compile(pattern.encode(encoding), flags)
    matches: list[dict[str, Any]] = []
    for match in regex.finditer(data):
        matches.append(
            {
                "offset": match.start(),
                "hex": f"0x{match.start():X}",
                "value": match.group(0).decode(encoding, errors="replace"),
            }
        )
        if len(matches) >= limit:
            break
    return matches


def _hashes(path: Path) -> tuple[int, str, str, str]:
    sha256 = hashlib.sha256()
    sha1 = hashlib.sha1()
    md5 = hashlib.md5()
    size = 0
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            size += len(chunk)
            sha256.update(chunk)
            sha1.update(chunk)
            md5.update(chunk)
    return size, sha256.hexdigest(), sha1.hexdigest(), md5.hexdigest()


def _read_ascii_z(data: bytes, offset: int, max_length: int = 512) -> str:
    if offset < 0 or offset >= len(data):
        return ""
    end = data.find(b"\x00", offset, min(len(data), offset + max_length))
    if end < 0:
        end = min(len(data), offset + max_length)
    raw = data[offset:end]
    if not raw or any(byte < 0x20 or byte > 0x7E for byte in raw):
        return ""
    return raw.decode("ascii", errors="replace")


def extract_strings(
    data: bytes,
    *,
    min_length: int = 4,
    limit: int = 5000,
) -> tuple[list[ExtractedString], bool]:
    if min_length < 3 or min_length > 128:
        raise ValueError("min_length must be between 3 and 128")
    if limit < 1 or limit > 100_000:
        raise ValueError("limit must be between 1 and 100000")

    results: list[ExtractedString] = []
    ascii_re = re.compile(rb"[\x20-\x7E]{" + str(min_length).encode() + rb",}")
    utf16_re = re.compile(
        rb"(?:[\x20-\x7E]\x00){" + str(min_length).encode() + rb",}"
    )
    for encoding, regex in (("ascii", ascii_re), ("utf-16le", utf16_re)):
        for match in regex.finditer(data):
            value = match.group(0).decode(encoding, errors="replace")
            results.append(
                ExtractedString(
                    offset=match.start(),
                    encoding=encoding,
                    value=value,
                )
            )
            if len(results) >= limit:
                return sorted(results, key=lambda item: item.offset), True
    return sorted(results, key=lambda item: item.offset), False


PE_MACHINES = {
    0x014C: "x86",
    0x8664: "x86-64",
    0x01C0: "ARM",
    0x01C4: "ARMv7",
    0xAA64: "ARM64",
}

ELF_MACHINES = {
    0x03: "x86",
    0x08: "MIPS",
    0x14: "PowerPC",
    0x28: "ARM",
    0x3E: "x86-64",
    0xB7: "AArch64",
    0xF3: "RISC-V",
}


def detect_format(data: bytes) -> tuple[str, str]:
    if data.startswith(b"MZ"):
        return "PE", "unknown"
    if data.startswith(b"\x7FELF"):
        if len(data) >= 20:
            byte_order = "<" if data[5:6] == b"\x01" else ">"
            machine = struct.unpack_from(byte_order + "H", data, 18)[0]
            bits = {1: "32-bit", 2: "64-bit"}.get(data[4], "unknown")
            return "ELF", f"{ELF_MACHINES.get(machine, f'machine-0x{machine:X}')} {bits}"
        return "ELF", "unknown"
    magic = data[:4]
    macho = {
        b"\xFE\xED\xFA\xCE": "Mach-O 32-bit big-endian",
        b"\xCE\xFA\xED\xFE": "Mach-O 32-bit little-endian",
        b"\xFE\xED\xFA\xCF": "Mach-O 64-bit big-endian",
        b"\xCF\xFA\xED\xFE": "Mach-O 64-bit little-endian",
        b"\xCA\xFE\xBA\xBE": "Mach-O universal",
    }
    if magic in macho:
        return "Mach-O", macho[magic]
    if data.startswith(b"PK\x03\x04"):
        return "ZIP", "archive"
    if data.startswith(b"%PDF-"):
        return "PDF", "document"
    return "unknown", "unknown"


def _u16(data: bytes, offset: int) -> int:
    return int(struct.unpack_from("<H", data, offset)[0])


def _u32(data: bytes, offset: int) -> int:
    return int(struct.unpack_from("<I", data, offset)[0])


def _u64(data: bytes, offset: int) -> int:
    return int(struct.unpack_from("<Q", data, offset)[0])


def _permissions(characteristics: int) -> str:
    return "".join(
        (
            "R" if characteristics & 0x40000000 else "-",
            "W" if characteristics & 0x80000000 else "-",
            "X" if characteristics & 0x20000000 else "-",
        )
    )


def _rva_to_offset(rva: int, sections: Iterable[Section], size: int) -> int | None:
    for section in sections:
        span = max(section.virtual_size, section.raw_size)
        if section.virtual_address <= rva < section.virtual_address + span:
            offset = section.raw_offset + (rva - section.virtual_address)
            return offset if 0 <= offset < size else None
    return rva if 0 <= rva < size else None


def parse_pe(data: bytes) -> dict[str, Any]:
    if len(data) < 0x40 or not data.startswith(b"MZ"):
        raise AnalysisError("not a valid DOS/PE header")
    pe_offset = _u32(data, 0x3C)
    if pe_offset + 24 > len(data) or data[pe_offset : pe_offset + 4] != b"PE\x00\x00":
        raise AnalysisError("PE signature is missing or out of bounds")

    coff = pe_offset + 4
    machine = _u16(data, coff)
    number_of_sections = _u16(data, coff + 2)
    timestamp = _u32(data, coff + 4)
    optional_size = _u16(data, coff + 16)
    characteristics = _u16(data, coff + 18)
    optional = coff + 20
    if number_of_sections > 512 or optional + optional_size > len(data):
        raise AnalysisError("PE header declares unsafe section or optional-header bounds")

    optional_magic = _u16(data, optional) if optional_size >= 2 else 0
    if optional_magic == 0x10B:
        bits = 32
        image_base = _u32(data, optional + 28)
        directory_count = _u32(data, optional + 92) if optional_size >= 96 else 0
        directory_offset = optional + 96
    elif optional_magic == 0x20B:
        bits = 64
        image_base = _u64(data, optional + 24)
        directory_count = _u32(data, optional + 108) if optional_size >= 112 else 0
        directory_offset = optional + 112
    else:
        bits = 0
        image_base = 0
        directory_count = 0
        directory_offset = optional + optional_size

    entry_rva = _u32(data, optional + 16) if optional_size >= 20 else 0
    linker_version = (
        f"{data[optional + 2]}.{data[optional + 3]}" if optional_size >= 4 else ""
    )
    section_alignment = _u32(data, optional + 32) if optional_size >= 36 else 0
    file_alignment = _u32(data, optional + 36) if optional_size >= 40 else 0
    size_of_image = _u32(data, optional + 56) if optional_size >= 60 else 0
    size_of_headers = _u32(data, optional + 60) if optional_size >= 64 else 0
    checksum = _u32(data, optional + 64) if optional_size >= 68 else 0
    subsystem = _u16(data, optional + 68) if optional_size >= 70 else 0
    dll_characteristics = _u16(data, optional + 70) if optional_size >= 72 else 0
    section_table = optional + optional_size
    sections: list[Section] = []
    for index in range(number_of_sections):
        offset = section_table + index * 40
        if offset + 40 > len(data):
            raise AnalysisError("section table extends beyond the file")
        name = data[offset : offset + 8].split(b"\x00", 1)[0].decode(
            "ascii", errors="replace"
        )
        virtual_size = _u32(data, offset + 8)
        virtual_address = _u32(data, offset + 12)
        raw_size = _u32(data, offset + 16)
        raw_offset = _u32(data, offset + 20)
        section_characteristics = _u32(data, offset + 36)
        raw_end = min(len(data), raw_offset + raw_size)
        section_data = data[raw_offset:raw_end] if raw_offset < len(data) else b""
        sections.append(
            Section(
                name=name or f"section_{index}",
                virtual_address=virtual_address,
                virtual_size=virtual_size,
                raw_offset=raw_offset,
                raw_size=raw_size,
                characteristics=section_characteristics,
                permissions=_permissions(section_characteristics),
                entropy=round(calculate_entropy(section_data), 4),
            )
        )

    imports: list[ImportLibrary] = []
    if directory_count > 1 and directory_offset + 16 <= optional + optional_size:
        import_rva = _u32(data, directory_offset + 8)
        import_offset = _rva_to_offset(import_rva, sections, len(data))
        if import_rva and import_offset is not None:
            imports = _parse_pe_imports(data, import_offset, sections, bits)

    directory_names = {
        0: "export",
        1: "import",
        2: "resource",
        3: "exception",
        4: "certificate",
        5: "relocation",
        6: "debug",
        9: "tls",
        10: "load_config",
        12: "iat",
        13: "delay_import",
        14: "clr",
    }
    data_directories: dict[str, dict[str, int | str]] = {}
    for index, name in directory_names.items():
        entry = directory_offset + index * 8
        if index >= directory_count or entry + 8 > optional + optional_size:
            continue
        address = _u32(data, entry)
        directory_size = _u32(data, entry + 4)
        if not address and not directory_size:
            continue
        data_directories[name] = {
            "address": address,
            "address_hex": f"0x{address:X}",
            "size": directory_size,
            "address_space": "file_offset" if index == 4 else "rva",
        }

    end_of_sections = max(
        (section.raw_offset + section.raw_size for section in sections), default=0
    )
    overlay_offset = end_of_sections if 0 < end_of_sections < len(data) else None
    return {
        "architecture": PE_MACHINES.get(machine, f"machine-0x{machine:X}"),
        "bits": bits,
        "machine": machine,
        "timestamp": timestamp,
        "characteristics": characteristics,
        "image_base": image_base,
        "entry_point_rva": entry_rva,
        "entry_point_va": image_base + entry_rva if image_base else None,
        "linker_version": linker_version,
        "section_alignment": section_alignment,
        "file_alignment": file_alignment,
        "size_of_image": size_of_image,
        "size_of_headers": size_of_headers,
        "checksum": checksum,
        "subsystem": subsystem,
        "dll_characteristics": dll_characteristics,
        "data_directories": data_directories,
        "sections": sections,
        "imports": imports,
        "is_dll": bool(characteristics & 0x2000),
        "overlay_offset": overlay_offset,
        "overlay_size": len(data) - overlay_offset if overlay_offset is not None else 0,
    }


def _parse_pe_imports(
    data: bytes,
    descriptor_offset: int,
    sections: list[Section],
    bits: int,
) -> list[ImportLibrary]:
    libraries: list[ImportLibrary] = []
    for descriptor_index in range(4096):
        offset = descriptor_offset + descriptor_index * 20
        if offset + 20 > len(data):
            break
        original_first_thunk = _u32(data, offset)
        name_rva = _u32(data, offset + 12)
        first_thunk = _u32(data, offset + 16)
        if not any(data[offset : offset + 20]):
            break
        name_offset = _rva_to_offset(name_rva, sections, len(data))
        dll_name = _read_ascii_z(data, name_offset) if name_offset is not None else ""
        if not dll_name:
            dll_name = f"<invalid-name-rva-0x{name_rva:X}>"
        thunk_rva = original_first_thunk or first_thunk
        thunk_offset = _rva_to_offset(thunk_rva, sections, len(data))
        symbols: list[str] = []
        if thunk_offset is not None:
            width = 8 if bits == 64 else 4
            ordinal_mask = 1 << (63 if bits == 64 else 31)
            value_mask = ordinal_mask - 1
            for symbol_index in range(4096):
                entry_offset = thunk_offset + symbol_index * width
                if entry_offset + width > len(data):
                    break
                value = _u64(data, entry_offset) if width == 8 else _u32(data, entry_offset)
                if value == 0:
                    break
                if value & ordinal_mask:
                    symbols.append(f"ordinal:{value & 0xFFFF}")
                    continue
                hint_name_offset = _rva_to_offset(value & value_mask, sections, len(data))
                name = (
                    _read_ascii_z(data, hint_name_offset + 2)
                    if hint_name_offset is not None and hint_name_offset + 2 < len(data)
                    else ""
                )
                symbols.append(name or f"<invalid-import-rva-0x{value & value_mask:X}>")
        libraries.append(ImportLibrary(name=dll_name, symbols=symbols))
    return libraries


INJECTION_APIS = {
    "createremotethread",
    "ntcreatethreadex",
    "rtlcreateuserthread",
    "virtualallocex",
    "writeprocessmemory",
    "ntwritevirtualmemory",
    "queueuserapc",
    "setthreadcontext",
    "openprocess",
}

ANTI_DEBUG_APIS = {
    "checkremotedebuggerpresent",
    "isdebuggerpresent",
    "ntqueryinformationprocess",
    "outputdebugstringa",
    "outputdebugstringw",
}

PACKER_SECTION_RE = re.compile(
    r"^(UPX\d*|ASPack|\.aspack|\.adata|PECompact|Themida|\.vmp\d*)$",
    re.IGNORECASE,
)


class StaticAnalyzer:
    def __init__(
        self,
        *,
        max_file_size: int = 512 * 1024 * 1024,
        min_string_length: int = 4,
        max_strings: int = 5000,
    ) -> None:
        self.max_file_size = max_file_size
        self.min_string_length = min_string_length
        self.max_strings = max_strings

    def analyze(self, path: str | Path) -> AnalysisResult:
        sample = Path(path)
        if not sample.is_file():
            raise AnalysisError(f"sample is not a regular file: {sample}")
        size, sha256, sha1, md5 = _hashes(sample)
        if size > self.max_file_size:
            raise AnalysisError(
                f"sample size {size} exceeds configured limit {self.max_file_size}"
            )
        data = sample.read_bytes()
        file_format, architecture = detect_format(data)
        identity = FileIdentity.from_values(sample, size, sha256, sha1, md5)
        strings, strings_truncated = extract_strings(
            data,
            min_length=self.min_string_length,
            limit=self.max_strings,
        )
        summary: dict[str, Any] = {
            "format": file_format,
            "architecture": architecture,
            "entropy": round(calculate_entropy(data), 4),
            "header_hex": format_bytes(data[:32]),
        }
        sections: list[Section] = []
        imports: list[ImportLibrary] = []
        limitations: list[str] = []
        findings: list[Finding] = []

        if strings_truncated:
            limitations.append(f"strings truncated at configured limit {self.max_strings}")

        if file_format == "PE":
            try:
                pe = parse_pe(data)
                sections = pe.pop("sections")
                imports = pe.pop("imports")
                summary.update(pe)
            except (AnalysisError, struct.error) as error:
                limitations.append(f"PE parsing incomplete: {error}")

        findings.extend(self._heuristic_findings(summary, sections, imports))
        return AnalysisResult(
            source=identity,
            summary=summary,
            sections=sections,
            imports=imports,
            strings=strings,
            findings=findings,
            limitations=limitations,
            environment={
                "python": sys.version.split()[0],
                "platform": platform.platform(),
                "analyzer": "re-core-stdlib/0.5.0",
            },
        )

    @staticmethod
    def _heuristic_findings(
        summary: dict[str, Any],
        sections: list[Section],
        imports: list[ImportLibrary],
    ) -> list[Finding]:
        findings: list[Finding] = []
        if summary.get("entropy", 0) >= 7.2:
            findings.append(
                Finding(
                    id="triage.high-entropy",
                    title="High whole-file entropy",
                    source="re-core-stdlib",
                    observation=f"Whole-file entropy is {summary['entropy']:.4f} bits/byte.",
                    interpretation=(
                        "Compression, encryption, packed code, or dense non-code data may be present."
                    ),
                    confidence="medium",
                    severity="info",
                    tags=["entropy", "packing-candidate"],
                )
            )

        for section in sections:
            location = {
                "space": "file_offset",
                "value": section.raw_offset,
                "hex": f"0x{section.raw_offset:X}",
            }
            if section.permissions == "RWX":
                findings.append(
                    Finding(
                        id="pe.rwx-section",
                        title="Read-write-execute PE section",
                        source="re-core-stdlib",
                        observation=f"Section {section.name!r} has RWX permissions.",
                        interpretation="Verify whether runtime code modification is intended.",
                        location=location,
                        confidence="high",
                        severity="medium",
                        tags=["pe", "permissions", "rwx"],
                    )
                )
            if PACKER_SECTION_RE.match(section.name):
                findings.append(
                    Finding(
                        id="pe.packer-section-name",
                        title="Known packer-like section name",
                        source="re-core-stdlib",
                        observation=f"Section name {section.name!r} matched a triage signature.",
                        interpretation="Confirm with DiE/YARA-X and entry-point code.",
                        location=location,
                        confidence="medium",
                        severity="info",
                        tags=["pe", "packer-candidate"],
                    )
                )

        symbols = {
            symbol.lower()
            for library in imports
            for symbol in library.symbols
            if not symbol.startswith("<")
        }
        injection_matches = sorted(symbols & INJECTION_APIS)
        if injection_matches:
            findings.append(
                Finding(
                    id="capability.process-injection-primitives",
                    title="Process-injection-related imports",
                    source="re-core-stdlib",
                    observation="Imported APIs: " + ", ".join(injection_matches),
                    interpretation=(
                        "These primitives can have legitimate uses; verify call sites and data flow."
                    ),
                    confidence="medium",
                    severity="low",
                    tags=["imports", "injection-candidate"],
                )
            )
        anti_debug_matches = sorted(symbols & ANTI_DEBUG_APIS)
        if anti_debug_matches:
            findings.append(
                Finding(
                    id="capability.anti-debug-primitives",
                    title="Anti-debug-related imports",
                    source="re-core-stdlib",
                    observation="Imported APIs: " + ", ".join(anti_debug_matches),
                    interpretation="Verify whether these imports are reached and how results are used.",
                    confidence="medium",
                    severity="info",
                    tags=["imports", "anti-debug-candidate"],
                )
            )
        return findings
