from __future__ import annotations

import hashlib
import re
import struct
import zipfile
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from .analyzers import AnalysisError, detect_format, parse_pe


class FileTypeError(RuntimeError):
    """Raised when a file cannot be classified within bounded limits."""


@dataclass(frozen=True)
class TypeEvidence:
    kind: str
    value: str
    confidence: str
    offset: int | None = None


@dataclass
class FileTypeResult:
    path: str
    size: int
    sha256: str
    primary_category: str
    categories: list[str]
    format: str
    subtype: str
    media_type: str
    architecture: str
    confidence: str
    evidence: list[TypeEvidence] = field(default_factory=list)
    container_entries: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    schema_version: str = "0.5.0"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


DONGLE_MARKERS = {
    b"hasp_": "Sentinel HASP API",
    b"hasp_windows": "Sentinel HASP runtime",
    b"sentinel ldk": "Sentinel LDK",
    b"sntl_adminapi": "Sentinel Admin API",
    b"wibu": "Wibu license component",
    b"codemeter": "CodeMeter component",
    b"wupiw32": "WibuKey API",
    b"flexnet": "FlexNet component",
    b"lmgrd": "FlexNet license manager",
    b"rockey": "Rockey dongle component",
    b"aksusb": "Aladdin/Sentinel USB driver",
}


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _add_category(categories: list[str], value: str) -> None:
    if value not in categories:
        categories.append(value)


def _add_evidence(
    evidence: list[TypeEvidence],
    kind: str,
    value: str,
    confidence: str = "high",
    offset: int | None = None,
) -> None:
    evidence.append(TypeEvidence(kind, value, confidence, offset))


def _pe_details(data: bytes) -> dict[str, Any]:
    pe = parse_pe(data)
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    optional = pe_offset + 24
    optional_size = struct.unpack_from("<H", data, pe_offset + 20)[0]
    magic = struct.unpack_from("<H", data, optional)[0]
    subsystem = (
        struct.unpack_from("<H", data, optional + 68)[0]
        if optional_size >= 70
        else 0
    )
    if magic == 0x10B:
        count_offset, directory_offset = optional + 92, optional + 96
    elif magic == 0x20B:
        count_offset, directory_offset = optional + 108, optional + 112
    else:
        count_offset, directory_offset = 0, 0
    clr_rva = 0
    if count_offset and count_offset + 4 <= optional + optional_size:
        count = struct.unpack_from("<I", data, count_offset)[0]
        clr_entry = directory_offset + 14 * 8
        if count > 14 and clr_entry + 8 <= optional + optional_size:
            clr_rva = struct.unpack_from("<I", data, clr_entry)[0]
    return {**pe, "subsystem": subsystem, "clr_rva": clr_rva}


def _classify_zip(
    path: Path,
    categories: list[str],
    evidence: list[TypeEvidence],
    limitations: list[str],
) -> tuple[str, str, str, list[str]]:
    subtype = "zip-archive"
    media_type = "application/zip"
    primary = "binary"
    entries: list[str] = []
    try:
        with zipfile.ZipFile(path) as archive:
            infos = archive.infolist()
            if len(infos) > 100_000:
                raise FileTypeError("ZIP central directory exceeds 100000 entries")
            names = [item.filename.replace("\\", "/") for item in infos]
            entries = names[:200]
            if len(names) > len(entries):
                limitations.append("container entry list truncated at 200 names")
            lowered = {name.lower() for name in names}
            if "androidmanifest.xml" in lowered and any(
                name.startswith("classes") and name.endswith(".dex")
                for name in lowered
            ):
                primary, subtype, media_type = (
                    "android",
                    "android-apk",
                    "application/vnd.android.package-archive",
                )
                for category in ("android", "java", "binary"):
                    _add_category(categories, category)
                _add_evidence(evidence, "container", "AndroidManifest.xml + classes*.dex")
            elif "bundleconfig.pb" in lowered and any(
                name.startswith("base/manifest/") for name in lowered
            ):
                primary, subtype = "android", "android-app-bundle"
                for category in ("android", "java", "binary"):
                    _add_category(categories, category)
                _add_evidence(evidence, "container", "BundleConfig.pb + base manifest")
            elif "androidmanifest.xml" in lowered and "classes.jar" in lowered:
                primary, subtype = "android", "android-aar"
                for category in ("android", "java", "binary"):
                    _add_category(categories, category)
                _add_evidence(evidence, "container", "AndroidManifest.xml + classes.jar")
            elif any(name.startswith("payload/") and ".app/" in name for name in lowered):
                primary, subtype, media_type = "mac", "apple-ipa", "application/x-ios-app"
                for category in ("mac", "binary"):
                    _add_category(categories, category)
                _add_evidence(evidence, "container", "Payload/*.app bundle")
            elif "meta-inf/manifest.mf" in lowered and any(
                name.endswith(".class") for name in lowered
            ):
                primary, subtype, media_type = (
                    "java",
                    "java-jar",
                    "application/java-archive",
                )
                for category in ("java", "binary"):
                    _add_category(categories, category)
                _add_evidence(evidence, "container", "META-INF/MANIFEST.MF + .class")
            elif "package.json" in lowered:
                primary, subtype = "script", "javascript-package"
                _add_category(categories, "script")
                _add_evidence(evidence, "container", "package.json")
    except (zipfile.BadZipFile, OSError, RuntimeError) as error:
        limitations.append(f"ZIP inspection incomplete: {error}")
    return primary, subtype, media_type, entries


def _text_kind(data: bytes, suffix: str) -> tuple[str, str] | None:
    if not data or b"\x00" in data[:4096]:
        return None
    text = data[:256 * 1024].decode("utf-8", errors="replace")
    stripped = text.lstrip()
    script_extensions = {
        ".py": "python",
        ".ps1": "powershell",
        ".js": "javascript",
        ".mjs": "javascript-module",
        ".ts": "typescript",
        ".sh": "shell",
        ".bash": "bash",
        ".bat": "batch",
        ".cmd": "batch",
        ".vbs": "vbscript",
        ".lua": "lua",
        ".php": "php",
        ".rb": "ruby",
        ".pl": "perl",
    }
    if suffix in script_extensions:
        return "script", script_extensions[suffix]
    if stripped.startswith("#!"):
        first = stripped.splitlines()[0][:160]
        return "script", f"shebang:{first}"
    if suffix in {".asm", ".s", ".inc", ".nasm"} or re.search(
        r"(?im)^\s*(section\s+\.text|\.text\b|global\s+\w+|[a-z_][\w.]*:\s*$)",
        text,
    ):
        return "assembly", "assembly-source"
    if suffix in {".svg"} and "<svg" in stripped[:2048].lower():
        return "visual", "svg"
    return None


def _looks_like_java_class(data: bytes, suffix: str) -> bool:
    if len(data) < 10 or not data.startswith(b"\xca\xfe\xba\xbe"):
        return False
    _, major = struct.unpack_from(">HH", data, 4)
    fat_arch_count = struct.unpack_from(">I", data, 4)[0]
    return 45 <= major <= 100 and (suffix == ".class" or fat_arch_count > 32)


def classify_file(
    path: str | Path,
    *,
    max_file_size: int = 512 * 1024 * 1024,
) -> FileTypeResult:
    sample = Path(path).resolve()
    if not sample.is_file():
        raise FileTypeError(f"sample is not a regular file: {sample}")
    size = sample.stat().st_size
    if size > max_file_size:
        raise FileTypeError(f"sample exceeds configured limit {max_file_size}")
    with sample.open("rb") as stream:
        data = stream.read(min(size, 8 * 1024 * 1024))
    sha256 = _sha256_file(sample)
    suffix = sample.suffix.lower()
    categories: list[str] = []
    evidence: list[TypeEvidence] = []
    limitations: list[str] = []
    entries: list[str] = []
    primary, subtype, media_type = "binary", "unknown-binary", "application/octet-stream"
    architecture = "unknown"
    confidence = "medium"

    file_format, detected_architecture = detect_format(data)
    architecture = detected_architecture
    if data.startswith(b"MZ"):
        primary, media_type, confidence = "win", "application/vnd.microsoft.portable-executable", "high"
        for category in ("win", "binary"):
            _add_category(categories, category)
        _add_evidence(evidence, "magic", "MZ/PE", offset=0)
        try:
            pe = _pe_details(data)
            architecture = pe["architecture"]
            imported_libraries = {item.name.lower() for item in pe["imports"]}
            if pe["clr_rva"] or b"BSJB" in data:
                subtype = "dotnet-assembly"
                _add_category(categories, "assembly")
                _add_evidence(evidence, "pe-directory", "CLR runtime header")
            elif pe["is_dll"]:
                subtype = "windows-dll"
            elif pe["subsystem"] == 1 or suffix == ".sys" or any(
                name in imported_libraries for name in {"ntoskrnl.exe", "hal.dll"}
            ):
                subtype = "windows-driver"
            elif pe["subsystem"] in {10, 11, 12, 13}:
                subtype = "uefi-image"
            else:
                subtype = "windows-executable"
        except (AnalysisError, struct.error) as error:
            subtype = "dos-or-malformed-pe"
            limitations.append(f"PE subtype inspection incomplete: {error}")
    elif data.startswith(b"\x7fELF"):
        primary, subtype, media_type, confidence = (
            "binary",
            "elf",
            "application/x-elf",
            "high",
        )
        _add_category(categories, "binary")
        _add_evidence(evidence, "magic", "ELF", offset=0)
    elif data[:4] == b"\xca\xfe\xba\xbe" and _looks_like_java_class(data, suffix):
        major = struct.unpack_from(">H", data, 6)[0]
        primary, subtype, media_type, confidence = (
            "java",
            f"java-class-v{major}",
            "application/java-vm",
            "high",
        )
        for category in ("java", "binary"):
            _add_category(categories, category)
        _add_evidence(evidence, "magic", "CAFEBABE Java class", offset=0)
    elif data[:4] in {
        b"\xfe\xed\xfa\xce",
        b"\xce\xfa\xed\xfe",
        b"\xfe\xed\xfa\xcf",
        b"\xcf\xfa\xed\xfe",
        b"\xca\xfe\xba\xbe",
        b"\xbe\xba\xfe\xca",
    }:
        primary, subtype, media_type, confidence = (
            "mac",
            "mach-o",
            "application/x-mach-binary",
            "high",
        )
        for category in ("mac", "binary"):
            _add_category(categories, category)
        _add_evidence(evidence, "magic", "Mach-O", offset=0)
    elif data.startswith(b"dex\n") and len(data) >= 8 and data[7] == 0:
        primary, subtype, media_type, confidence = (
            "android",
            "dalvik-dex",
            "application/vnd.android.dex",
            "high",
        )
        for category in ("android", "java", "binary"):
            _add_category(categories, category)
        _add_evidence(evidence, "magic", data[:8].decode("ascii", errors="replace"), offset=0)
    elif data.startswith(b"PK\x03\x04"):
        _add_category(categories, "binary")
        _add_evidence(evidence, "magic", "ZIP", offset=0)
        primary, subtype, media_type, entries = _classify_zip(
            sample, categories, evidence, limitations
        )
        confidence = "high" if subtype != "zip-archive" else "medium"
    else:
        visual_signatures = [
            (b"\x89PNG\r\n\x1a\n", "png", "image/png"),
            (b"\xff\xd8\xff", "jpeg", "image/jpeg"),
            (b"GIF87a", "gif", "image/gif"),
            (b"GIF89a", "gif", "image/gif"),
            (b"BM", "bmp", "image/bmp"),
            (b"\x00\x00\x01\x00", "ico", "image/x-icon"),
        ]
        audio_signatures = [
            (b"fLaC", "flac", "audio/flac"),
            (b"OggS", "ogg", "audio/ogg"),
            (b"ID3", "mp3", "audio/mpeg"),
            (b"MThd", "midi", "audio/midi"),
        ]
        matched = False
        for magic, name, mime in visual_signatures:
            if data.startswith(magic):
                primary, subtype, media_type, confidence = "visual", name, mime, "high"
                _add_category(categories, "visual")
                _add_evidence(evidence, "magic", name.upper(), offset=0)
                matched = True
                break
        if not matched and data.startswith(b"RIFF") and data[8:12] == b"WEBP":
            primary, subtype, media_type, confidence = "visual", "webp", "image/webp", "high"
            _add_category(categories, "visual")
            _add_evidence(evidence, "magic", "RIFF/WEBP", offset=0)
            matched = True
        if not matched and data.startswith(b"RIFF") and data[8:12] == b"WAVE":
            primary, subtype, media_type, confidence = "audio", "wav", "audio/wav", "high"
            _add_category(categories, "audio")
            _add_evidence(evidence, "magic", "RIFF/WAVE", offset=0)
            matched = True
        if not matched:
            for magic, name, mime in audio_signatures:
                if data.startswith(magic):
                    primary, subtype, media_type, confidence = "audio", name, mime, "high"
                    _add_category(categories, "audio")
                    _add_evidence(evidence, "magic", name.upper(), offset=0)
                    matched = True
                    break
        if not matched:
            text_kind = _text_kind(data, suffix)
            if text_kind:
                primary, subtype = text_kind
                media_type, confidence = "text/plain", "medium"
                _add_category(categories, primary)
                _add_evidence(evidence, "text-structure", subtype, "medium")
            else:
                _add_category(categories, "binary")
                _add_evidence(evidence, "fallback", file_format, "low")

    lowered = data.lower()
    for marker, description in DONGLE_MARKERS.items():
        offset = lowered.find(marker)
        if offset >= 0:
            _add_category(categories, "dongle")
            _add_evidence(evidence, "license-dongle-indicator", description, "medium", offset)
    if not categories:
        categories.append(primary)
    if primary not in categories:
        categories.insert(0, primary)
    if size > len(data):
        limitations.append(
            f"content indicators scanned only in the first {len(data)} of {size} bytes"
        )
    return FileTypeResult(
        path=str(sample),
        size=size,
        sha256=sha256,
        primary_category=primary,
        categories=categories,
        format=file_format,
        subtype=subtype,
        media_type=media_type,
        architecture=architecture,
        confidence=confidence,
        evidence=evidence,
        container_entries=entries,
        limitations=limitations,
    )
