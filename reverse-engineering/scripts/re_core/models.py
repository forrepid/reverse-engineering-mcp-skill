from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4


SCHEMA_VERSION = "0.5.0"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


@dataclass(frozen=True)
class FileIdentity:
    path: str
    name: str
    size: int
    sha256: str
    sha1: str
    md5: str

    @classmethod
    def from_values(
        cls,
        path: Path,
        size: int,
        sha256: str,
        sha1: str,
        md5: str,
    ) -> "FileIdentity":
        resolved = path.resolve()
        return cls(
            path=str(resolved),
            name=resolved.name,
            size=size,
            sha256=sha256,
            sha1=sha1,
            md5=md5,
        )


@dataclass(frozen=True)
class Section:
    name: str
    virtual_address: int
    virtual_size: int
    raw_offset: int
    raw_size: int
    characteristics: int
    permissions: str
    entropy: float


@dataclass(frozen=True)
class ImportLibrary:
    name: str
    symbols: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class ExtractedString:
    offset: int
    encoding: str
    value: str


@dataclass(frozen=True)
class Finding:
    id: str
    title: str
    source: str
    observation: str
    interpretation: str = ""
    location: dict[str, Any] = field(default_factory=dict)
    confidence: str = "medium"
    severity: str = "info"
    tags: list[str] = field(default_factory=list)
    provenance: dict[str, Any] = field(default_factory=dict)


@dataclass
class AnalysisResult:
    source: FileIdentity
    summary: dict[str, Any]
    sections: list[Section] = field(default_factory=list)
    imports: list[ImportLibrary] = field(default_factory=list)
    strings: list[ExtractedString] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    environment: dict[str, Any] = field(default_factory=dict)
    run_id: str = field(default_factory=lambda: str(uuid4()))
    started_at: str = field(default_factory=utc_now)
    schema_version: str = SCHEMA_VERSION

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
