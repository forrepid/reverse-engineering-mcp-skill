from __future__ import annotations

from dataclasses import asdict
from pathlib import Path
from typing import Any

from .analyzers import StaticAnalyzer
from .models import utc_now


def build_binary_inventory(
    path: str | Path,
    *,
    max_file_bytes: int = 512 * 1024 * 1024,
    max_scan_bytes: int = 64 * 1024 * 1024,
) -> dict[str, Any]:
    """Build dependency evidence without claiming full SBOM compliance."""
    result = StaticAnalyzer(
        max_file_size=max_file_bytes,
        max_scan_bytes=max_scan_bytes,
        max_strings=256,
    ).analyze(path)
    dependencies = []
    for library in result.imports:
        dependencies.append(
            {
                "type": "import-library",
                "name": library.name,
                "version": "unknown",
                "supplier": "unknown",
                "license": "unknown",
                "imported_symbols": library.symbols,
                "evidence": {
                    "source": "static-import-table",
                    "symbol_count": len(library.symbols),
                },
            }
        )
    return {
        "schema_version": "0.5.0",
        "created_at": utc_now(),
        "inventory_type": "binary-dependency-evidence",
        "compliance": {
            "cyclonedx": False,
            "spdx": False,
            "note": "This is analysis evidence, not a complete software bill of materials.",
        },
        "subject": asdict(result.source),
        "format": result.summary.get("format", "unknown"),
        "architecture": result.summary.get("architecture", "unknown"),
        "entry_point_va": result.summary.get("entry_point_va"),
        "dependencies": dependencies,
        "sections": [asdict(section) for section in result.sections],
        "findings": [asdict(finding) for finding in result.findings],
        "limitations": [
            *result.limitations,
            "Delay-load imports, runtime-loaded modules, bundled runtimes, and transitive dependencies may be absent.",
            "Dependency versions, suppliers, licenses, and known vulnerabilities require independent provenance.",
        ],
        "mutation_performed": False,
    }
