from __future__ import annotations

from pathlib import Path
from typing import Any

from .analyzers import StaticAnalyzer, format_bytes


def _byte_diff_ranges(left: bytes, right: bytes, limit: int = 1000) -> dict[str, Any]:
    ranges: list[dict[str, Any]] = []
    maximum = max(len(left), len(right))
    index = 0
    total_changed = 0
    while index < maximum:
        left_byte = left[index] if index < len(left) else None
        right_byte = right[index] if index < len(right) else None
        if left_byte == right_byte:
            index += 1
            continue
        start = index
        while index < maximum:
            left_byte = left[index] if index < len(left) else None
            right_byte = right[index] if index < len(right) else None
            if left_byte == right_byte:
                break
            index += 1
        end = index
        total_changed += end - start
        if len(ranges) < limit:
            ranges.append(
                {
                    "offset": start,
                    "offset_hex": f"0x{start:X}",
                    "length": end - start,
                    "left": format_bytes(left[start:end]),
                    "right": format_bytes(right[start:end]),
                }
            )
    return {
        "total_changed_bytes": total_changed,
        "ranges": ranges,
        "ranges_truncated": len(ranges) >= limit and total_changed > sum(
            item["length"] for item in ranges
        ),
    }


def compare_files(
    left_path: str | Path,
    right_path: str | Path,
    *,
    analyzer: StaticAnalyzer | None = None,
    diff_range_limit: int = 1000,
) -> dict[str, Any]:
    engine = analyzer or StaticAnalyzer()
    left = engine.analyze(left_path)
    right = engine.analyze(right_path)
    left_data = Path(left_path).read_bytes()
    right_data = Path(right_path).read_bytes()

    summary_keys = sorted(set(left.summary) | set(right.summary))
    summary_changes = {
        key: {"left": left.summary.get(key), "right": right.summary.get(key)}
        for key in summary_keys
        if left.summary.get(key) != right.summary.get(key)
        and key not in {"header_hex"}
    }

    left_sections = {item.name: item for item in left.sections}
    right_sections = {item.name: item for item in right.sections}
    section_changes: dict[str, Any] = {}
    for name in sorted(set(left_sections) | set(right_sections)):
        before = left_sections.get(name)
        after = right_sections.get(name)
        if before != after:
            section_changes[name] = {
                "left": vars(before) if before else None,
                "right": vars(after) if after else None,
            }

    left_imports = {
        library.name.lower(): sorted(library.symbols) for library in left.imports
    }
    right_imports = {
        library.name.lower(): sorted(library.symbols) for library in right.imports
    }
    imports_added = sorted(set(right_imports) - set(left_imports))
    imports_removed = sorted(set(left_imports) - set(right_imports))
    import_symbol_changes = {
        name: {
            "added": sorted(set(right_imports.get(name, [])) - set(left_imports.get(name, []))),
            "removed": sorted(set(left_imports.get(name, [])) - set(right_imports.get(name, []))),
        }
        for name in sorted(set(left_imports) & set(right_imports))
        if left_imports[name] != right_imports[name]
    }

    left_strings = {item.value for item in left.strings}
    right_strings = {item.value for item in right.strings}
    return {
        "schema_version": "0.5.0",
        "left": {
            "path": left.source.path,
            "size": left.source.size,
            "sha256": left.source.sha256,
        },
        "right": {
            "path": right.source.path,
            "size": right.source.size,
            "sha256": right.source.sha256,
        },
        "identical": left.source.sha256 == right.source.sha256,
        "summary_changes": summary_changes,
        "section_changes": section_changes,
        "imports": {
            "libraries_added": imports_added,
            "libraries_removed": imports_removed,
            "symbol_changes": import_symbol_changes,
        },
        "strings": {
            "added": sorted(right_strings - left_strings)[:1000],
            "removed": sorted(left_strings - right_strings)[:1000],
            "truncated": (
                len(right_strings - left_strings) > 1000
                or len(left_strings - right_strings) > 1000
            ),
        },
        "byte_diff": _byte_diff_ranges(
            left_data, right_data, limit=diff_range_limit
        ),
    }
