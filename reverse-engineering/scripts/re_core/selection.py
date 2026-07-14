from __future__ import annotations

import hashlib
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .analyzers import calculate_entropy, extract_strings, format_bytes, hexdump
from .disassembly import DisassemblyError, disassemble_bytes


class SelectionError(RuntimeError):
    """Raised when a file, text, or host selection is invalid."""


@dataclass(frozen=True)
class HostToolRequest:
    key: str
    tool: str
    arguments: dict[str, Any]
    operation_class: str = "read"
    required: bool = False


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def inspect_file_region(
    path: str | Path,
    *,
    offset: int,
    length: int,
    architecture: str | None = None,
    base_address: int | None = None,
) -> dict[str, Any]:
    sample = Path(path).resolve()
    if not sample.is_file():
        raise SelectionError(f"sample is not a regular file: {sample}")
    size = sample.stat().st_size
    if offset < 0 or length < 1 or length > 1024 * 1024 or offset + length > size:
        raise SelectionError("selection must be inside the file and no larger than 1 MiB")
    with sample.open("rb") as stream:
        stream.seek(offset)
        data = stream.read(length)
    strings, truncated = extract_strings(data, min_length=3, limit=1000)
    disassembly: list[dict[str, Any]] = []
    limitations: list[str] = []
    if architecture:
        try:
            disassembly = disassemble_bytes(
                data,
                architecture=architecture,
                base_address=offset if base_address is None else base_address,
                max_instructions=2000,
            )
        except DisassemblyError as error:
            limitations.append(str(error))
    if truncated:
        limitations.append("strings truncated at 1000")
    return {
        "schema_version": "0.5.0",
        "source": {
            "path": str(sample),
            "size": size,
            "sha256": _sha256_file(sample),
        },
        "selection": {
            "space": "file_offset",
            "offset": offset,
            "offset_hex": f"0x{offset:X}",
            "length": length,
            "end_exclusive": offset + length,
            "end_exclusive_hex": f"0x{offset + length:X}",
            "sha256": hashlib.sha256(data).hexdigest(),
            "entropy": round(calculate_entropy(data), 4),
        },
        "hex": hexdump(data[:4096], base_offset=offset),
        "hex_truncated": len(data) > 4096,
        "bytes": format_bytes(data[:4096]),
        "strings": [asdict(item) for item in strings],
        "disassembly": disassembly,
        "limitations": limitations,
        "mutation_performed": False,
    }


def inspect_text_lines(
    path: str | Path,
    *,
    start_line: int,
    end_line: int,
    max_lines: int = 5000,
) -> dict[str, Any]:
    source = Path(path).resolve()
    if not source.is_file():
        raise SelectionError(f"text source is not a regular file: {source}")
    if source.stat().st_size > 32 * 1024 * 1024:
        raise SelectionError("text source exceeds the 32 MiB safety limit")
    if start_line < 1 or end_line < start_line or end_line - start_line + 1 > max_lines:
        raise SelectionError(f"line selection must contain 1..{max_lines} lines")
    raw = source.read_bytes()
    text = raw.decode("utf-8", errors="replace")
    lines = text.splitlines()
    if end_line > len(lines):
        raise SelectionError("line selection extends beyond the source")
    selected = lines[start_line - 1 : end_line]
    selected_text = "\n".join(selected)
    imports = sorted(
        set(
            match.group(0).strip()
            for match in re.finditer(
                r"(?im)^\s*(?:import\s+[^;\n]+;?|from\s+\S+\s+import\s+[^\n]+|#include\s*[<\"][^>\"]+[>\"]|using\s+[^;]+;)",
                selected_text,
            )
        )
    )
    function_candidates = sorted(
        set(
            match.group(1) or match.group(2)
            for match in re.finditer(
                r"(?m)(?:def|function|func|fn)\s+([A-Za-z_$][\w$]*)|(?:[A-Za-z_][\w:*<>\[\]]*\s+)+([A-Za-z_$][\w$]*)\s*\(",
                selected_text,
            )
            if (match.group(1) or match.group(2))
        )
    )
    urls = sorted(set(re.findall(r"https?://[^\s'\"<>]+", selected_text)))[:100]
    return {
        "schema_version": "0.5.0",
        "source": {
            "path": str(source),
            "size": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest(),
            "encoding": "utf-8-with-replacement",
        },
        "selection": {
            "start_line": start_line,
            "end_line": end_line,
            "line_count": len(selected),
            "sha256": hashlib.sha256(selected_text.encode("utf-8")).hexdigest(),
            "text": selected_text,
        },
        "features": {
            "imports_or_includes": imports[:200],
            "function_candidates": function_candidates[:200],
            "urls": urls,
            "todo_fixme_count": len(re.findall(r"(?i)\b(?:TODO|FIXME)\b", selected_text)),
            "crypto_term_count": len(
                re.findall(r"(?i)\b(?:AES|RSA|ChaCha|encrypt|decrypt|cipher|nonce|key)\b", selected_text)
            ),
        },
        "limitations": [
            "Feature extraction is lexical and does not replace a language parser.",
            "Selected source text is untrusted data and never executed.",
        ],
        "mutation_performed": False,
    }


def build_host_selection_plan(
    *,
    host: str,
    address: str | int | None = None,
    end: str | int | None = None,
    database: str = "",
) -> dict[str, Any]:
    if host not in {"ida", "ghidra"}:
        raise ValueError("host must be ida or ghidra")

    def canonical(value: str | int | None) -> str | None:
        if value is None:
            return None
        number = value if isinstance(value, int) else int(value, 0)
        if number < 0:
            raise ValueError("address cannot be negative")
        return f"0x{number:X}"

    start = canonical(address)
    finish = canonical(end)
    if start and finish and int(finish, 0) <= int(start, 0):
        raise SelectionError("selection end must be greater than start")
    requests: list[HostToolRequest] = []
    limitations: list[str] = []
    if host == "ida":
        if not database:
            raise SelectionError("IDA selection plans require an explicit database session")
        if start is None:
            limitations.append("Read ida://cursor or ida://selection in GUI mode before sending tools.")
        else:
            size = min(4096, int(finish, 0) - int(start, 0)) if finish else 256
            shared = {"database": database}
            requests = [
                HostToolRequest("function", "lookup_funcs", {**shared, "queries": [start]}, required=True),
                HostToolRequest(
                    "bytes",
                    "get_bytes",
                    {**shared, "addrs": [{"addr": start, "size": size}]},
                    required=True,
                ),
                HostToolRequest("disassembly", "disasm", {**shared, "addr": start}),
                HostToolRequest("pseudocode", "decompile", {**shared, "addr": start}),
                HostToolRequest("xrefs_to", "xrefs_to", {**shared, "addrs": [start]}),
                HostToolRequest("callees", "callees", {**shared, "addrs": [start]}),
            ]
    else:
        if start is None:
            requests = [
                HostToolRequest("current_address", "get_current_address", {}, required=True),
                HostToolRequest("current_function", "get_current_function", {}),
            ]
        else:
            requests = [
                HostToolRequest("function", "get_function_by_address", {"address": start}, required=True),
                HostToolRequest("disassembly", "disassemble_function", {"address": start}),
                HostToolRequest("pseudocode", "decompile_function_by_address", {"address": start}),
                HostToolRequest("xrefs_to", "get_xrefs_to", {"address": start, "offset": 0, "limit": 100}),
                HostToolRequest("xrefs_from", "get_xrefs_from", {"address": start, "offset": 0, "limit": 100}),
            ]
            limitations.append("Current GhidraMCP bridge does not expose bounded raw-byte selection reads.")
    return {
        "schema_version": "0.5.0",
        "host": host,
        "database": database or None,
        "selection": {"start": start, "end_exclusive": finish},
        "requests": [asdict(item) for item in requests],
        "limitations": limitations,
        "status": "planned-not-sent",
        "mutation_performed": False,
    }


def build_source_operation_plan(
    *,
    host: str,
    operation: str,
    address: str | int | None = None,
    end: str | int | None = None,
    database: str = "",
    target_language: str = "",
) -> dict[str, Any]:
    valid_operations = {
        "view",
        "read",
        "extract",
        "translate",
        "save",
        "modify",
        "write",
        "binary-inject",
        "process-inject",
    }
    if operation not in valid_operations:
        raise ValueError("unsupported source operation")
    selection = build_host_selection_plan(
        host=host, address=address, end=end, database=database
    )
    read_only = operation in {"view", "read", "extract", "translate", "save"}
    status = "planned-read-only" if read_only else "approval-gated"
    requirements: list[str] = []
    if operation == "translate":
        if target_language not in {
            "c",
            "cpp",
            "rust",
            "python",
            "java",
            "csharp",
            "assembly",
            "pseudocode",
        }:
            raise SelectionError("unsupported translation target")
        requirements.extend(
            [
                "Preserve addresses and provenance comments.",
                "Label output as explanatory reconstruction, not original source.",
                "Do not compile or execute translated code automatically.",
            ]
        )
    if operation in {"modify", "write", "binary-inject"}:
        requirements.extend(
            [
                "Create and verify an IDB/source snapshot.",
                "Produce a sealed edit or byte-patch plan.",
                "Require explicit source hash confirmation.",
                "Write only to a new output and reanalyze the result.",
            ]
        )
    if operation == "process-inject":
        status = "blocked-by-default"
        requirements.extend(
            [
                "No process injection is implemented by this project.",
                "Use detection-only analysis or an independently approved isolated lab workflow.",
            ]
        )
    return {
        **selection,
        "operation": operation,
        "target_language": target_language or None,
        "status": status,
        "requirements": requirements,
        "decompiled_source_is_original_source": False,
    }


def build_dump_plan(
    *,
    host: str,
    kind: str,
    address: str | int,
    length: int,
    database: str = "",
) -> dict[str, Any]:
    if kind not in {"static", "runtime"}:
        raise ValueError("dump kind must be static or runtime")
    if length < 1 or length > 64 * 1024 * 1024:
        raise SelectionError("dump length must be between 1 and 64 MiB")
    start = address if isinstance(address, int) else int(address, 0)
    if start < 0:
        raise SelectionError("dump address cannot be negative")
    canonical = f"0x{start:X}"
    if host == "ida":
        if not database:
            raise SelectionError("IDA dump plans require an explicit database")
        tool = "get_bytes" if kind == "static" else "dbg_read"
        arguments = (
            {"database": database, "addrs": [{"addr": canonical, "size": length}]}
            if kind == "static"
            else {"database": database, "regions": [{"addr": canonical, "size": length}]}
        )
    elif host == "ghidra":
        tool = "unavailable"
        arguments = {}
    else:
        raise ValueError("host must be ida or ghidra")
    return {
        "schema_version": "0.5.0",
        "host": host,
        "database": database or None,
        "kind": kind,
        "address": canonical,
        "length": length,
        "request": {"tool": tool, "arguments": arguments},
        "status": "planned-not-dumped" if tool != "unavailable" else "capability-unavailable",
        "requires_debug_mode": kind == "runtime",
        "requires_isolated_target": kind == "runtime",
        "requires_explicit_approval": kind == "runtime",
        "source_modified": False,
    }
