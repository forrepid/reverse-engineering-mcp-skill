from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

# These modules are supplied by IDAPython at runtime and intentionally are not
# dependencies of the standalone companion package.
import ida_bytes  # type: ignore[import-not-found]
import ida_funcs  # type: ignore[import-not-found]
import ida_kernwin  # type: ignore[import-not-found]
import ida_loader  # type: ignore[import-not-found]
import idaapi  # type: ignore[import-not-found]
import idc  # type: ignore[import-not-found]


ACTION_NAME = "re_skill:export_selection"
MAX_SELECTION = 4096
MAX_INSTRUCTIONS = 2000


def _selection() -> tuple[int, int]:
    result = ida_kernwin.read_range_selection(None)
    if isinstance(result, tuple) and len(result) == 3:
        ok, start, end = result
        if ok and end > start:
            return int(start), int(end)
    if isinstance(result, tuple) and len(result) == 2:
        start, end = result
        if end > start:
            return int(start), int(end)
    start = int(ida_kernwin.get_screen_ea())
    function = ida_funcs.get_func(start)
    if function:
        return start, min(int(function.end_ea), start + MAX_SELECTION)
    return start, start + 64


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _export_context() -> Path:
    start, requested_end = _selection()
    end = min(requested_end, start + MAX_SELECTION)
    data = ida_bytes.get_bytes(start, max(0, end - start)) or b""
    instructions: list[dict[str, object]] = []
    cursor = start
    while cursor < end and len(instructions) < MAX_INSTRUCTIONS:
        line = idc.generate_disasm_line(cursor, 0) or ""
        size = max(1, int(ida_bytes.get_item_size(cursor)))
        instructions.append(
            {
                "address": cursor,
                "address_hex": f"0x{cursor:X}",
                "size": size,
                "text": line,
            }
        )
        cursor = int(ida_bytes.next_head(cursor, end))
        if cursor == idaapi.BADADDR:
            break
    pseudocode = ""
    pseudocode_error = ""
    try:
        import ida_hexrays  # type: ignore[import-not-found]

        if ida_hexrays.init_hexrays_plugin():
            pseudocode = str(ida_hexrays.decompile(start))[:200_000]
    except Exception as error:
        pseudocode_error = str(error)
    input_path = Path(idaapi.get_input_file_path()).resolve()
    idb_path = Path(ida_loader.get_path(ida_loader.PATH_TYPE_IDB)).resolve()
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    output_dir = Path.home() / ".reverse-engineering-skill" / "exports"
    output_dir.mkdir(parents=True, exist_ok=True)
    output = output_dir / f"ida-selection-{timestamp}.json"
    payload = {
        "schema_version": "0.5.0",
        "host": "ida",
        "input": str(input_path),
        "input_sha256": _sha256_file(input_path) if input_path.is_file() else "",
        "idb": str(idb_path),
        "selection": {
            "start": start,
            "start_hex": f"0x{start:X}",
            "end_exclusive": end,
            "end_exclusive_hex": f"0x{end:X}",
            "requested_end": requested_end,
            "truncated": requested_end > end,
            "bytes_hex": " ".join(f"{byte:02X}" for byte in data),
        },
        "function": ida_funcs.get_func_name(start) or "",
        "instructions": instructions,
        "pseudocode": pseudocode,
        "pseudocode_error": pseudocode_error,
        "untrusted_binary_content": True,
        "mutation_performed": False,
    }
    with output.open("x", encoding="utf-8") as stream:
        json.dump(payload, stream, indent=2, ensure_ascii=False)
    return output


class _ExportHandler(idaapi.action_handler_t):
    def activate(self, _context):
        try:
            output = _export_context()
            ida_kernwin.info(f"Reverse Engineering Skill context exported:\n{output}")
        except Exception as error:
            ida_kernwin.warning(f"Context export failed: {error}")
        return 1

    def update(self, _context):
        return idaapi.AST_ENABLE_ALWAYS


class ReverseEngineeringSkillPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    comment = "Bounded, read-only context export for the Reverse Engineering Skill"
    help = "Exports selection bytes, disassembly, and optional pseudocode as JSON."
    wanted_name = "Reverse Engineering Skill Context Export"
    wanted_hotkey = ""

    def init(self):
        descriptor = idaapi.action_desc_t(
            ACTION_NAME,
            "Export selection for Reverse Engineering Skill",
            _ExportHandler(),
        )
        if not ida_kernwin.register_action(descriptor):
            return idaapi.PLUGIN_SKIP
        ida_kernwin.attach_action_to_menu(
            "File/Produce file/",
            ACTION_NAME,
            ida_kernwin.SETMENU_APP,
        )
        return idaapi.PLUGIN_KEEP

    def run(self, _argument):
        _ExportHandler().activate(None)

    def term(self):
        ida_kernwin.detach_action_from_menu("File/Produce file/", ACTION_NAME)
        ida_kernwin.unregister_action(ACTION_NAME)


def PLUGIN_ENTRY():
    return ReverseEngineeringSkillPlugin()
