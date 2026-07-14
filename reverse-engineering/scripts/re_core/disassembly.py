from __future__ import annotations

import importlib
from pathlib import Path
from typing import Any


class DisassemblyError(RuntimeError):
    """Raised when the optional disassembly provider is unavailable or invalid."""


def _engine(architecture: str) -> Any:
    try:
        capstone: Any = importlib.import_module("capstone")
    except ImportError as error:
        raise DisassemblyError(
            "Capstone Python bindings are not installed; use a live IDA/Ghidra "
            "session or install a reviewed, pinned capstone build."
        ) from error

    mapping = {
        "x86": (capstone.CS_ARCH_X86, capstone.CS_MODE_32),
        "x64": (capstone.CS_ARCH_X86, capstone.CS_MODE_64),
        "arm": (
            capstone.CS_ARCH_ARM,
            capstone.CS_MODE_ARM | capstone.CS_MODE_LITTLE_ENDIAN,
        ),
        "thumb": (
            capstone.CS_ARCH_ARM,
            capstone.CS_MODE_THUMB | capstone.CS_MODE_LITTLE_ENDIAN,
        ),
        "arm64": (capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN),
        "mips32le": (
            capstone.CS_ARCH_MIPS,
            capstone.CS_MODE_MIPS32 | capstone.CS_MODE_LITTLE_ENDIAN,
        ),
        "mips64le": (
            capstone.CS_ARCH_MIPS,
            capstone.CS_MODE_MIPS64 | capstone.CS_MODE_LITTLE_ENDIAN,
        ),
    }
    if architecture not in mapping:
        raise DisassemblyError(
            "architecture must be one of: " + ", ".join(sorted(mapping))
        )
    engine = capstone.Cs(*mapping[architecture])
    engine.detail = False
    engine.skipdata = True
    return engine


def disassemble_bytes(
    data: bytes,
    *,
    architecture: str,
    base_address: int = 0,
    max_instructions: int = 1000,
) -> list[dict[str, Any]]:
    if not 1 <= max_instructions <= 100_000:
        raise ValueError("max_instructions must be between 1 and 100000")
    instructions: list[dict[str, Any]] = []
    for instruction in _engine(architecture).disasm(
        data, base_address, count=max_instructions
    ):
        instructions.append(
            {
                "address": instruction.address,
                "address_hex": f"0x{instruction.address:X}",
                "size": instruction.size,
                "bytes": " ".join(f"{byte:02X}" for byte in instruction.bytes),
                "mnemonic": instruction.mnemonic,
                "operands": instruction.op_str,
            }
        )
    return instructions


def disassemble_file(
    path: str | Path,
    *,
    architecture: str,
    offset: int,
    length: int,
    base_address: int | None = None,
    max_instructions: int = 1000,
) -> dict[str, Any]:
    if offset < 0:
        raise ValueError("offset cannot be negative")
    if not 1 <= length <= 1024 * 1024:
        raise ValueError("length must be between 1 and 1048576")
    sample = Path(path).resolve()
    with sample.open("rb") as stream:
        stream.seek(offset)
        data = stream.read(length)
    address = offset if base_address is None else base_address
    return {
        "provider": "capstone",
        "sample": str(sample),
        "architecture": architecture,
        "file_offset": offset,
        "file_offset_hex": f"0x{offset:X}",
        "base_address": address,
        "instructions": disassemble_bytes(
            data,
            architecture=architecture,
            base_address=address,
            max_instructions=max_instructions,
        ),
        "note": "Linear sweep only; code/data boundaries require host analysis.",
    }
