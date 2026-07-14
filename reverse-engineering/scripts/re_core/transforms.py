from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from .analyzers import calculate_entropy, format_bytes


class TransformError(RuntimeError):
    """Raised when a bounded decode/transform request violates the contract."""


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _read_region(
    path: str | Path,
    *,
    offset: int,
    length: int,
    max_length: int = 1024 * 1024,
) -> tuple[Path, bytes, str, int]:
    sample = Path(path).resolve()
    if not sample.is_file():
        raise TransformError(f"sample is not a regular file: {sample}")
    size = sample.stat().st_size
    if offset < 0 or length < 1 or length > max_length or offset + length > size:
        raise TransformError(
            f"region must be inside the file and length <= {max_length} bytes"
        )
    source_digest = hashlib.sha256()
    with sample.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            source_digest.update(chunk)
        stream.seek(offset)
        region = stream.read(length)
    return sample, region, source_digest.hexdigest(), size


def _text_score(data: bytes) -> tuple[float, float, float]:
    if not data:
        return 0.0, 0.0, 0.0
    printable = sum(byte in {9, 10, 13} or 32 <= byte <= 126 for byte in data)
    letters_spaces = sum(
        byte == 32 or 65 <= byte <= 90 or 97 <= byte <= 122 for byte in data
    )
    common = sum(chr(byte).lower() in " etaoinshrdlu" for byte in data if byte < 128)
    size = len(data)
    return printable / size, letters_spaces / size, common / size


def _preview(data: bytes, limit: int = 96) -> str:
    return "".join(
        chr(byte) if byte in {9, 10, 13} or 32 <= byte <= 126 else "."
        for byte in data[:limit]
    )


def scan_single_byte_xor(
    path: str | Path,
    *,
    offset: int,
    length: int,
    limit: int = 10,
) -> dict[str, Any]:
    if not 1 <= limit <= 64:
        raise ValueError("limit must be between 1 and 64")
    sample, region, source_sha256, size = _read_region(
        path, offset=offset, length=length
    )
    candidates: list[dict[str, Any]] = []
    for key in range(256):
        decoded = bytes(byte ^ key for byte in region)
        printable, letters_spaces, common = _text_score(decoded)
        score = printable * 0.55 + letters_spaces * 0.30 + common * 0.15
        candidates.append(
            {
                "key": key,
                "key_hex": f"0x{key:02X}",
                "score": round(score, 6),
                "printable_ratio": round(printable, 6),
                "preview": _preview(decoded),
                "preview_hex": format_bytes(decoded[:32]),
                "decoded_sha256": _sha256(decoded),
            }
        )
    candidates.sort(key=lambda item: (-item["score"], item["key"]))
    return {
        "schema_version": "0.5.0",
        "source": str(sample),
        "source_size": size,
        "source_sha256": source_sha256,
        "selection": {"offset": offset, "offset_hex": f"0x{offset:X}", "length": length},
        "method": "bounded-single-byte-xor-keyspace",
        "keyspace": 256,
        "candidates": candidates[:limit],
        "limitations": [
            "Ranking favors readable text and is not cryptographic proof.",
            "This is not password, license-key, credential, or remote-service brute force.",
        ],
        "mutation_performed": False,
    }


def entropy_windows(
    path: str | Path,
    *,
    offset: int = 0,
    length: int | None = None,
    window: int = 4096,
    threshold: float = 7.2,
    limit: int = 1000,
) -> dict[str, Any]:
    sample = Path(path).resolve()
    size = sample.stat().st_size if sample.is_file() else 0
    selected_length = size - offset if length is None else length
    _, region, source_sha256, _ = _read_region(
        sample,
        offset=offset,
        length=selected_length,
        max_length=64 * 1024 * 1024,
    )
    if not 256 <= window <= 1024 * 1024:
        raise ValueError("window must be between 256 and 1048576")
    if not 0.0 <= threshold <= 8.0:
        raise ValueError("threshold must be between 0 and 8")
    matches: list[dict[str, Any]] = []
    for relative in range(0, len(region), window):
        chunk = region[relative : relative + window]
        entropy = calculate_entropy(chunk)
        if entropy >= threshold:
            absolute = offset + relative
            matches.append(
                {
                    "offset": absolute,
                    "offset_hex": f"0x{absolute:X}",
                    "length": len(chunk),
                    "entropy": round(entropy, 4),
                }
            )
            if len(matches) >= limit:
                break
    return {
        "schema_version": "0.5.0",
        "source": str(sample),
        "source_sha256": source_sha256,
        "selection": {"offset": offset, "length": selected_length},
        "window": window,
        "threshold": threshold,
        "matches": matches,
        "matches_truncated": len(matches) >= limit,
        "interpretation": "High entropy is a compression/encryption/packing candidate, not proof.",
        "mutation_performed": False,
    }


def transform_region_to_file(
    path: str | Path,
    *,
    offset: int,
    length: int,
    operation: str,
    output: str | Path,
    confirm_sha256: str,
    key: int | None = None,
) -> dict[str, Any]:
    sample, region, source_sha256, size = _read_region(
        path, offset=offset, length=length
    )
    if confirm_sha256.lower() != source_sha256:
        raise TransformError("explicit confirmation hash does not match the source")
    target = Path(output).resolve()
    if target == sample:
        raise TransformError("in-place transformation is forbidden")
    if target.exists():
        raise TransformError("output already exists")
    if operation == "xor":
        if key is None or not 0 <= key <= 255:
            raise TransformError("single-byte XOR requires key between 0 and 255")
        transformed = bytes(byte ^ key for byte in region)
    elif operation == "not":
        if key is not None:
            raise TransformError("NOT transform does not accept a key")
        transformed = bytes(byte ^ 0xFF for byte in region)
    elif operation == "identity":
        transformed = region
    else:
        raise TransformError("operation must be xor, not, or identity")
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("xb") as stream:
        stream.write(transformed)
    return {
        "schema_version": "0.5.0",
        "source": str(sample),
        "source_size": size,
        "source_sha256": source_sha256,
        "selection": {"offset": offset, "offset_hex": f"0x{offset:X}", "length": length},
        "operation": operation,
        "key": key,
        "output": str(target),
        "output_size": len(transformed),
        "output_sha256": _sha256(transformed),
        "source_modified": False,
        "note": "The output contains only the selected transformed region.",
    }
