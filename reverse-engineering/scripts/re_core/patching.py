from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from .analyzers import format_bytes
from .models import utc_now


class PatchError(RuntimeError):
    """Raised when patch integrity or authorization preconditions fail."""


def _parse_exact_bytes(value: str) -> bytes:
    tokens = value.strip().split()
    if not tokens:
        raise PatchError("byte sequence is empty")
    try:
        result = bytes(int(token, 16) for token in tokens)
    except ValueError as error:
        raise PatchError("patch bytes must be two-digit hexadecimal tokens") from error
    if any(len(token) != 2 for token in tokens):
        raise PatchError("patch bytes must be two-digit hexadecimal tokens")
    return result


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@dataclass(frozen=True)
class PatchOperation:
    offset: int
    expected: str
    replacement: str
    rationale: str = ""


@dataclass
class PatchPlan:
    source_path: str
    source_sha256: str
    source_size: int
    operations: list[PatchOperation]
    created_at: str = field(default_factory=utc_now)
    schema_version: str = "0.5.0"
    plan_digest: str = ""

    def canonical_payload(self) -> dict[str, Any]:
        payload = asdict(self)
        payload.pop("plan_digest", None)
        return payload

    def calculate_digest(self) -> str:
        encoded = json.dumps(
            self.canonical_payload(),
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def seal(self) -> "PatchPlan":
        self.plan_digest = self.calculate_digest()
        return self

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["plan_digest"] = self.plan_digest or self.calculate_digest()
        return payload


def create_patch_plan(
    source: str | Path,
    *,
    offset: int,
    expected: str,
    replacement: str,
    rationale: str = "",
) -> PatchPlan:
    path = Path(source).resolve()
    data = path.read_bytes()
    expected_bytes = _parse_exact_bytes(expected)
    replacement_bytes = _parse_exact_bytes(replacement)
    if len(expected_bytes) != len(replacement_bytes):
        raise PatchError("v0 patch operations must preserve byte length")
    if offset < 0 or offset + len(expected_bytes) > len(data):
        raise PatchError("patch range is outside the source file")
    actual = data[offset : offset + len(expected_bytes)]
    if actual != expected_bytes:
        raise PatchError(
            f"expected {format_bytes(expected_bytes)} at 0x{offset:X}, "
            f"found {format_bytes(actual)}"
        )
    return PatchPlan(
        source_path=str(path),
        source_sha256=_sha256(data),
        source_size=len(data),
        operations=[
            PatchOperation(
                offset=offset,
                expected=format_bytes(expected_bytes),
                replacement=format_bytes(replacement_bytes),
                rationale=rationale,
            )
        ],
    ).seal()


def save_patch_plan(plan: PatchPlan, output: str | Path) -> Path:
    target = Path(output).resolve()
    if target == Path(plan.source_path).resolve():
        raise PatchError("patch-plan output cannot overwrite the source")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        json.dumps(plan.to_dict(), indent=2, sort_keys=True),
        encoding="utf-8",
    )
    return target.resolve()


def load_patch_plan(path: str | Path) -> PatchPlan:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    operations = [PatchOperation(**item) for item in payload.pop("operations")]
    plan = PatchPlan(operations=operations, **payload)
    if not plan.plan_digest or plan.plan_digest != plan.calculate_digest():
        raise PatchError("patch plan digest is missing or invalid")
    return plan


def apply_patch_plan(
    source: str | Path,
    plan: PatchPlan,
    *,
    confirm_sha256: str,
    output: str | Path,
) -> dict[str, Any]:
    source_path = Path(source).resolve()
    output_path = Path(output).resolve()
    if source_path == output_path:
        raise PatchError("in-place patching is forbidden")
    if output_path.exists():
        raise PatchError("output already exists; choose a new path")
    data = bytearray(source_path.read_bytes())
    actual_sha256 = _sha256(bytes(data))
    if confirm_sha256.lower() != actual_sha256:
        raise PatchError("explicit confirmation hash does not match the source")
    if plan.source_sha256 != actual_sha256 or plan.source_size != len(data):
        raise PatchError("patch plan was created for a different source")
    if plan.plan_digest != plan.calculate_digest():
        raise PatchError("patch plan digest validation failed")

    occupied: set[int] = set()
    changes: list[dict[str, Any]] = []
    for operation in sorted(plan.operations, key=lambda item: item.offset):
        expected = _parse_exact_bytes(operation.expected)
        replacement = _parse_exact_bytes(operation.replacement)
        if len(expected) != len(replacement):
            raise PatchError("v0 patch operations must preserve byte length")
        span = set(range(operation.offset, operation.offset + len(expected)))
        if occupied & span:
            raise PatchError("patch operations overlap")
        occupied |= span
        actual = bytes(data[operation.offset : operation.offset + len(expected)])
        if actual != expected:
            raise PatchError(
                f"source changed at 0x{operation.offset:X}; expected "
                f"{format_bytes(expected)}, found {format_bytes(actual)}"
            )
        data[operation.offset : operation.offset + len(expected)] = replacement
        changes.append(
            {
                "offset": operation.offset,
                "offset_hex": f"0x{operation.offset:X}",
                "before": format_bytes(expected),
                "after": format_bytes(replacement),
                "rationale": operation.rationale,
            }
        )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("xb") as stream:
        stream.write(data)
    return {
        "source": str(source_path),
        "source_sha256": actual_sha256,
        "output": str(output_path),
        "output_sha256": _sha256(bytes(data)),
        "plan_digest": plan.plan_digest,
        "changes": changes,
    }
