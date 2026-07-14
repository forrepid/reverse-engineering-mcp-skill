from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from .models import utc_now


class SourceEditError(RuntimeError):
    """Raised when a source edit fails integrity or output safety checks."""


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@dataclass
class SourceEditPlan:
    source_path: str
    source_sha256: str
    source_size: int
    mode: str
    start_line: int
    end_line: int
    expected_text: str
    replacement_text: str
    rationale: str = ""
    target_language: str = ""
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
            ensure_ascii=False,
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def seal(self) -> "SourceEditPlan":
        self.plan_digest = self.calculate_digest()
        return self

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["plan_digest"] = self.plan_digest or self.calculate_digest()
        return payload


def _read_utf8(path: Path) -> tuple[bytes, str, list[str]]:
    raw = path.read_bytes()
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        raise SourceEditError("UTF-16 source edits are not supported in v0.4")
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError as error:
        raise SourceEditError("source must be valid UTF-8") from error
    return raw, text, text.splitlines(keepends=True)


def create_source_edit_plan(
    source: str | Path,
    *,
    mode: str,
    start_line: int,
    end_line: int,
    replacement_text: str,
    rationale: str = "",
    target_language: str = "",
) -> SourceEditPlan:
    if mode not in {"replace", "insert_before", "insert_after"}:
        raise SourceEditError("mode must be replace, insert_before, or insert_after")
    path = Path(source).resolve()
    if not path.is_file():
        raise SourceEditError(f"source is not a regular file: {path}")
    if path.stat().st_size > 32 * 1024 * 1024:
        raise SourceEditError("source exceeds the 32 MiB safety limit")
    raw, _, lines = _read_utf8(path)
    if start_line < 1 or end_line < start_line or end_line > len(lines):
        raise SourceEditError("line selection is outside the source")
    if mode != "replace" and start_line != end_line:
        raise SourceEditError("insert modes require a single anchor line")
    expected = "".join(lines[start_line - 1 : end_line])
    return SourceEditPlan(
        source_path=str(path),
        source_sha256=_sha256(raw),
        source_size=len(raw),
        mode=mode,
        start_line=start_line,
        end_line=end_line,
        expected_text=expected,
        replacement_text=replacement_text,
        rationale=rationale,
        target_language=target_language,
    ).seal()


def save_source_edit_plan(plan: SourceEditPlan, output: str | Path) -> Path:
    target = Path(output).resolve()
    if target == Path(plan.source_path).resolve():
        raise SourceEditError("edit plan cannot overwrite the source")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        json.dumps(plan.to_dict(), indent=2, sort_keys=True, ensure_ascii=False),
        encoding="utf-8",
    )
    return target


def load_source_edit_plan(path: str | Path) -> SourceEditPlan:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    plan = SourceEditPlan(**payload)
    if not plan.plan_digest or plan.plan_digest != plan.calculate_digest():
        raise SourceEditError("source edit plan digest is missing or invalid")
    return plan


def apply_source_edit_plan(
    source: str | Path,
    plan: SourceEditPlan,
    *,
    confirm_sha256: str,
    output: str | Path,
) -> dict[str, Any]:
    source_path = Path(source).resolve()
    output_path = Path(output).resolve()
    if output_path == source_path:
        raise SourceEditError("in-place source editing is forbidden")
    if output_path.exists():
        raise SourceEditError("output already exists")
    raw, _, lines = _read_utf8(source_path)
    actual_sha256 = _sha256(raw)
    if confirm_sha256.lower() != actual_sha256:
        raise SourceEditError("explicit confirmation hash does not match source")
    if plan.source_sha256 != actual_sha256 or plan.source_size != len(raw):
        raise SourceEditError("source edit plan was created for a different file")
    if plan.plan_digest != plan.calculate_digest():
        raise SourceEditError("source edit plan digest validation failed")
    if plan.end_line > len(lines):
        raise SourceEditError("source line count changed")
    selected = "".join(lines[plan.start_line - 1 : plan.end_line])
    if selected != plan.expected_text:
        raise SourceEditError("selected source lines changed after planning")
    if plan.mode == "replace":
        replacement = plan.replacement_text
    elif plan.mode == "insert_before":
        replacement = plan.replacement_text + selected
    else:
        replacement = selected + plan.replacement_text
    updated = (
        "".join(lines[: plan.start_line - 1])
        + replacement
        + "".join(lines[plan.end_line :])
    ).encode("utf-8")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("xb") as stream:
        stream.write(updated)
    return {
        "schema_version": "0.5.0",
        "source": str(source_path),
        "source_sha256": actual_sha256,
        "output": str(output_path),
        "output_sha256": _sha256(updated),
        "mode": plan.mode,
        "lines": {"start": plan.start_line, "end": plan.end_line},
        "plan_digest": plan.plan_digest,
        "source_modified": False,
        "decompiled_source_warning": (
            "Editing exported pseudocode does not patch the original binary or IDB."
        ),
    }
