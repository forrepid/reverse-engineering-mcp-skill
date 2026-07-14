from __future__ import annotations

import hashlib
import json
import re
import shutil
from pathlib import Path
from typing import Any

from .models import utc_now


class SnapshotError(RuntimeError):
    """Raised when snapshot integrity cannot be guaranteed."""


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _safe_label(label: str) -> str:
    normalized = re.sub(r"[^a-zA-Z0-9._-]+", "-", label.strip()).strip("-")
    return normalized[:64] or "snapshot"


def create_idb_snapshot(
    source: str | Path,
    output_dir: str | Path,
    *,
    confirm_saved: bool,
    label: str = "before-change",
) -> dict[str, Any]:
    if not confirm_saved:
        raise SnapshotError("confirm_saved is required before copying an IDB")
    source_path = Path(source).resolve()
    if not source_path.is_file():
        raise SnapshotError(f"IDB source does not exist: {source_path}")
    before_hash = _sha256_file(source_path)
    timestamp = utc_now().replace(":", "").replace("-", "")
    snapshot_dir = (
        Path(output_dir).resolve()
        / f"{timestamp}-{_safe_label(label)}-{before_hash[:12]}"
    )
    snapshot_dir.mkdir(parents=True, exist_ok=False)
    target = snapshot_dir / source_path.name
    shutil.copy2(source_path, target)
    after_hash = _sha256_file(source_path)
    copied_hash = _sha256_file(target)
    if before_hash != after_hash or before_hash != copied_hash:
        raise SnapshotError("source changed during snapshot or copied hash mismatched")
    manifest = {
        "schema_version": "0.5.0",
        "created_at": utc_now(),
        "label": label,
        "source": str(source_path),
        "source_size": source_path.stat().st_size,
        "source_sha256": before_hash,
        "snapshot": str(target),
        "snapshot_sha256": copied_hash,
        "immutable_intent": True,
        "restore_automatic": False,
    }
    manifest_path = snapshot_dir / "manifest.json"
    with manifest_path.open("x", encoding="utf-8") as stream:
        json.dump(manifest, stream, indent=2, sort_keys=True, ensure_ascii=False)
    return {**manifest, "manifest": str(manifest_path)}


def build_restore_plan(
    manifest_path: str | Path,
    target: str | Path,
) -> dict[str, Any]:
    manifest_file = Path(manifest_path).resolve()
    manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
    snapshot = Path(manifest["snapshot"]).resolve()
    if not snapshot.is_file():
        raise SnapshotError("snapshot file is missing")
    snapshot_hash = _sha256_file(snapshot)
    if snapshot_hash != manifest.get("snapshot_sha256"):
        raise SnapshotError("snapshot hash does not match its manifest")
    target_path = Path(target).resolve()
    return {
        "schema_version": "0.5.0",
        "status": "planned-not-restored",
        "manifest": str(manifest_file),
        "snapshot": str(snapshot),
        "snapshot_sha256": snapshot_hash,
        "target": str(target_path),
        "target_exists": target_path.exists(),
        "target_sha256": _sha256_file(target_path) if target_path.is_file() else "",
        "requires_ida_closed": True,
        "requires_explicit_confirmation": True,
        "automatic_execution": False,
    }
