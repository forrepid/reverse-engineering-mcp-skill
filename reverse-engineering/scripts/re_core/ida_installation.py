from __future__ import annotations

import ctypes
import hashlib
import os
import re
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


class IdaInstallationError(RuntimeError):
    """Raised when an IDA installation cannot be profiled safely."""


@dataclass(frozen=True)
class IdaComponent:
    name: str
    path: str
    exists: bool
    size: int = 0
    sha256: str = ""


@dataclass
class IdaInstallationReport:
    root: str
    executable: str
    version: str
    ready: bool
    components: list[IdaComponent]
    idalib_wheels: list[str] = field(default_factory=list)
    mcp_plugins: list[str] = field(default_factory=list)
    suspicious_executables: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    schema_version: str = "0.5.0"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


class _VSFixedFileInfo(ctypes.Structure):
    _fields_ = [
        ("dwSignature", ctypes.c_uint32),
        ("dwStrucVersion", ctypes.c_uint32),
        ("dwFileVersionMS", ctypes.c_uint32),
        ("dwFileVersionLS", ctypes.c_uint32),
        ("dwProductVersionMS", ctypes.c_uint32),
        ("dwProductVersionLS", ctypes.c_uint32),
        ("dwFileFlagsMask", ctypes.c_uint32),
        ("dwFileFlags", ctypes.c_uint32),
        ("dwFileOS", ctypes.c_uint32),
        ("dwFileType", ctypes.c_uint32),
        ("dwFileSubtype", ctypes.c_uint32),
        ("dwFileDateMS", ctypes.c_uint32),
        ("dwFileDateLS", ctypes.c_uint32),
    ]


def _windows_file_version(path: Path) -> str:
    if os.name != "nt":
        return ""
    try:
        version = ctypes.WinDLL("version", use_last_error=True)
        size = version.GetFileVersionInfoSizeW(str(path), None)
        if not size:
            return ""
        buffer = ctypes.create_string_buffer(size)
        if not version.GetFileVersionInfoW(str(path), 0, size, buffer):
            return ""
        pointer = ctypes.c_void_p()
        length = ctypes.c_uint()
        if not version.VerQueryValueW(
            buffer, "\\", ctypes.byref(pointer), ctypes.byref(length)
        ):
            return ""
        info = ctypes.cast(pointer, ctypes.POINTER(_VSFixedFileInfo)).contents
        if info.dwSignature != 0xFEEF04BD:
            return ""
        return ".".join(
            str(value)
            for value in (
                info.dwProductVersionMS >> 16,
                info.dwProductVersionMS & 0xFFFF,
                info.dwProductVersionLS >> 16,
                info.dwProductVersionLS & 0xFFFF,
            )
        )
    except (AttributeError, OSError, ValueError):
        return ""


def _component(name: str, path: Path, include_hashes: bool) -> IdaComponent:
    exists = path.is_file()
    return IdaComponent(
        name=name,
        path=str(path),
        exists=exists,
        size=path.stat().st_size if exists else 0,
        sha256=_sha256_file(path) if exists and include_hashes else "",
    )


def _standard_site_packages(python_path: Path) -> list[Path]:
    root = python_path.parent if os.name == "nt" else python_path.parent.parent
    candidates = [root / "Lib" / "site-packages"]
    candidates.extend((root / "lib").glob("python*/site-packages"))
    return [item for item in candidates if item.is_dir()]


def _package_detected(python_path: Path, package: str) -> bool:
    normalized = package.replace("-", "_").lower()
    for site_packages in _standard_site_packages(python_path):
        if (site_packages / normalized).exists():
            return True
        if any(site_packages.glob(f"{normalized}-*.dist-info")):
            return True
    return False


def _python_version(python_path: Path) -> str:
    patchlevel = python_path.parent / "Include" / "patchlevel.h"
    if patchlevel.is_file():
        match = re.search(
            r'^#define\s+PY_VERSION\s+"([^"]+)"',
            patchlevel.read_text(encoding="utf-8", errors="replace"),
            re.MULTILINE,
        )
        if match:
            return match.group(1)
    if python_path == Path(sys.executable).resolve():
        return sys.version.split()[0]
    return "unknown"


def detect_ida_installation(
    path: str | Path,
    *,
    include_hashes: bool = True,
) -> IdaInstallationReport:
    supplied = Path(path).expanduser().resolve()
    root = supplied if supplied.is_dir() else supplied.parent
    executable = supplied if supplied.is_file() else root / "ida.exe"
    if executable.name.lower() not in {"ida.exe", "ida64.exe"}:
        raise IdaInstallationError("expected ida.exe/ida64.exe or its installation root")
    if not executable.is_file():
        raise IdaInstallationError(f"IDA executable does not exist: {executable}")

    component_paths = {
        "ida_gui": executable,
        "ida_headless": root / "idat.exe",
        "idalib": root / "idalib.dll",
        "idalib32": root / "idalib32.dll",
        "idapython": root / "plugins" / "idapython3.dll",
        "idapyswitch": root / "idapyswitch.exe",
        "idalib_activation": root / "idalib" / "python" / "py-activate-idalib.py",
    }
    components = [
        _component(name, component_path, include_hashes)
        for name, component_path in component_paths.items()
    ]
    wheels = sorted(
        str(item.resolve())
        for item in (root / "idalib" / "python").glob("idapro-*.whl")
        if item.is_file()
    )
    mcp_plugins = sorted(
        str(item.resolve())
        for item in (root / "plugins").rglob("*")
        if item.is_file() and "mcp" in item.name.lower()
    )
    suspicious_tokens = ("keygen", "crack", "license-generator")
    suspicious = sorted(
        str(item.resolve())
        for item in root.iterdir()
        if item.is_file()
        and item.suffix.lower() in {".exe", ".dll", ".bat", ".cmd", ".ps1"}
        and any(token in item.name.lower() for token in suspicious_tokens)
    )
    required = {"ida_gui", "idalib", "idapython", "idalib_activation"}
    ready = all(
        component.exists for component in components if component.name in required
    ) and bool(wheels)
    warnings: list[str] = []
    if not mcp_plugins:
        warnings.append("No MCP-named plugin was found in the IDA plugin directory.")
    if suspicious:
        warnings.append(
            "Non-vendor-style executable names were found; launch allowlists must exclude them."
        )
    return IdaInstallationReport(
        root=str(root),
        executable=str(executable),
        version=_windows_file_version(executable),
        ready=ready,
        components=components,
        idalib_wheels=wheels,
        mcp_plugins=mcp_plugins,
        suspicious_executables=suspicious,
        warnings=warnings,
    )


def build_idalib_profile(
    path: str | Path,
    *,
    python_executable: str | Path | None = None,
    include_hashes: bool = True,
) -> dict[str, Any]:
    report = detect_ida_installation(path, include_hashes=include_hashes)
    python_path = Path(python_executable or sys.executable).resolve()
    if not python_path.is_file():
        raise IdaInstallationError(f"Python executable does not exist: {python_path}")
    activation = next(
        component.path
        for component in report.components
        if component.name == "idalib_activation"
    )
    wheel = report.idalib_wheels[-1] if report.idalib_wheels else ""
    commands: dict[str, list[str]] = {
        "activate": [str(python_path), activation, "-d", report.root],
    }
    if wheel:
        commands["install_wheel"] = [
            str(python_path),
            "-m",
            "pip",
            "install",
            "--no-deps",
            wheel,
        ]
    return {
        "schema_version": "0.5.0",
        "installation": report.to_dict(),
        "python": {
            "executable": str(python_path),
            "version": _python_version(python_path),
            "file_version": _windows_file_version(python_path),
            "idapro_importable": _package_detected(python_path, "idapro"),
            "detection_method": "standard-site-packages-read-only",
        },
        "commands_preview_only": commands,
        "ready_for_activation": report.ready and bool(wheel),
        "automatic_execution": False,
        "trusted_launch_targets": [
            report.executable,
            activation,
            str(Path(report.root) / "idat.exe"),
        ],
    }
