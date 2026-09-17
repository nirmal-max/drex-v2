"""Authoritative recovery-backend manifest and local executable discovery.

This module deliberately does not download or vendor third-party tools.  It
records the upstream projects DREX is designed to invoke and detects only
locally installed executables.  A source checkout is not an executable and is
never reported as READY.
"""

from __future__ import annotations

import os
import shutil
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class BackendSpec:
    backend_id: str
    project_url: str
    executable_names: tuple[str, ...]
    license_name: str


BACKENDS = {
    "testdisk": BackendSpec("testdisk", "https://github.com/cgsecurity/testdisk", ("testdisk.exe", "testdisk_win.exe"), "GNU GPL v2"),
    "photorec": BackendSpec("photorec", "https://github.com/cgsecurity/testdisk", ("photorec.exe", "photorec_win.exe", "fidentify.exe"), "GNU GPL v2"),
    "tsk": BackendSpec("tsk", "https://github.com/sleuthkit/sleuthkit", ("fls.exe", "fsstat.exe", "icat.exe", "tsk_recover.exe", "mmls.exe"), "Mixed upstream licenses; see TSK licenses directory"),
    "ddrescue": BackendSpec("ddrescue", "https://savannah.gnu.org/git/?group=ddrescue", ("ddrescue.exe", "ddrescue"), "GNU GPL"),
    "autopsy": BackendSpec("autopsy", "https://github.com/sleuthkit/autopsy", ("autopsy.exe",), "Apache License 2.0 / bundled component licenses"),
}


METHOD_BACKENDS = {
    "quick": ("testdisk", "photorec"),
    "smart": ("tsk", "testdisk", "photorec"),
    "targeted": ("photorec", "testdisk"),
    "filesystem": ("tsk", "testdisk"),
    "deep": ("photorec",),
    "fragment": ("photorec",),
    "raid": ("tsk", "testdisk"),
    "damaged": ("ddrescue", "photorec", "tsk"),
    "forensic": ("tsk", "autopsy", "photorec"),
}


def find_backend_executable(backend_id: str, root: Path, meipass: Path | None = None) -> Path | None:
    spec = BACKENDS[backend_id]
    search_dirs = [root / "native_bin", root / "third_party" / backend_id]
    if meipass:
        search_dirs.insert(0, meipass / "native_bin")
    for directory in search_dirs:
        for name in spec.executable_names:
            candidate = directory / name
            if candidate.is_file():
                return candidate
    for name in spec.executable_names:
        found = shutil.which(name)
        if found:
            return Path(found)
    return None


def backend_status(method_id: str, root: Path, meipass: Path | None = None) -> tuple[str, str]:
    required = METHOD_BACKENDS.get(method_id, ())
    if not required:
        return "UNSUPPORTED", f"No backend mapping exists for method '{method_id}'."
    found = [backend for backend in required if find_backend_executable(backend, root, meipass)]
    if found:
        return "BACKEND DETECTED", ", ".join(found)
    return "BACKEND MISSING", "Required official backend executable not found: " + ", ".join(required)

BACKENDS.update({
    "bleachbit": BackendSpec("bleachbit", "https://github.com/bleachbit/bleachbit", ("bleachbit.py", "bleachbit.exe"), "GPLv3"),
    "eraser": BackendSpec("eraser", "https://github.com/Eraser/eraser", ("Eraser.exe",), "GPLv3"),
    "drivewipe": BackendSpec("drivewipe", "https://github.com/KodyDennon/DriveWipe", ("drivewipe-cli.exe", "drivewipe-cli"), "GPLv3"),
    "nvme-cli": BackendSpec("nvme-cli", "https://github.com/linux-nvme/nvme-cli", ("nvme.exe", "nvme"), "GPLv2"),
})
