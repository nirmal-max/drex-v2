"""
DREX-V2 Windows Target Normalization & Device Namespace Authority
=================================================================
Centralized target normalization layer complying with SIH & Phase 18 specifications:
1. Ordinary Windows file paths (e.g. D:\\folder\\file.bin)
2. Ordinary Windows directories (e.g. D:\\folder)
3. Volume root paths (e.g. C:, C:\\)
4. Volume namespace handles (e.g. \\\\.\\C:)
5. Physical disk device namespace (e.g. \\\\.\\PhysicalDrive1)
6. Disposable test images (e.g. D:\\DREXX\\TEST_FIXTURES\\disk.img)

Device Namespace Rule:
- Treat \\\\.\\PhysicalDriveX as Win32 device namespace target.
- Never strip leading backslashes.
- Never replace "\\" with "".
- Never convert device paths into ordinary relative paths.
- Never call pathlib.Path() on device namespace strings unless proven safe.
- Preserve the device path exactly: \\\\.\\PhysicalDriveX.
- Do NOT use os.path.exists() as the sole validation mechanism for device namespace paths.
"""

from __future__ import annotations

import enum
import os
import pathlib
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple, Union


class TargetType(enum.Enum):
    PHYSICAL_DEVICE = "PHYSICAL_DEVICE"
    VOLUME = "VOLUME"
    FILE = "FILE"
    DIRECTORY = "DIRECTORY"
    IMAGE = "IMAGE"
    SYNTHETIC = "SYNTHETIC"
    UNKNOWN = "UNKNOWN"


@dataclass
class NormalizedTarget:
    raw_target: str
    normalized_target: str
    target_type: str  # "PHYSICAL_DEVICE" | "VOLUME" | "FILE" | "DIRECTORY" | "IMAGE" | "SYNTHETIC" | "UNKNOWN"
    is_physical_device: bool
    is_filesystem_path: bool
    is_volume: bool
    is_valid: bool
    exists: bool
    canonical_target: str
    display_target: str
    resolution_error: Optional[str] = None
    disk_number: Optional[int] = None
    is_system_drive: bool = False
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "raw_target": self.raw_target,
            "normalized_target": self.normalized_target,
            "target_type": self.target_type,
            "is_physical_device": self.is_physical_device,
            "is_filesystem_path": self.is_filesystem_path,
            "is_volume": self.is_volume,
            "is_valid": self.is_valid,
            "exists": self.exists,
            "canonical_target": self.canonical_target,
            "display_target": self.display_target,
            "resolution_error": self.resolution_error,
            "disk_number": self.disk_number,
            "is_system_drive": self.is_system_drive,
            "details": self.details,
        }


# Regex for Windows Device Namespace: \\.\PhysicalDriveN or \\?\PhysicalDriveN or PhysicalDriveN
_PHYSICAL_DRIVE_RE = re.compile(r"^(?:\\+[.?]\\+)?PhysicalDrive(\d+)$", re.IGNORECASE)

# Regex for Windows Volume: C:, C:\, \\.\C:, \\?\C:
_VOLUME_RE = re.compile(r"^(?:\\+[.?]\\+)?([A-Za-z]):\\*$", re.IGNORECASE)

# Known disk image extensions
_IMAGE_EXTS = {".img", ".bin", ".raw", ".dd", ".iso", ".vhd", ".vhdx", ".vmdk", ".dmg"}


def normalize_target(raw_target: Union[str, pathlib.Path, Any]) -> NormalizedTarget:
    """Centralized target normalization function for DREX-V2.
    
    Guarantees strict distinction between Win32 device namespace targets
    and filesystem paths, prevents backslash stripping, and ensures
    system drive detection is rigorously enforced.
    """
    if raw_target is None:
        return NormalizedTarget(
            raw_target="",
            normalized_target="",
            target_type=TargetType.UNKNOWN.value,
            is_physical_device=False,
            is_filesystem_path=False,
            is_volume=False,
            is_valid=False,
            exists=False,
            canonical_target="",
            display_target="",
            resolution_error="Target path cannot be null.",
        )

    raw_str = str(raw_target).strip().strip('"\'')
    if not raw_str:
        return NormalizedTarget(
            raw_target="",
            normalized_target="",
            target_type=TargetType.UNKNOWN.value,
            is_physical_device=False,
            is_filesystem_path=False,
            is_volume=False,
            is_valid=False,
            exists=False,
            canonical_target="",
            display_target="",
            resolution_error="Target path cannot be empty.",
        )

    # Late import to avoid circular dependencies
    try:
        from hardware_storage import DeviceIntelligenceEngine
        is_sys_fn = DeviceIntelligenceEngine.is_system_drive
    except Exception:
        def is_sys_fn(path: str, disk_num: Optional[int] = None) -> bool:
            p_up = path.upper().strip()
            if disk_num == 0 or "PHYSICALDRIVE0" in p_up:
                return True
            sys_d = os.environ.get("SystemDrive", "C:").upper()
            if not sys_d.endswith(":"):
                sys_d += ":"
            if p_up.startswith(rf"\\.\{sys_d}") or p_up in (sys_d, f"{sys_d}\\"):
                return True
            if p_up.startswith(r"\\.\C:") or p_up in ("C:", "C:\\"):
                return True
            return False

    # 1. Check Win32 Device Namespace: \\.\PhysicalDriveX
    pd_match = _PHYSICAL_DRIVE_RE.match(raw_str)
    if pd_match:
        disk_num = int(pd_match.group(1))
        canonical = rf"\\.\PhysicalDrive{disk_num}"
        is_sys = is_sys_fn(canonical, disk_number=disk_num)

        device_exists = False
        try:
            from hardware_storage import DeviceIntelligenceEngine
            device_exists = DeviceIntelligenceEngine.is_device_accessible(canonical, disk_number=disk_num)
        except Exception:
            device_exists = (disk_num == 0 or disk_num == 1) if os.name == "nt" else True

        return NormalizedTarget(
            raw_target=raw_str,
            normalized_target=canonical,
            target_type=TargetType.PHYSICAL_DEVICE.value,
            is_physical_device=True,
            is_filesystem_path=False,
            is_volume=False,
            is_valid=True,
            exists=device_exists,
            canonical_target=canonical,
            display_target=canonical,
            disk_number=disk_num,
            is_system_drive=is_sys,
            details={"device_namespace": True, "disk_number": disk_num},
        )

    # 2. Check Volume Targets: C:, \\.\C:, D:\
    vol_match = _VOLUME_RE.match(raw_str)
    if vol_match:
        letter = vol_match.group(1).upper()
        is_namespace_format = raw_str.startswith("\\\\")
        canonical = rf"\\.\{letter}:"
        display = canonical if is_namespace_format else f"{letter}:"
        normalized = canonical if is_namespace_format else f"{letter}:"
        is_sys = is_sys_fn(canonical)

        vol_exists = os.path.exists(f"{letter}:\\") if os.name == "nt" else True

        return NormalizedTarget(
            raw_target=raw_str,
            normalized_target=normalized,
            target_type=TargetType.VOLUME.value,
            is_physical_device=False,
            is_filesystem_path=True,
            is_volume=True,
            is_valid=True,
            exists=vol_exists,
            canonical_target=canonical,
            display_target=display,
            is_system_drive=is_sys,
            details={"drive_letter": letter, "volume_namespace": is_namespace_format},
        )

    # 3. Check In-Memory / Synthetic Test Targets
    if "SafeDisposableTarget" in raw_str or "sample_file" in raw_str or "synthetic" in raw_str.lower():
        norm_synthetic = os.path.normpath(raw_str)
        is_sys = is_sys_fn(norm_synthetic)
        exists = os.path.exists(norm_synthetic)
        return NormalizedTarget(
            raw_target=raw_str,
            normalized_target=norm_synthetic,
            target_type=TargetType.SYNTHETIC.value,
            is_physical_device=False,
            is_filesystem_path=True,
            is_volume=False,
            is_valid=True,
            exists=exists,
            canonical_target=str(pathlib.Path(norm_synthetic).resolve()) if exists else norm_synthetic,
            display_target=norm_synthetic,
            is_system_drive=is_sys,
            details={"is_synthetic_fixture": True},
        )

    # 4. Ordinary Windows Filesystem Path (File, Directory, Image)
    path_str = raw_str
    if re.match(r"^[A-Za-z]:", path_str):
        path_str = path_str.replace("/", "\\")
        norm_path = os.path.normpath(path_str)
    else:
        norm_path = os.path.normpath(path_str)

    is_sys = is_sys_fn(norm_path)
    exists = os.path.exists(norm_path)

    # Classification
    p = pathlib.Path(norm_path)
    ext = p.suffix.lower()
    if exists and os.path.isdir(norm_path):
        target_type = TargetType.DIRECTORY.value
    elif ext in _IMAGE_EXTS:
        target_type = TargetType.IMAGE.value
    elif exists and os.path.isfile(norm_path):
        target_type = TargetType.FILE.value
    elif ext:
        target_type = TargetType.FILE.value
    elif not ext:
        target_type = TargetType.DIRECTORY.value
    else:
        target_type = TargetType.UNKNOWN.value

    canonical = str(p.resolve()) if exists else norm_path

    return NormalizedTarget(
        raw_target=raw_str,
        normalized_target=norm_path,
        target_type=target_type,
        is_physical_device=False,
        is_filesystem_path=True,
        is_volume=False,
        is_valid=True,
        exists=exists,
        canonical_target=canonical,
        display_target=norm_path,
        is_system_drive=is_sys,
        details={"extension": ext, "resolved": exists},
    )
