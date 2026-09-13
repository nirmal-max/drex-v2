"""DREX-V2 Volume Shadow Copy (VSS) Discovery & Sanitization Engine

Implements strict forensic safety separation:
1. Discovery (non-destructive inspection)
2. Reporting (enumerating snapshot IDs and volume targets)
3. Sanitization Decision (explicit operator selection)
4. Confirmation Guard (confirm_destructive=True requirement)
5. Administrative Elevation Check
6. Dry-Run Execution Simulation
7. Evidence Audit Logging

Attribution:
- VSS discovery commands adapted from EraseXperts (MIT License) with safety gates.
"""

from __future__ import annotations

import ctypes
import os
import re
import subprocess
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class VssShadowCopy:
    shadow_id: str
    original_volume: str
    creation_time: str
    provider: str = "Microsoft Software Shadow Copy provider 1.0"
    attributes: str = "Persistent"


@dataclass
class VssPurgePlan:
    shadow_copies: List[VssShadowCopy]
    target_count: int
    is_elevated: bool
    requires_confirmation: bool = True
    planned_command: str = "vssadmin delete shadows /for=<volume> /quiet"


@dataclass
class VssPurgeResult:
    status: str  # "SUCCESS", "DRY_RUN", "BLOCKED", "FAILED"
    is_elevated: bool
    shadows_targeted: int
    shadows_purged: int
    command_executed: str
    output: str
    error_message: Optional[str] = None


class VssSanitizer:
    """Safe, gated manager for Volume Shadow Copy discovery and sanitization."""

    @staticmethod
    def is_admin() -> bool:
        """Check if current process has administrative elevation."""
        if os.name != "nt":
            return os.geteuid() == 0 if hasattr(os, "geteuid") else False
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except (AttributeError, OSError):
            return False

    @classmethod
    def discover_shadows(cls, command_output: Optional[str] = None) -> List[VssShadowCopy]:
        """Discover existing Volume Shadow Copies without modifying any system state.
        
        If command_output is provided, parses it directly (for testing/mocking).
        Otherwise queries vssadmin if running on Windows.
        """
        raw_text = command_output
        if raw_text is None:
            if os.name != "nt":
                return []
            try:
                proc = subprocess.run(
                    ["vssadmin", "list", "shadows"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )
                raw_text = proc.stdout
            except (subprocess.SubprocessError, FileNotFoundError, OSError):
                return []

        shadows: List[VssShadowCopy] = []
        if not raw_text:
            return shadows

        # Regex to parse vssadmin list shadows output
        current_id = ""
        current_vol = ""
        current_time = ""

        for line in raw_text.splitlines():
            line = line.strip()
            if "Shadow Copy ID:" in line:
                m = re.search(r"\{[0-9a-fA-F-]+\}", line)
                if m:
                    current_id = m.group(0)
            elif "Original Volume:" in line:
                m = re.search(r"\([A-Za-z]:\)", line)
                current_vol = m.group(0) if m else line.split(":", 1)[-1].strip()
            elif "Creation Time:" in line:
                current_time = line.split(":", 1)[-1].strip()
                if current_id:
                    shadows.append(
                        VssShadowCopy(
                            shadow_id=current_id,
                            original_volume=current_vol or "Unknown",
                            creation_time=current_time or "Unknown",
                        )
                    )
                    current_id = ""
                    current_vol = ""
                    current_time = ""

        return shadows

    @classmethod
    def create_purge_plan(
        cls,
        shadows: Optional[List[VssShadowCopy]] = None,
        mock_output: Optional[str] = None,
    ) -> VssPurgePlan:
        """Create a non-destructive purge plan enumerating what would be deleted."""
        target_shadows = shadows if shadows is not None else cls.discover_shadows(mock_output)
        return VssPurgePlan(
            shadow_copies=target_shadows,
            target_count=len(target_shadows),
            is_elevated=cls.is_admin(),
            requires_confirmation=True,
            planned_command="vssadmin delete shadows /all /quiet",
        )

    @classmethod
    def execute_purge(
        cls,
        confirm_destructive: bool = False,
        dry_run: bool = True,
        target_volume: Optional[str] = None,
    ) -> VssPurgeResult:
        """Execute VSS purge with strict safety gates.
        
        Guards:
        - If dry_run is True: Simulates execution and returns DRY_RUN result.
        - If confirm_destructive is False: BLOCKED with explicit safety reason.
        - If not elevated: BLOCKED due to insufficient administrative privilege.
        """
        is_elevated = cls.is_admin()

        if dry_run:
            vol_arg = ""
            if target_volume:
                vol_clean = target_volume.strip()
                if not re.match(r"^[A-Za-z]:\\?$", vol_clean):
                    return VssPurgeResult(
                        status="BLOCKED",
                        is_elevated=is_elevated,
                        shadows_targeted=0,
                        shadows_purged=0,
                        command_executed="none",
                        output="",
                        error_message=f"Invalid target volume format '{target_volume}'. Expected drive specifier like 'C:'.",
                    )
                vol_arg = f" /for={vol_clean[:2]}"
            cmd = f"vssadmin delete shadows{vol_arg or ' /all'} /quiet"
            return VssPurgeResult(
                status="DRY_RUN",
                is_elevated=is_elevated,
                shadows_targeted=1 if target_volume else 0,
                shadows_purged=0,
                command_executed=cmd,
                output="DRY RUN: No actual shadow copies were modified or destroyed.",
                error_message=None,
            )

        if not confirm_destructive:
            return VssPurgeResult(
                status="BLOCKED",
                is_elevated=is_elevated,
                shadows_targeted=0,
                shadows_purged=0,
                command_executed="none",
                output="",
                error_message="Destructive confirmation not provided (confirm_destructive=False).",
            )

        if not is_elevated:
            return VssPurgeResult(
                status="BLOCKED",
                is_elevated=False,
                shadows_targeted=0,
                shadows_purged=0,
                command_executed="none",
                output="",
                error_message="Administrative elevation required to purge Volume Shadow Copies.",
            )

        if os.name != "nt":
            return VssPurgeResult(
                status="BLOCKED",
                is_elevated=is_elevated,
                shadows_targeted=0,
                shadows_purged=0,
                command_executed="none",
                output="",
                error_message="VSS is only applicable on Windows NT platforms.",
            )

        # Real execution path (Windows + Elevated + Confirmed + Non-dry-run)
        cmd = ["vssadmin", "delete", "shadows"]
        if target_volume:
            vol_clean = target_volume.strip()
            if not re.match(r"^[A-Za-z]:\\?$", vol_clean):
                return VssPurgeResult(
                    status="BLOCKED",
                    is_elevated=is_elevated,
                    shadows_targeted=0,
                    shadows_purged=0,
                    command_executed="none",
                    output="",
                    error_message=f"Invalid target volume format '{target_volume}'. Expected drive specifier like 'C:'.",
                )
            cmd.extend([f"/for={vol_clean[:2]}", "/quiet"])
        else:
            cmd.extend(["/all", "/quiet"])

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            success = (proc.returncode == 0)
            return VssPurgeResult(
                status="SUCCESS" if success else "FAILED",
                is_elevated=True,
                shadows_targeted=1,
                shadows_purged=1 if success else 0,
                command_executed=" ".join(cmd),
                output=proc.stdout,
                error_message=proc.stderr if not success else None,
            )
        except Exception as ex:
            return VssPurgeResult(
                status="FAILED",
                is_elevated=True,
                shadows_targeted=0,
                shadows_purged=0,
                command_executed=" ".join(cmd),
                output="",
                error_message=str(ex),
            )
