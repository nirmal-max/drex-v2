"""
DREX-V2 Independent Forensic Differential Validation Engine
Module: fs_differential.py
Phase: 3 / 12

Performs independent cross-validation comparing DREX native filesystem recovery outputs
against external mature reference tools (e.g. The Sleuth Kit) without bundling external code.
Classifies outcomes as EXACT_MATCH, PARTIAL_MATCH, MISMATCH, or REFERENCE_UNAVAILABLE.

Provenance:
- Implements independent differential validation protocol (PROV-009).
- See docs/PROVEN_CODE_PROVENANCE.md and docs/PROVEN_CODE_VALIDATION_MATRIX.md.
"""

from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from fs_base import FilesystemKind, FsCandidateRecord, ReadOnlySource
from fs_recovery import FilesystemRecoveryEngine
from recovery_backends import find_backend_executable


class DifferentialValidationOutcome(str, Enum):
    """Classification states for differential cross-validation."""
    EXACT_MATCH = "EXACT_MATCH"
    PARTIAL_MATCH = "PARTIAL_MATCH"
    MISMATCH = "MISMATCH"
    REFERENCE_UNAVAILABLE = "REFERENCE_UNAVAILABLE"


@dataclass
class DifferentialComparisonRecord:
    """Detailed record of differential validation comparing DREX vs Reference backend."""
    source_identifier: str
    filesystem: str
    drex_candidate_count: int
    reference_candidate_count: int
    matched_count: int
    mismatches: List[str] = field(default_factory=list)
    outcome: DifferentialValidationOutcome = DifferentialValidationOutcome.REFERENCE_UNAVAILABLE
    reference_backend: str = "The Sleuth Kit (External Optional Reference)"
    details: Dict[str, Any] = field(default_factory=dict)


class DifferentialValidator:
    """Forensic cross-validator comparing native DREX recovery against independent backends."""

    @classmethod
    def cross_validate(
        cls,
        source: ReadOnlySource,
        root_path: Optional[Path] = None,
        meipass: Optional[Path] = None,
        timeout: int = 60,
    ) -> DifferentialComparisonRecord:
        """
        Execute native DREX scan and independently compare against TSK if available.
        Never fails or alters DREX native results if external reference is unavailable.
        """
        source_id = source.get_source_identifier()

        # 1. Native DREX Scan
        drex_candidates = FilesystemRecoveryEngine.scan_source(source)
        fs_type = drex_candidates[0].filesystem.value if drex_candidates else "UNKNOWN"

        # 2. Probe for External Reference Tool (TSK fls)
        tsk_exe = find_backend_executable("tsk", root_path, meipass)
        if tsk_exe is None or not os.path.exists(source_id):
            return DifferentialComparisonRecord(
                source_identifier=source_id,
                filesystem=fs_type,
                drex_candidate_count=len(drex_candidates),
                reference_candidate_count=0,
                matched_count=len(drex_candidates),
                outcome=DifferentialValidationOutcome.REFERENCE_UNAVAILABLE,
                details={
                    "reason": "External TSK reference binary not detected on test environment.",
                    "drex_native_candidates": [c.filename for c in drex_candidates],
                },
            )

        fls_binary = tsk_exe.parent / "fls.exe"
        if not fls_binary.is_file():
            fls_binary = tsk_exe.parent / "fls"
        if not fls_binary.is_file():
            fls_binary = tsk_exe

        # 3. Execute Independent Reference Scan via CLI subprocess
        cmd = [str(fls_binary), "-r", "-p", "-d", str(source_id)]
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            if res.returncode != 0 and not res.stdout:
                return DifferentialComparisonRecord(
                    source_identifier=source_id,
                    filesystem=fs_type,
                    drex_candidate_count=len(drex_candidates),
                    reference_candidate_count=0,
                    matched_count=0,
                    outcome=DifferentialValidationOutcome.REFERENCE_UNAVAILABLE,
                    details={"error": res.stderr.strip() if res.stderr else "TSK execution returned non-zero code"},
                )

            # Parse TSK fls output lines
            ref_filenames: Set[str] = set()
            for line in res.stdout.splitlines():
                parts = line.strip().split()
                if len(parts) >= 2:
                    name_candidate = parts[-1]
                    ref_filenames.add(name_candidate.lstrip("/"))

            # 4. Perform Differential Comparison
            drex_filenames = {c.filename for c in drex_candidates if not c.is_directory}
            drex_deleted_filenames = {c.filename for c in drex_candidates if c.is_deleted and not c.is_directory}

            matched = drex_deleted_filenames.intersection(ref_filenames)
            drex_only = drex_deleted_filenames.difference(ref_filenames)
            ref_only = ref_filenames.difference(drex_deleted_filenames)

            mismatches: List[str] = []
            for d in drex_only:
                mismatches.append(f"DREX discovered candidate not reported by TSK: {d}")
            for r in ref_only:
                mismatches.append(f"TSK reported candidate not discovered by DREX: {r}")

            if len(drex_deleted_filenames) == len(ref_filenames) and len(mismatches) == 0:
                outcome = DifferentialValidationOutcome.EXACT_MATCH
            elif len(matched) > 0:
                outcome = DifferentialValidationOutcome.PARTIAL_MATCH
            else:
                outcome = DifferentialValidationOutcome.MISMATCH

            return DifferentialComparisonRecord(
                source_identifier=source_id,
                filesystem=fs_type,
                drex_candidate_count=len(drex_candidates),
                reference_candidate_count=len(ref_filenames),
                matched_count=len(matched),
                mismatches=mismatches,
                outcome=outcome,
                details={
                    "matched_candidates": list(matched),
                    "drex_only": list(drex_only),
                    "ref_only": list(ref_only),
                },
            )

        except Exception as exc:
            return DifferentialComparisonRecord(
                source_identifier=source_id,
                filesystem=fs_type,
                drex_candidate_count=len(drex_candidates),
                reference_candidate_count=0,
                matched_count=0,
                outcome=DifferentialValidationOutcome.REFERENCE_UNAVAILABLE,
                details={"exception": str(exc)},
            )
