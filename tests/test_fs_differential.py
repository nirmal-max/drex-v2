"""
Acceptance Tests for Independent Differential Validation Engine
File: tests/test_fs_differential.py
Phase: 3 / 12
"""

from unittest.mock import MagicMock, patch
import pytest

from fs_base import FilesystemKind, SyntheticFixtureSource
from fs_differential import (
    DifferentialComparisonRecord,
    DifferentialValidationOutcome,
    DifferentialValidator,
)
from tests.test_fs_ntfs import create_synthetic_ntfs_image


def test_differential_validator_reference_unavailable():
    """Verify differential validator handles missing external TSK without failing."""
    image_bytes = create_synthetic_ntfs_image()
    source = SyntheticFixtureSource(image_bytes, identifier="synthetic://ntfs_image")

    with patch("fs_differential.find_backend_executable", return_value=None):
        rec = DifferentialValidator.cross_validate(source)

        assert rec.outcome == DifferentialValidationOutcome.REFERENCE_UNAVAILABLE
        assert rec.filesystem == FilesystemKind.NTFS.value
        assert rec.drex_candidate_count >= 4
        assert "reason" in rec.details


def test_differential_validator_exact_match():
    """Verify differential validator records EXACT_MATCH when native and TSK match 1:1."""
    image_bytes = create_synthetic_ntfs_image()
    source = SyntheticFixtureSource(image_bytes, identifier="synthetic://ntfs_image")

    mock_tsk_exe = MagicMock()
    mock_tsk_exe.parent = mock_tsk_exe
    mock_tsk_exe.is_file.return_value = True

    # Synthetic TSK output matching DREX deleted candidates
    mock_stdout = (
        "d/d 1: deleted_note.txt\n"
        "d/d 3: fragmented_deleted.dat\n"
    )

    with patch("fs_differential.find_backend_executable", return_value=mock_tsk_exe), \
         patch("os.path.exists", return_value=True), \
         patch("subprocess.run") as mock_run:

        mock_run.return_value = MagicMock(returncode=0, stdout=mock_stdout, stderr="")
        rec = DifferentialValidator.cross_validate(source)

        assert rec.outcome == DifferentialValidationOutcome.EXACT_MATCH
        assert rec.matched_count == 2
        assert len(rec.mismatches) == 0


def test_differential_validator_partial_match_discrepancy():
    """Verify differential validator records PARTIAL_MATCH and captures discrepancies."""
    image_bytes = create_synthetic_ntfs_image()
    source = SyntheticFixtureSource(image_bytes, identifier="synthetic://ntfs_image")

    mock_tsk_exe = MagicMock()
    mock_tsk_exe.parent = mock_tsk_exe
    mock_tsk_exe.is_file.return_value = True

    # Synthetic TSK output missing fragmented_deleted.dat and reporting extra file
    mock_stdout = (
        "d/d 1: deleted_note.txt\n"
        "d/d 99: extra_unmatched_file.log\n"
    )

    with patch("fs_differential.find_backend_executable", return_value=mock_tsk_exe), \
         patch("os.path.exists", return_value=True), \
         patch("subprocess.run") as mock_run:

        mock_run.return_value = MagicMock(returncode=0, stdout=mock_stdout, stderr="")
        rec = DifferentialValidator.cross_validate(source)

        assert rec.outcome == DifferentialValidationOutcome.PARTIAL_MATCH
        assert rec.matched_count == 1
        assert len(rec.mismatches) == 2
        assert any("fragmented_deleted.dat" in m for m in rec.mismatches)
        assert any("extra_unmatched_file.log" in m for m in rec.mismatches)
