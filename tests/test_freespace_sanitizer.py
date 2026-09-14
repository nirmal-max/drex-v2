"""Unit and Integration Tests for DREX-V2 Logical Free-Space Sanitizer (Phase 6 Track C)."""

import os
import pathlib
import tempfile
import pytest

from file_sanitizer import (
    FileSanitizationStatus,
    FreeSpaceSanitizer,
)


def test_free_space_bounded_wipe(tmp_path):
    """Verify bounded free space wipe allocates temp files, writes pattern, and cleans up."""
    wipe_limit = 2 * 1024 * 1024  # 2 MB test cap

    res = FreeSpaceSanitizer.wipe_free_space(
        target_dir=tmp_path,
        pattern_byte=0x00,
        max_bytes_to_wipe=wipe_limit,
    )

    assert res.status == FileSanitizationStatus.SUCCESS
    assert res.bytes_wiped == wipe_limit
    assert res.chunk_count >= 1
    assert res.coverage_type == "LOGICAL_FREE_SPACE_COVERAGE"
    assert res.execution_state == "REAL"
    assert res.verification_state == "ALLOCATION_AND_CLEANUP_VERIFIED"

    # Verify all temporary wipe files were purged
    remaining_tmps = list(tmp_path.glob("**/drex_freespace_*"))
    assert len(remaining_tmps) == 0


def test_free_space_invalid_mount_fails_closed():
    """Verify non-existent directory fails closed cleanly."""
    res = FreeSpaceSanitizer.wipe_free_space(
        target_dir="Z:\\NON_EXISTENT_MOUNT_POINT_XYZ",
    )

    assert res.status == FileSanitizationStatus.FAILED
    assert "does not exist" in res.error_message


def test_free_space_progress_callback(tmp_path):
    """Verify progress callback is invoked during chunk writes."""
    wipe_limit = 512 * 1024  # 512 KB
    progress_calls = []

    def callback(written, total):
        progress_calls.append((written, total))

    res = FreeSpaceSanitizer.wipe_free_space(
        target_dir=tmp_path,
        max_bytes_to_wipe=wipe_limit,
        progress_callback=callback,
    )

    assert res.status == FileSanitizationStatus.SUCCESS
    assert len(progress_calls) > 0
    assert progress_calls[-1][0] == wipe_limit
