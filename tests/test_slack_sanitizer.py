"""Unit and Integration Tests for DREX-V2 File Slack & Cluster-Tip Sanitizer (Phase 6 Track B)."""

import hashlib
import pytest

from file_sanitizer import (
    FileSanitizationStatus,
    SlackSanitizer,
)


def test_slack_analysis_prime_offsets(tmp_path):
    """Test slack calculation across prime non-aligned file sizes."""
    cluster_size = 4096

    # Case 1: 17 bytes -> alloc_end = 4096, slack = 4079
    f1 = tmp_path / "f17.bin"
    f1.write_bytes(b"A" * 17)
    log_sz, alloc_end, slack = SlackSanitizer.analyze_slack(f1, cluster_size=cluster_size)
    assert log_sz == 17
    assert alloc_end == 4096
    assert slack == 4079

    # Case 2: 513 bytes -> alloc_end = 4096, slack = 3583
    f2 = tmp_path / "f513.bin"
    f2.write_bytes(b"B" * 513)
    log_sz, alloc_end, slack = SlackSanitizer.analyze_slack(f2, cluster_size=cluster_size)
    assert log_sz == 513
    assert alloc_end == 4096
    assert slack == 3583

    # Case 3: 4096 bytes (perfectly aligned) -> slack = 0
    f3 = tmp_path / "f4096.bin"
    f3.write_bytes(b"C" * 4096)
    log_sz, alloc_end, slack = SlackSanitizer.analyze_slack(f3, cluster_size=cluster_size)
    assert log_sz == 4096
    assert alloc_end == 4096
    assert slack == 0


def test_slack_sanitization_payload_preservation(tmp_path):
    """Verify that slack sanitization preserves 100% of live payload bytes (zero corruption)."""
    f = tmp_path / "test_slack_target.bin"
    payload = b"CRITICAL_USER_DATABASE_RECORD_XYZ_9876543210" * 10
    payload_len = len(payload)
    cluster_size = 4096
    f.write_bytes(payload)

    pre_sha = hashlib.sha256(payload).hexdigest()

    result = SlackSanitizer.sanitize_slack(
        f,
        cluster_size=cluster_size,
        confirm_mutation=True,
    )

    assert result.status == FileSanitizationStatus.SUCCESS
    assert result.payload_preserved is True
    assert result.slack_zero_readback_verified is True
    assert result.pre_payload_sha256 == pre_sha
    assert result.post_payload_sha256 == pre_sha
    assert result.slack_bytes_zeroed == (cluster_size - payload_len)
    assert result.logical_size == payload_len

    # Verify file content on disk is identical to original payload
    assert f.read_bytes() == payload


def test_slack_sanitization_unconfirmed_guard(tmp_path):
    """Verify that unconfirmed mutation fails closed with UNSUPPORTED status."""
    f = tmp_path / "unconfirmed.bin"
    f.write_bytes(b"DATA" * 50)

    result = SlackSanitizer.sanitize_slack(
        f,
        cluster_size=4096,
        confirm_mutation=False,
    )

    assert result.status == FileSanitizationStatus.UNSUPPORTED
    assert "Explicit mutation confirmation required" in result.error_message


def test_slack_aligned_file_noop(tmp_path):
    """Verify cluster-aligned file reports SUCCESS with 0 bytes to zero."""
    f = tmp_path / "aligned.bin"
    f.write_bytes(b"D" * 4096)

    result = SlackSanitizer.sanitize_slack(f, cluster_size=4096, confirm_mutation=True)

    assert result.status == FileSanitizationStatus.SUCCESS
    assert result.slack_bytes_zeroed == 0
    assert result.payload_preserved is True
