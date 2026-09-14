"""Unit and Integration Tests for DREX-V2 Core File & Cryptographic Sanitizer (Phase 6 Track A & D)."""

import hashlib
import os
import pathlib
import tempfile
import pytest

from file_sanitizer import (
    CryptoSanitizer,
    FileSanitizer,
    FileSanitizationStatus,
    NISTProfile,
    SanitizationStandard,
)


@pytest.fixture
def temp_test_file(tmp_path):
    """Create a temporary test file with known binary content."""
    f = tmp_path / "target_data.bin"
    content = b"CRITICAL_FORENSIC_DATA_PAYLOAD_1234567890" * 100
    f.write_bytes(content)
    return f


def test_nist_clear_single_pass(temp_test_file):
    """Verify NIST SP 800-88 Rev. 2 Clear single-pass zero wipe."""
    orig_size = temp_test_file.stat().st_size

    orig_sha = hashlib.sha256(temp_test_file.read_bytes()).hexdigest()

    result = FileSanitizer.wipe_file(
        temp_test_file,
        standard=SanitizationStandard.NIST_800_88_CLEAR,
        unlink_after=False,
    )

    assert result.status == FileSanitizationStatus.SUCCESS
    assert result.pass_count == 1
    assert result.bytes_written == orig_size
    assert result.pre_wipe_sha256 == orig_sha
    assert result.exact_readback_verified is True
    assert result.nist_profile == NISTProfile.REV_2
    assert "Rev. 2 aligned" in result.standard_label
    assert temp_test_file.read_bytes() == b"\x00" * orig_size


def test_nist_rev1_legacy_profile(temp_test_file):
    """Verify explicit NIST SP 800-88 Rev. 1 (Legacy / Historical profile) selection."""
    orig_size = temp_test_file.stat().st_size
    result = FileSanitizer.wipe_file(
        temp_test_file,
        standard=SanitizationStandard.NIST_800_88_REV1_CLEAR,
        unlink_after=False,
    )

    assert result.status == FileSanitizationStatus.SUCCESS
    assert result.pass_count == 1
    assert result.bytes_written == orig_size
    assert result.exact_readback_verified is True
    assert result.nist_profile == NISTProfile.REV_1
    assert "Rev. 1 aligned" in result.standard_label
    assert "Legacy / Historical" in result.standard_label


def test_nist_rev2_current_profile(temp_test_file):
    """Verify explicit NIST SP 800-88 Rev. 2 (Current profile) selection."""
    orig_size = temp_test_file.stat().st_size
    result = FileSanitizer.wipe_file(
        temp_test_file,
        standard=SanitizationStandard.NIST_800_88_REV2_CLEAR,
        unlink_after=False,
    )

    assert result.status == FileSanitizationStatus.SUCCESS
    assert result.pass_count == 1
    assert result.bytes_written == orig_size
    assert result.exact_readback_verified is True
    assert result.nist_profile == NISTProfile.REV_2
    assert "Rev. 2 aligned" in result.standard_label
    assert "Current" in result.standard_label


def test_nist_default_and_no_silent_substitution(temp_test_file):
    """Verify default NIST profile is Rev. 2 and profiles are not silently substituted."""
    # 1. Default selection must be Rev. 2
    res_default = FileSanitizer.wipe_file(
        temp_test_file,
        standard=SanitizationStandard.NIST_800_88_CLEAR,
        unlink_after=False,
    )
    assert res_default.nist_profile == NISTProfile.REV_2
    assert "Rev. 2" in res_default.standard_label

    # 2. Explicit Rev. 1 override must remain strictly Rev. 1
    res_rev1 = FileSanitizer.wipe_file(
        temp_test_file,
        standard=SanitizationStandard.NIST_800_88_CLEAR,
        unlink_after=False,
        nist_profile=NISTProfile.REV_1,
    )
    assert res_rev1.nist_profile == NISTProfile.REV_1
    assert "Rev. 1" in res_rev1.standard_label
    assert res_rev1.nist_profile != res_default.nist_profile


def test_dod_3pass_overwrite(temp_test_file):
    """Verify DoD 5220.22-M 3-pass overwrite (0x00, 0xFF, CSPRNG)."""
    orig_size = temp_test_file.stat().st_size
    result = FileSanitizer.wipe_file(
        temp_test_file,
        standard=SanitizationStandard.DOD_5220_22_M_3PASS,
        unlink_after=False,
    )

    assert result.status == FileSanitizationStatus.SUCCESS
    assert result.pass_count == 3
    assert result.bytes_written == orig_size * 3
    assert result.exact_readback_verified is True
    assert temp_test_file.stat().st_size == orig_size


def test_dod_7pass_ece_overwrite(temp_test_file):
    """Verify DoD 5220.22-M 7-pass ECE overwrite."""
    orig_size = temp_test_file.stat().st_size
    result = FileSanitizer.wipe_file(
        temp_test_file,
        standard=SanitizationStandard.DOD_5220_22_M_7PASS,
        unlink_after=False,
    )

    assert result.status == FileSanitizationStatus.SUCCESS
    assert result.pass_count == 7
    assert result.bytes_written == orig_size * 7


def test_gutmann_35pass_overwrite(temp_test_file):
    """Verify Gutmann 35-pass overwrite sequence."""
    orig_size = temp_test_file.stat().st_size
    result = FileSanitizer.wipe_file(
        temp_test_file,
        standard=SanitizationStandard.GUTMANN_35PASS,
        unlink_after=False,
    )

    assert result.status == FileSanitizationStatus.SUCCESS
    assert result.pass_count == 35
    assert result.bytes_written == orig_size * 35


def test_csprng_stream_overwrite(temp_test_file):
    """Verify CSPRNG stream overwrite."""
    orig_size = temp_test_file.stat().st_size
    result = FileSanitizer.wipe_file(
        temp_test_file,
        standard=SanitizationStandard.CSPRNG_OVERWRITE,
        unlink_after=False,
    )

    assert result.status == FileSanitizationStatus.SUCCESS
    assert result.pass_count == 1
    assert result.bytes_written == orig_size
    assert temp_test_file.stat().st_size == orig_size


def test_wipe_and_unlink(temp_test_file):
    """Verify file unlinking and metadata scrambling."""
    target_path = str(temp_test_file)
    result = FileSanitizer.wipe_file(
        temp_test_file,
        standard=SanitizationStandard.SINGLE_PASS_ZERO,
        unlink_after=True,
        scramble_metadata=True,
    )

    assert result.status == FileSanitizationStatus.SUCCESS
    assert not os.path.exists(target_path)


def test_wipe_directory_tree(tmp_path):
    """Verify recursive directory tree sanitization."""
    sub_dir = tmp_path / "deep" / "nested" / "folder"
    sub_dir.mkdir(parents=True)
    f1 = sub_dir / "f1.txt"
    f2 = sub_dir / "f2.txt"
    f1.write_text("Hello World 1")
    f2.write_text("Hello World 2")

    results = FileSanitizer.wipe_directory_tree(tmp_path / "deep", unlink_after=True)

    assert len(results) == 2
    assert all(r.status == FileSanitizationStatus.SUCCESS for r in results)
    assert not (tmp_path / "deep").exists()


def test_missing_file_fails_closed(tmp_path):
    """Verify missing file produces clean FAILED result without crash."""
    missing = tmp_path / "does_not_exist.bin"
    result = FileSanitizer.wipe_file(missing)

    assert result.status == FileSanitizationStatus.FAILED
    assert "File not found" in result.error_message


def test_crypto_sanitizer_key_invalidation(tmp_path):
    """Verify cryptographic key invalidation and header overwrite."""
    container = tmp_path / "encrypted_vault.luks"
    container.write_bytes(b"\xAA" * 8192)

    res = CryptoSanitizer.invalidate_key(
        key_identifier="KEY-AES-256-VSS-9921",
        container_path=container,
        overwrite_header_bytes=4096,
    )

    assert res.status == FileSanitizationStatus.SUCCESS
    assert res.key_purged is True
    assert res.header_overwritten is True
    assert res.execution_state == "REAL"
    assert res.verification_state == "KEY_INVALIDATION_VERIFIED"
    assert container.read_bytes()[:4096] != b"\xAA" * 4096
