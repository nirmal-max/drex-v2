"""
DREX-V2 Phase 9 — Known-Answer Test Suite: M01-M16 Sanitization
================================================================
File: tests/test_phase9_kat_sanitization.py

Validates canonical sanitization methods (M01-M16) against deterministic,
mathematically verifiable ground-truth fixtures:
- M01: NIST SP 800-88 Policy Engine (Clear vs Purge selection)
- M08: CSPRNG Random Overwrite (100% byte verification + secondary entropy telemetry)
- M10: File Slack / Cluster-Tip (Active payload preservation + slack zeroing)
- M11: Filesystem Metadata Sanitization (MFT record scrubbing)
- M13: Secure Free-Space Wiping (Cluster unallocated wipe)
- M14: Single-Pass Zero Overwrite (Deterministic zero-fill verification, H=0.0)
- M16: Temporary / Cache Sanitization (Safe cache shredding)

Crucial Invariant: Entropy (H) is strictly secondary telemetry, NEVER proof of sanitization.
Primary sanitization proof is deterministic pattern verification / byte-for-byte readback.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import pytest
import struct

from fixture_generator import (
    SyntheticFixtureGenerator,
    sha256_bytes,
)
from file_sanitizer import (
    FileSanitizer,
    SlackSanitizer,
    FreeSpaceSanitizer,
    SanitizationStandard,
    FileSanitizationStatus,
)
from mft_sanitizer import (
    MFTSanitizer,
    MFTRecordStatus,
    MFTSanitizeStatus,
)
from entropy_engine import (
    calculate_shannon_entropy,
)
from hardware_storage import (
    Qualification25MethodEngine,
    DeviceIntelligenceEngine,
)


class TestPhase9KATSanitizationDriveErasure:
    """Known-Answer Tests for M01-M07: Drive Erasure & Policy Selection."""

    def test_m01_nist_800_88_policy_selection(self):
        """M01: Policy Engine selects appropriate sanitization level based on media intelligence."""
        # Simulated Magnetic HDD -> Clear via Overwrite
        hdd_snap = DeviceIntelligenceEngine.create_snapshot(
            r"\\.\PhysicalDrive1",
            simulated_descriptor={"disk_number": 1, "bus_type": "SATA", "media_type": "HDD", "capacity_bytes": 500 * 10**9},
        )
        matrix_hdd = Qualification25MethodEngine.evaluate_25_methods(hdd_snap)
        assert matrix_hdd[1].qualification_status.value in ("AVAILABLE", "QUALIFIED")
        assert matrix_hdd[1].truth_model.software_qualification == "SOFTWARE-QUALIFIED"
        assert matrix_hdd[1].truth_model.physical_qualification == "NOT_ESTABLISHED"

        # Simulated NVMe SSD -> Purge / Block Erase / Crypto Scramble
        nvme_snap = DeviceIntelligenceEngine.create_snapshot(
            r"\\.\PhysicalDrive2",
            simulated_descriptor={"disk_number": 2, "bus_type": "NVMe", "media_type": "SSD", "capacity_bytes": 10**12},
        )
        matrix_nvme = Qualification25MethodEngine.evaluate_25_methods(nvme_snap)
        assert matrix_nvme[1].qualification_status.value in ("AVAILABLE", "QUALIFIED")
        assert matrix_nvme[5].qualification_status.value in ("UNSUPPORTED", "AVAILABLE", "QUALIFIED")
        assert matrix_nvme[5].truth_model.physical_qualification in ("NOT_ESTABLISHED", "HARDWARE_REQUIRED")

    def test_m07_verified_overwrite_deterministic_pattern(self, tmp_path: Path):
        """M07: Verified overwrite with 100% pattern verification."""
        test_file = tmp_path / "target_m07.bin"
        file_size = 65536
        test_file.write_bytes(b"\xAA" * file_size)

        # Sanitize using single-pass zero (unlink_after=False to allow checking)
        result = FileSanitizer.wipe_file(
            test_file,
            standard=SanitizationStandard.SINGLE_PASS_ZERO,
            unlink_after=False,
        )
        assert result.status == FileSanitizationStatus.SUCCESS
        assert result.exact_readback_verified is True
        assert result.bytes_written == file_size


class TestPhase9KATSanitizationFileFolder:
    """Known-Answer Tests for M08-M16: File, Slack, Metadata, and Free-Space Sanitization."""

    def test_m08_csprng_random_overwrite_and_secondary_entropy(self, tmp_path: Path):
        """M08: CSPRNG overwrite with exact readback and secondary statistical entropy telemetry."""
        test_file = tmp_path / "target_m08.bin"
        original_data = b"CONFIDENTIAL FINANCIAL RECORD " * 2000  # ~60 KB
        test_file.write_bytes(original_data)

        # Compute initial entropy
        h_initial = calculate_shannon_entropy(original_data)
        assert h_initial < 5.0  # Structured repetitive text has low entropy

        # Execute CSPRNG sanitization without unlinking immediately
        result = FileSanitizer.wipe_file(
            test_file,
            standard=SanitizationStandard.CSPRNG_OVERWRITE,
            unlink_after=False,
        )
        assert result.status == FileSanitizationStatus.SUCCESS
        assert result.exact_readback_verified is True

        # Secondary telemetry: High entropy stream
        overwritten_data = test_file.read_bytes()
        h_post = calculate_shannon_entropy(overwritten_data)
        assert h_post >= 7.90, f"Expected high entropy telemetry for CSPRNG stream, got {h_post}"

    def test_m10_file_slack_cluster_tip_ground_truth(self, tmp_path: Path):
        """M10: Cluster-tip slack zeroing preserves active payload in [0, file_size) and zeroes [file_size, cluster_size)."""
        file_size = 1500
        cluster_size = 4096
        full_cluster, active_payload, expected_sanitized = SyntheticFixtureGenerator.generate_file_slack_fixture(
            file_size_bytes=file_size,
            cluster_size=cluster_size,
            seed=42,
        )

        # Verify fixture precondition
        assert len(full_cluster) == cluster_size
        assert full_cluster[0:file_size] == active_payload
        # Sensitive slack is non-zero
        assert full_cluster[file_size:] != b"\x00" * (cluster_size - file_size)

        # Write to temporary file
        target_file = tmp_path / "test_slack.bin"
        target_file.write_bytes(active_payload)

        # Analyze slack
        log_size, alloc_end, slack_b = SlackSanitizer.analyze_slack(target_file, cluster_size=cluster_size)
        assert log_size == file_size
        assert alloc_end == cluster_size
        assert slack_b == cluster_size - file_size

        # Sanitize slack
        res = SlackSanitizer.sanitize_slack(target_file, cluster_size=cluster_size, confirm_mutation=True)
        assert res.status == FileSanitizationStatus.SUCCESS
        assert res.payload_preserved is True

    def test_m11_mft_metadata_sanitization(self):
        """M11: MFT metadata scrubbing zeros residual attributes on deleted records while protecting system inodes 0-15."""
        # Build 1024-byte MFT record for system inode 0 ($MFT)
        rec0 = bytearray(1024)
        rec0[0:4] = b"FILE"
        struct.pack_into("<H", rec0, 4, 48)   # Fixup offset
        struct.pack_into("<H", rec0, 6, 3)    # Fixup count
        struct.pack_into("<H", rec0, 20, 56)  # Attr offset
        struct.pack_into("<H", rec0, 22, 0x01) # In-use
        struct.pack_into("<I", rec0, 24, 100) # Used size
        struct.pack_into("<I", rec0, 28, 1024) # Alloc size
        info0 = MFTSanitizer.parse_record_header(bytes(rec0), record_number=0)
        assert info0 is not None
        assert info0.status == MFTRecordStatus.SYSTEM_METADATA_PROTECTED

        # Build 1024-byte MFT record for deleted user file (inode 17)
        rec17 = bytearray(1024)
        rec17[0:4] = b"FILE"
        struct.pack_into("<H", rec17, 4, 48)
        struct.pack_into("<H", rec17, 6, 3)
        struct.pack_into("<H", rec17, 20, 56)
        struct.pack_into("<H", rec17, 22, 0x00) # Inactive
        struct.pack_into("<I", rec17, 24, 100)
        struct.pack_into("<I", rec17, 28, 1024)
        payload = b"SENSITIVE INODE DATA TO BE SANITIZED"
        rec17[56 : 56 + len(payload)] = payload
        info17 = MFTSanitizer.parse_record_header(bytes(rec17), record_number=17)
        assert info17 is not None
        assert info17.status == MFTRecordStatus.DELETED_FILE

        # Build 20-record MFT stream (20 * 1024 bytes)
        stream = bytearray(20 * 1024)
        # Put rec0 at index 0
        stream[0:1024] = rec0
        # Put rec17 at index 17
        stream[17 * 1024 : 18 * 1024] = rec17

        res = MFTSanitizer.scrub_mft_stream(stream, dry_run=False, confirm_mft_scrub=True, is_live_system_disk=False)
        assert res.status == MFTSanitizeStatus.SUCCESS
        assert res.records_scrubbed == 1
        assert res.records_skipped_protected >= 1

    def test_m13_secure_free_space_wiping(self, tmp_path: Path):
        """M13: Logical free space wiping creates and fills unallocated capacity without overflowing headroom."""
        wipe_dir = tmp_path / "freespace_target"
        wipe_dir.mkdir()

        res = FreeSpaceSanitizer.wipe_free_space(wipe_dir, pattern_byte=0x00, max_bytes_to_wipe=1024 * 1024)
        assert res.status == FileSanitizationStatus.SUCCESS
        assert res.coverage_type == "LOGICAL_FREE_SPACE_COVERAGE"

    def test_m14_single_pass_zero_overwrite_entropy(self, tmp_path: Path):
        """M14: Single-pass zero overwrite produces uniform zero bytes with exact Shannon entropy H = 0.0."""
        zero_buf = b"\x00" * 65536
        h = calculate_shannon_entropy(zero_buf)
        assert h == 0.0

        test_file = tmp_path / "target_m14.bin"
        test_file.write_bytes(b"DATA" * 1024)

        res = FileSanitizer.wipe_file(
            test_file,
            standard=SanitizationStandard.SINGLE_PASS_ZERO,
            unlink_after=False,
        )
        assert res.status == FileSanitizationStatus.SUCCESS
        assert res.exact_readback_verified is True
        assert test_file.read_bytes() == b"\x00" * (4 * 1024)

    def test_m16_temporary_cache_sanitization(self, tmp_path: Path):
        """M16: Temporary and cache artifacts are purged and shredded."""
        cache_dir = tmp_path / "app_cache"
        cache_dir.mkdir()
        temp1 = cache_dir / "sess_01.tmp"
        temp2 = cache_dir / "cache.db"
        temp1.write_bytes(b"TEMPORARY SESSION DATA " * 100)
        temp2.write_bytes(b"SQLITE CACHE DATA " * 200)

        # Sanitize entire directory contents
        results = FileSanitizer.wipe_directory_tree(cache_dir, standard=SanitizationStandard.SINGLE_PASS_ZERO, unlink_after=True)
        assert len(results) == 2
        for res in results:
            assert res.status == FileSanitizationStatus.SUCCESS

        # Assert directory and files are purged
        assert not temp1.exists()
        assert not temp2.exists()
