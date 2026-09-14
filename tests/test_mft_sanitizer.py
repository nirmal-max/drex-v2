"""Unit and Integration Tests for DREX-V2 MFT Analysis & Record Sanitizer (Phase 6 Track D)."""

import struct
import pytest

from mft_sanitizer import (
    MFTRecordInfo,
    MFTRecordStatus,
    MFTSanitizeResult,
    MFTSanitizeStatus,
    MFTSanitizer,
)


def create_synthetic_mft_stream(num_records: int = 32) -> bytearray:
    """Create a synthetic 1024-byte NTFS MFT stream containing active and deleted records."""
    buf = bytearray(num_records * 1024)

    for i in range(num_records):
        offset = i * 1024
        # Magic "FILE"
        buf[offset:offset + 4] = b"FILE"
        fixup_offset = 48
        fixup_count = 3
        lsn = 1000 + i
        seq = 1
        link_count = 1
        attr_offset = 56
        # Inodes 0-15 are system records (InUse | Directory)
        # Inode 16: Active File (0x01)
        # Inode 17: Deleted File (0x00)
        # Inode 18: Deleted Directory (0x02)
        if i < 16:
            flags = 0x0003  # InUse | Directory (System)
        elif i == 16:
            flags = 0x0001  # Active File
        elif i == 17:
            flags = 0x0000  # Deleted File
        elif i == 18:
            flags = 0x0002  # Deleted Directory
        else:
            flags = 0x0000  # Deleted File

        used_size = 512
        alloc_size = 1024

        struct.pack_into(
            "<HHQHHHHII",
            buf,
            offset + 4,
            fixup_offset,
            fixup_count,
            lsn,
            seq,
            link_count,
            attr_offset,
            flags,
            used_size,
            alloc_size,
        )


        # Fill attribute payload with test data
        buf[offset + attr_offset:offset + used_size] = b"\xEE" * (used_size - attr_offset)

    return buf


def test_mft_parser_classification():
    """Verify classification of system records, active files, and deleted files."""
    mft_stream = create_synthetic_mft_stream(32)
    records = MFTSanitizer.scan_mft_stream(bytes(mft_stream))

    assert len(records) == 32
    assert records[0].status == MFTRecordStatus.SYSTEM_METADATA_PROTECTED
    assert records[15].status == MFTRecordStatus.SYSTEM_METADATA_PROTECTED
    assert records[16].status == MFTRecordStatus.ACTIVE_FILE
    assert records[17].status == MFTRecordStatus.DELETED_FILE
    assert records[18].status == MFTRecordStatus.DELETED_DIRECTORY


def test_mft_plan_dry_run():
    """Verify MFT scrub planning enumerates deleted records without mutation."""
    mft_stream = create_synthetic_mft_stream(32)
    plan = MFTSanitizer.plan_scrub(bytes(mft_stream), is_live_system_disk=False)

    assert plan.total_records_scanned == 32
    assert plan.protected_system_records == 16
    assert plan.inactive_records_found == 15  # 32 - 16 - 1 (record 16 is active)
    assert 16 not in plan.eligible_records
    assert 17 in plan.eligible_records
    assert plan.volume_write_authority_qualified is True


def test_mft_live_system_disk_fail_closed():
    """Verify that live system disk target fails closed at qualification stage."""
    mft_stream = create_synthetic_mft_stream(32)
    res = MFTSanitizer.scrub_mft_stream(
        mft_stream,
        dry_run=False,
        confirm_mft_scrub=True,
        is_live_system_disk=True,  # Safety trigger
    )

    assert res.status == MFTSanitizeStatus.QUALIFICATION_BLOCKED
    assert res.records_scrubbed == 0
    assert "live system disk" in res.error_message


def test_mft_scrub_execution_structural_invariants():
    """Verify live MFT scrubbing zeroes deleted attribute payload while preserving FILE header."""
    mft_stream = create_synthetic_mft_stream(32)
    orig_mft = bytes(mft_stream)

    res = MFTSanitizer.scrub_mft_stream(
        mft_stream,
        dry_run=False,
        confirm_mft_scrub=True,
        is_live_system_disk=False,
    )

    assert res.status == MFTSanitizeStatus.SUCCESS
    assert res.records_scrubbed == 15
    assert res.records_skipped_protected == 16
    assert res.exact_readback_verified is True

    # 1. Verify protected system records 0-15 are 100% UNTOUCHED
    for i in range(16):
        assert mft_stream[i * 1024:(i + 1) * 1024] == orig_mft[i * 1024:(i + 1) * 1024]

    # 2. Verify active record 16 is 100% UNTOUCHED
    assert mft_stream[16 * 1024:17 * 1024] == orig_mft[16 * 1024:17 * 1024]

    # 3. Verify deleted record 17 header is preserved but attribute payload is ZEROED
    rec17 = bytes(mft_stream[17 * 1024:18 * 1024])
    assert rec17[:4] == b"FILE"  # Magic signature intact
    attr_offset = 56
    assert rec17[attr_offset:512] == b"\x00" * (512 - attr_offset)
