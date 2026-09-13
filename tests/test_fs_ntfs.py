"""
Acceptance Tests for Native NTFS Forensic Recovery Engine
File: tests/test_fs_ntfs.py
Phase: 3 / 12
"""

import hashlib
import struct
import pytest

from fs_base import (
    ExtentState,
    FilesystemKind,
    FsCandidateRecord,
    PathState,
    SyntheticFixtureSource,
)
from fs_ntfs import NtfsParser


def create_synthetic_ntfs_image() -> bytes:
    """Create a minimal synthetic NTFS image with Boot sector, MFT records, resident and non-resident files."""
    sector_size = 512
    cluster_size = 4096
    total_clusters = 32
    image = bytearray(total_clusters * cluster_size)

    # 1. Boot Sector at Sector 0 (Cluster 0)
    boot = bytearray(512)
    boot[0:3] = b"\xeb\x52\x90"
    boot[3:11] = b"NTFS    "
    struct.pack_into("<HB", boot, 11, sector_size, 8)  # 512 bytes/sec, 8 sec/cluster -> 4096 cluster size
    struct.pack_into("<Q", boot, 48, 4)  # MFT starts at cluster 4 (offset 16384)
    struct.pack_into("<b", boot, 64, -10)  # MFT record size 2^10 = 1024 bytes
    boot[510:512] = b"\x55\xaa"
    image[0:512] = boot

    # 2. File Content Clusters
    # Cluster 8: Non-resident file 1 data
    file1_data = b"FORENSIC_EVIDENCE_NTFS_NON_RESIDENT_FILE_CONTENT_CLUSTER_8_DATA_1234567890" * 20
    image[8 * cluster_size: 8 * cluster_size + len(file1_data)] = file1_data

    # Cluster 10 & Cluster 12: Fragmented file data (cluster 10 is 4096 bytes, cluster 12 has remaining data)
    frag_part1 = (b"FRAGMENT_PART_1_CLUSTER_10_" * 152)[:4096]  # Exactly 4096 bytes
    frag_part2 = b"FRAGMENT_PART_2_CLUSTER_12_" * 30
    image[10 * cluster_size: 10 * cluster_size + len(frag_part1)] = frag_part1
    image[12 * cluster_size: 12 * cluster_size + len(frag_part2)] = frag_part2

    # 3. MFT Records at Cluster 4 (offset 16384)
    mft_offset = 4 * cluster_size

    # Record 0: Root directory (In-use Directory, flags=0x03)
    rec0 = _build_mft_record(record_idx=0, flags=0x03, filename=".", is_dir=True)
    image[mft_offset: mft_offset + 1024] = rec0

    # Record 1: Resident deleted file (Not-in-use File, flags=0x00)
    res_content = b"DELETED_RESIDENT_CONFIDENTIAL_FORENSIC_NOTE_2026.TXT"
    rec1 = _build_mft_record(
        record_idx=1,
        flags=0x00,
        filename="deleted_note.txt",
        is_dir=False,
        resident_data=res_content,
        parent_mft=5,
    )
    image[mft_offset + 1024: mft_offset + 2048] = rec1

    # Record 2: Non-resident in-use file (In-use File, flags=0x01, single cluster run at cluster 8)
    # Data run for Cluster 8, length 1 cluster: header 0x11, length 0x01, offset 0x08
    rec2 = _build_mft_record(
        record_idx=2,
        flags=0x01,
        filename="evidence.bin",
        is_dir=False,
        data_runs=bytes([0x11, 0x01, 0x08, 0x00]),
        real_size=len(file1_data),
        parent_mft=0,
    )
    image[mft_offset + 2048: mft_offset + 3072] = rec2

    # Record 3: Fragmented deleted file (Not-in-use File, flags=0x00, clusters 10 then +2 = 12)
    # Run 1: len 1, lcn 10 (0x11, 0x01, 0x0A)
    # Run 2: len 1, rel_lcn +2 (0x11, 0x01, 0x02)
    rec3 = _build_mft_record(
        record_idx=3,
        flags=0x00,
        filename="fragmented_deleted.dat",
        is_dir=False,
        data_runs=bytes([0x11, 0x01, 0x0A, 0x11, 0x01, 0x02, 0x00]),
        real_size=len(frag_part1) + len(frag_part2),
        parent_mft=0,
    )
    image[mft_offset + 3072: mft_offset + 4096] = rec3

    return bytes(image)


def _build_mft_record(
    record_idx: int,
    flags: int,
    filename: str,
    is_dir: bool = False,
    resident_data: bytes = None,
    data_runs: bytes = None,
    real_size: int = 0,
    parent_mft: int = 0,
) -> bytes:
    """Helper to synthesize a valid 1024-byte MFT record with USA fixup."""
    rec = bytearray(1024)
    rec[0:4] = b"FILE"
    usa_offset = 48
    usa_count = 3  # 1 update sequence number + 2 sector fixup values
    struct.pack_into("<HH", rec, 4, usa_offset, usa_count)
    struct.pack_into("<Q", rec, 8, 100)  # LSN
    struct.pack_into("<H", rec, 16, 1)   # Seq num
    struct.pack_into("<H", rec, 18, 1)   # Link count
    first_attr_offset = 56
    struct.pack_into("<H", rec, 20, first_attr_offset)
    struct.pack_into("<H", rec, 22, flags)  # Flags: bit 0 in-use, bit 1 directory
    struct.pack_into("<I", rec, 24, 1024)  # Real size
    struct.pack_into("<I", rec, 28, 1024)  # Alloc size

    # Set initial USA sequence number
    usa_num = b"\x42\x24"
    rec[usa_offset: usa_offset + 2] = usa_num
    # Original sector end bytes (will be placed at byte 510 and byte 1022 before fixup)
    orig_sec1 = b"\x11\x22"
    orig_sec2 = b"\x33\x44"
    rec[usa_offset + 2: usa_offset + 4] = orig_sec1
    rec[usa_offset + 4: usa_offset + 6] = orig_sec2

    # Put fixup signature at the end of each 512-byte sector
    rec[510:512] = usa_num
    rec[1022:1024] = usa_num

    offset = first_attr_offset

    # 1. $STANDARD_INFORMATION (0x10)
    std_attr_len = 72
    struct.pack_into("<I", rec, offset, 0x10)      # Type
    struct.pack_into("<I", rec, offset + 4, std_attr_len)
    rec[offset + 8] = 0                           # Resident
    struct.pack_into("<I", rec, offset + 16, 48)  # Value length
    struct.pack_into("<H", rec, offset + 20, 24)  # Value offset
    # Pack dummy timestamps
    ft_dummy = 133500000000000000
    struct.pack_into("<QQQQ", rec, offset + 24, ft_dummy, ft_dummy, ft_dummy, ft_dummy)
    offset += std_attr_len

    # 2. $FILE_NAME (0x30)
    fn_utf16 = filename.encode("utf-16-le")
    fn_val_len = 66 + len(fn_utf16)
    fn_attr_len = ((24 + fn_val_len + 7) // 8) * 8
    struct.pack_into("<I", rec, offset, 0x30)
    struct.pack_into("<I", rec, offset + 4, fn_attr_len)
    rec[offset + 8] = 0
    struct.pack_into("<I", rec, offset + 16, fn_val_len)
    struct.pack_into("<H", rec, offset + 20, 24)
    # File name content
    fn_data_offset = offset + 24
    struct.pack_into("<Q", rec, fn_data_offset, parent_mft)  # Parent MFT ref
    struct.pack_into("<QQQQ", rec, fn_data_offset + 8, ft_dummy, ft_dummy, ft_dummy, ft_dummy)
    struct.pack_into("<Q", rec, fn_data_offset + 40, real_size)  # Alloc size
    struct.pack_into("<Q", rec, fn_data_offset + 48, real_size)  # Real size
    rec[fn_data_offset + 64] = len(filename)                     # Filename len in chars
    rec[fn_data_offset + 65] = 0x03                              # Namespace Win32/DOS
    rec[fn_data_offset + 66: fn_data_offset + 66 + len(fn_utf16)] = fn_utf16
    offset += fn_attr_len

    # 3. $DATA (0x80)
    if resident_data is not None:
        data_val_len = len(resident_data)
        data_attr_len = ((24 + data_val_len + 7) // 8) * 8
        struct.pack_into("<I", rec, offset, 0x80)
        struct.pack_into("<I", rec, offset + 4, data_attr_len)
        rec[offset + 8] = 0  # Resident
        struct.pack_into("<I", rec, offset + 16, data_val_len)
        struct.pack_into("<H", rec, offset + 20, 24)
        rec[offset + 24: offset + 24 + data_val_len] = resident_data
        offset += data_attr_len
    elif data_runs is not None:
        run_len = len(data_runs)
        data_attr_len = ((64 + run_len + 7) // 8) * 8
        struct.pack_into("<I", rec, offset, 0x80)
        struct.pack_into("<I", rec, offset + 4, data_attr_len)
        rec[offset + 8] = 1  # Non-Resident
        struct.pack_into("<Q", rec, offset + 16, 0)  # Start VCN
        struct.pack_into("<Q", rec, offset + 24, 1)  # Last VCN
        struct.pack_into("<H", rec, offset + 32, 64) # Data runs offset
        struct.pack_into("<Q", rec, offset + 40, real_size) # Alloc size
        struct.pack_into("<Q", rec, offset + 48, real_size) # Real size
        struct.pack_into("<Q", rec, offset + 56, real_size) # Init size
        rec[offset + 64: offset + 64 + run_len] = data_runs
        offset += data_attr_len

    # End of attributes marker
    struct.pack_into("<I", rec, offset, 0xFFFFFFFF)

    return bytes(rec)


def test_ntfs_resident_file_recovery_byte_exact():
    """Verify byte-exact recovery of a deleted resident file from MFT record."""
    image_bytes = create_synthetic_ntfs_image()
    source = SyntheticFixtureSource(image_bytes)
    parser = NtfsParser(source, partition_offset=0)
    assert parser.is_initialized is True

    candidates = parser.scan_records(max_records=10)
    assert len(candidates) >= 4

    # Locate deleted resident note
    del_note = next(c for c in candidates if c.filename == "deleted_note.txt")
    assert del_note.is_deleted is True
    assert del_note.is_resident is True
    assert del_note.extent_state == ExtentState.RESIDENT_METADATA
    assert del_note.parent_id == "5"

    recovered_bytes = parser.read_candidate_bytes(del_note)
    expected_content = b"DELETED_RESIDENT_CONFIDENTIAL_FORENSIC_NOTE_2026.TXT"
    assert recovered_bytes == expected_content
    assert hashlib.sha256(recovered_bytes).hexdigest() == hashlib.sha256(expected_content).hexdigest()


def test_ntfs_nonresident_contiguous_data_runs_sha256():
    """Verify non-resident contiguous data run decoding and byte extraction."""
    image_bytes = create_synthetic_ntfs_image()
    source = SyntheticFixtureSource(image_bytes)
    parser = NtfsParser(source, partition_offset=0)

    candidates = parser.scan_records(max_records=10)
    evidence_bin = next(c for c in candidates if c.filename == "evidence.bin")
    assert evidence_bin.is_resident is False
    assert evidence_bin.is_deleted is False
    assert evidence_bin.extent_state == ExtentState.VERIFIED_EXTENTS
    assert len(evidence_bin.extents) == 1
    assert evidence_bin.extents[0].cluster_index == 8

    recovered = parser.read_candidate_bytes(evidence_bin)
    expected = b"FORENSIC_EVIDENCE_NTFS_NON_RESIDENT_FILE_CONTENT_CLUSTER_8_DATA_1234567890" * 20
    assert recovered == expected
    assert hashlib.sha256(recovered).hexdigest() == hashlib.sha256(expected).hexdigest()


def test_ntfs_nonresident_fragmented_data_runs_sha256():
    """Verify multi-run fragmented deleted file extraction."""
    image_bytes = create_synthetic_ntfs_image()
    source = SyntheticFixtureSource(image_bytes)
    parser = NtfsParser(source, partition_offset=0)

    candidates = parser.scan_records(max_records=10)
    frag_cand = next(c for c in candidates if c.filename == "fragmented_deleted.dat")
    assert frag_cand.is_deleted is True
    assert frag_cand.extent_state == ExtentState.FRAGMENTED_EXTENTS
    assert len(frag_cand.extents) == 2
    assert frag_cand.extents[0].cluster_index == 10
    assert frag_cand.extents[1].cluster_index == 12

    recovered = parser.read_candidate_bytes(frag_cand)
    expected_part1 = (b"FRAGMENT_PART_1_CLUSTER_10_" * 152)[:4096]
    expected_part2 = b"FRAGMENT_PART_2_CLUSTER_12_" * 30
    expected = expected_part1 + expected_part2
    assert recovered == expected
    assert hashlib.sha256(recovered).hexdigest() == hashlib.sha256(expected).hexdigest()


def test_ntfs_usa_fixup_validation_and_corruption():
    """Verify USA fixup application and detection of corrupted records."""
    image_bytes = bytearray(create_synthetic_ntfs_image())
    # Intentionally corrupt sector end signature in Record 1 (offset 16384 + 1024 + 510)
    corrupt_offset = (4 * 4096) + 1024 + 510
    image_bytes[corrupt_offset: corrupt_offset + 2] = b"\xFF\xFF"

    source = SyntheticFixtureSource(bytes(image_bytes))
    parser = NtfsParser(source, partition_offset=0)
    candidates = parser.scan_records(max_records=10)

    del_note = next(c for c in candidates if c.filename == "deleted_note.txt")
    assert "MFT_USA_FIXUP_MISMATCH" in del_note.limitations
