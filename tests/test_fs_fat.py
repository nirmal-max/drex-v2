"""
Acceptance Tests for Native FAT12 / FAT16 / FAT32 Forensic Recovery Engine
File: tests/test_fs_fat.py
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
from fs_fat import FatParser


def create_synthetic_fat32_image() -> bytes:
    """Create a minimal synthetic FAT32 image with BPB, FAT table, Root dir, and deleted entries."""
    sector_size = 512
    cluster_size = 4096  # 8 sectors per cluster
    total_clusters = 70000  # Ensure FAT32 cluster count threshold (> 65525)
    reserved_sectors = 32
    sectors_per_fat = 550
    num_fats = 2

    data_start_sec = reserved_sectors + (num_fats * sectors_per_fat)
    total_sectors = data_start_sec + (total_clusters * 8)

    # Allocate sparse-like bytearray for image (we only need the first 20 clusters in memory for testing)
    image_size = (data_start_sec + (20 * 8)) * sector_size
    image = bytearray(image_size)

    # 1. Boot Sector at Sector 0
    boot = bytearray(512)
    boot[0:3] = b"\xeb\x58\x90"
    boot[3:11] = b"MSDOS5.0"
    struct.pack_into("<HBHBH", boot, 11, sector_size, 8, reserved_sectors, num_fats, 0)
    struct.pack_into("<HsH", boot, 19, 0, b"\xf8", 0)
    struct.pack_into("<I", boot, 32, total_sectors)
    struct.pack_into("<I", boot, 36, sectors_per_fat)
    struct.pack_into("<I", boot, 44, 2)  # Root cluster = 2
    boot[82:90] = b"FAT32   "
    boot[510:512] = b"\x55\xaa"
    image[0:512] = boot

    # 2. FAT Table at reserved_sectors (Sector 32)
    fat_offset = reserved_sectors * sector_size
    # Cluster 0 & 1 reserved
    struct.pack_into("<I", image, fat_offset + 0, 0x0FFFFFF8)
    struct.pack_into("<I", image, fat_offset + 4, 0x0FFFFFFF)
    # Cluster 2 (Root directory): EOF
    struct.pack_into("<I", image, fat_offset + 8, 0x0FFFFFFF)
    # Cluster 3 (Active file 1): Single cluster EOF
    struct.pack_into("<I", image, fat_offset + 12, 0x0FFFFFFF)
    # Cluster 4 (Active fragmented file part 1): Points to cluster 6
    struct.pack_into("<I", image, fat_offset + 16, 6)
    # Cluster 6 (Active fragmented file part 2): Points to EOF
    struct.pack_into("<I", image, fat_offset + 24, 0x0FFFFFFF)
    # Cluster 8 (Deleted file with zeroed FAT chain): FAT entry is 0x00000000
    struct.pack_into("<I", image, fat_offset + 32, 0x00000000)

    # Mirror to FAT 2
    fat2_offset = fat_offset + (sectors_per_fat * sector_size)
    image[fat2_offset: fat2_offset + 128] = image[fat_offset: fat_offset + 128]

    # 3. Data Area Clusters
    data_start_offset = data_start_sec * sector_size

    # Helper to get cluster byte offset
    def cluster_offset(clus: int) -> int:
        return data_start_offset + ((clus - 2) * cluster_size)

    # Cluster 3: Active File Content
    active_content = b"ACTIVE_CONFIDENTIAL_FORENSIC_DOCUMENT_CONTENT_CLUSTER_3_12345" * 10
    image[cluster_offset(3): cluster_offset(3) + len(active_content)] = active_content

    # Cluster 4 & 6: Fragmented File Content
    frag_part1 = (b"FAT32_FRAGMENT_PART_1_CLUSTER_4_" * 152)[:4096]
    frag_part2 = b"FAT32_FRAGMENT_PART_2_CLUSTER_6_" * 20
    image[cluster_offset(4): cluster_offset(4) + len(frag_part1)] = frag_part1
    image[cluster_offset(6): cluster_offset(6) + len(frag_part2)] = frag_part2

    # Cluster 8: Deleted File with Zeroed Chain
    deleted_content = b"DELETED_EVIDENCE_FROM_ZEROED_FAT_CHAIN_HYPOTHESIS_NOTE_2026.LOG" * 15
    image[cluster_offset(8): cluster_offset(8) + len(deleted_content)] = deleted_content

    # 4. Root Directory Entries at Cluster 2
    root_offset = cluster_offset(2)

    # Entry 1: Active File with LFN ("Forensic_Evidence_Report_2026.docx")
    lfn_text = "Forensic_Evidence_Report_2026.docx"
    _write_lfn_and_entry(
        image,
        offset=root_offset,
        lfn_name=lfn_text,
        short_name="FORENS~1DOC",
        start_cluster=3,
        file_size=len(active_content),
        is_deleted=False,
    )

    # Entry 2: Deleted File with Zeroed Chain ("deleted_audit.log", 0xE5 marker)
    _write_lfn_and_entry(
        image,
        offset=root_offset + 64,
        lfn_name="deleted_audit.log",
        short_name="DELE_~1LOG",
        start_cluster=8,
        file_size=len(deleted_content),
        is_deleted=True,
    )

    # Entry 3: Fragmented Active File ("fragmented.bin")
    _write_lfn_and_entry(
        image,
        offset=root_offset + 128,
        lfn_name="fragmented.bin",
        short_name="FRAGME~1BIN",
        start_cluster=4,
        file_size=len(frag_part1) + len(frag_part2),
        is_deleted=False,
    )

    return bytes(image)


def _write_lfn_and_entry(
    image: bytearray,
    offset: int,
    lfn_name: str,
    short_name: str,
    start_cluster: int,
    file_size: int,
    is_deleted: bool = False,
) -> None:
    """Helper to write 32-byte LFN entry followed by 32-byte 8.3 entry."""
    raw_sname = (short_name + " " * 11)[:11].encode("latin1")
    lfn_chk = FatParser.compute_lfn_checksum(raw_sname)

    # Write LFN entry (sequence 1, last entry 0x41)
    lfn_entry = bytearray(32)
    lfn_entry[0] = 0x41 if not is_deleted else 0xE5
    # Pack up to 13 characters
    name_utf16 = (lfn_name[:13] + "\x00" * 13)[:13].encode("utf-16-le")
    lfn_entry[1:11] = name_utf16[0:10]
    lfn_entry[11] = 0x0F  # ATTR_LONG_NAME
    lfn_entry[12] = 0x00
    lfn_entry[13] = lfn_chk  # Valid Checksum
    lfn_entry[14:26] = name_utf16[10:22]
    lfn_entry[26:28] = b"\x00\x00"
    lfn_entry[28:32] = name_utf16[22:26]
    image[offset: offset + 32] = lfn_entry

    # Write Short Entry
    entry = bytearray(32)
    entry[0:11] = raw_sname
    if is_deleted:
        entry[0] = 0xE5

    entry[11] = 0x20  # ATTR_ARCHIVE
    clus_hi = (start_cluster >> 16) & 0xFFFF
    clus_lo = start_cluster & 0xFFFF
    struct.pack_into("<H", entry, 20, clus_hi)
    struct.pack_into("<H", entry, 26, clus_lo)
    struct.pack_into("<I", entry, 28, file_size)
    image[offset + 32: offset + 64] = entry


def test_fat32_lfn_unicode_and_active_recovery():
    """Verify LFN Unicode reassembly and active cluster chain extraction."""
    image_bytes = create_synthetic_fat32_image()
    source = SyntheticFixtureSource(image_bytes)
    parser = FatParser(source, partition_offset=0)
    assert parser.is_initialized is True
    assert parser.fat_kind == FilesystemKind.FAT32

    candidates = parser.scan_all_entries()
    assert len(candidates) >= 3

    active_file = next(c for c in candidates if "Forensic" in c.filename)
    assert active_file.is_deleted is False
    assert active_file.extent_state == ExtentState.VERIFIED_EXTENTS
    assert len(active_file.extents) == 1

    recovered = parser.read_candidate_bytes(active_file)
    expected = b"ACTIVE_CONFIDENTIAL_FORENSIC_DOCUMENT_CONTENT_CLUSTER_3_12345" * 10
    assert recovered == expected
    assert hashlib.sha256(recovered).hexdigest() == hashlib.sha256(expected).hexdigest()


def test_fat32_deleted_zeroed_chain_hypothesis():
    """Verify deleted file with zeroed FAT chain retains HYPOTHETICAL_EXTENTS state."""
    image_bytes = create_synthetic_fat32_image()
    source = SyntheticFixtureSource(image_bytes)
    parser = FatParser(source, partition_offset=0)

    candidates = parser.scan_all_entries()
    del_file = next(c for c in candidates if "deleted_audit" in c.filename or "DELE_" in c.filename)
    assert del_file.is_deleted is True
    assert del_file.extent_state == ExtentState.HYPOTHETICAL_EXTENTS
    assert "FAT_CHAIN_ZEROED_HYPOTHESIS" in del_file.limitations
    assert del_file.extents[0].is_hypothetical is True

    recovered = parser.read_candidate_bytes(del_file)
    expected = b"DELETED_EVIDENCE_FROM_ZEROED_FAT_CHAIN_HYPOTHESIS_NOTE_2026.LOG" * 15
    assert recovered == expected


def test_fat32_fragmented_chain_recovery():
    """Verify non-contiguous multi-cluster FAT chain reassembly."""
    image_bytes = create_synthetic_fat32_image()
    source = SyntheticFixtureSource(image_bytes)
    parser = FatParser(source, partition_offset=0)

    candidates = parser.scan_all_entries()
    frag_file = next(c for c in candidates if "fragmented" in c.filename)
    assert frag_file.extent_state == ExtentState.FRAGMENTED_EXTENTS
    assert len(frag_file.extents) == 2
    assert frag_file.extents[0].cluster_index == 4
    assert frag_file.extents[1].cluster_index == 6

    recovered = parser.read_candidate_bytes(frag_file)
    expected_p1 = (b"FAT32_FRAGMENT_PART_1_CLUSTER_4_" * 152)[:4096]
    expected_p2 = b"FAT32_FRAGMENT_PART_2_CLUSTER_6_" * 20
    expected = expected_p1 + expected_p2
    assert recovered == expected
    assert hashlib.sha256(recovered).hexdigest() == hashlib.sha256(expected).hexdigest()


def test_fat_lfn_checksum_mismatch_fallback():
    """Verify active file with corrupted LFN checksum falls back to short 8.3 name."""
    image_bytes = bytearray(create_synthetic_fat32_image())
    # In Entry 1 (offset at cluster 2 = 32 * 512 + 2 * 550 * 512 = 579584), corrupt LFN checksum byte at offset + 13
    # Find active file LFN checksum and corrupt it to 0xFF
    source_clean = SyntheticFixtureSource(bytes(image_bytes))
    parser_clean = FatParser(source_clean, 0)
    root_offset = parser_clean.cluster_to_byte_offset(2)
    image_bytes[root_offset + 13] = 0xAA  # Invalid checksum

    source_corrupt = SyntheticFixtureSource(bytes(image_bytes))
    parser_corrupt = FatParser(source_corrupt, 0)
    candidates = parser_corrupt.scan_all_entries()

    # Should fall back to 8.3 short name "FORENS~1.DOC" instead of "Forensic_Evidence_Report_2026.docx"
    short_cand = next(c for c in candidates if "FORENS~1" in c.filename)
    assert short_cand is not None
    assert short_cand.filename == "FORENS~1.DOC"
