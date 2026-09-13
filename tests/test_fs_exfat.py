"""
Acceptance Tests for Native exFAT Forensic Recovery Engine
File: tests/test_fs_exfat.py
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
from fs_exfat import ExfatParser


def create_synthetic_exfat_image() -> bytes:
    """Create a minimal synthetic exFAT image with VBR, Cluster Heap, Root Dir, and deleted Entry Sets."""
    sector_size = 512
    cluster_size = 4096  # 8 sectors per cluster (sec_shift=9, clus_shift=3)
    fat_offset_sec = 24
    fat_len_sec = 16
    cluster_heap_sec = 40
    cluster_count = 100

    image_size = (cluster_heap_sec + (20 * 8)) * sector_size
    image = bytearray(image_size)

    # 1. Volume Boot Record (VBR) at Sector 0
    vbr = bytearray(512)
    vbr[0:3] = b"\xeb\x76\x90"
    vbr[3:11] = b"EXFAT   "
    struct.pack_into("<I", vbr, 80, fat_offset_sec)      # FatOffset
    struct.pack_into("<I", vbr, 84, fat_len_sec)         # FatLength
    struct.pack_into("<I", vbr, 88, cluster_heap_sec)    # ClusterHeapOffset
    struct.pack_into("<I", vbr, 92, cluster_count)       # ClusterCount
    struct.pack_into("<I", vbr, 96, 2)                   # FirstClusterOfRootDir = 2
    vbr[108] = 9  # BytesPerSectorShift = 9 (512 bytes)
    vbr[109] = 3  # SectorsPerClusterShift = 3 (8 sectors/cluster -> 4096 bytes)
    vbr[510:512] = b"\x55\xaa"
    image[0:512] = vbr

    # 2. FAT Table at Sector 24
    fat_byte_offset = fat_offset_sec * sector_size
    # Cluster 2 (Root directory): EOF
    struct.pack_into("<I", image, fat_byte_offset + 8, 0xFFFFFFFF)
    # Cluster 5 & 7 (Fragmented File): Cluster 5 points to 7, Cluster 7 is EOF
    struct.pack_into("<I", image, fat_byte_offset + (5 * 4), 7)
    struct.pack_into("<I", image, fat_byte_offset + (7 * 4), 0xFFFFFFFF)

    # 3. Data Clusters in Cluster Heap
    heap_offset = cluster_heap_sec * sector_size

    def cluster_offset(clus: int) -> int:
        return heap_offset + ((clus - 2) * cluster_size)

    # Cluster 3: Contiguous active file (NoFatChain = 1)
    contig_content = b"EXFAT_CONTIGUOUS_ACTIVE_STREAM_DATA_CLUSTER_3_1234567890" * 20
    image[cluster_offset(3): cluster_offset(3) + len(contig_content)] = contig_content

    # Cluster 4: Deleted file (NoFatChain = 1, deleted entry set 0x05/0x40/0x41)
    deleted_content = b"EXFAT_DELETED_SENSITIVE_CASE_EVIDENCE_RECORD_2026.TXT" * 15
    image[cluster_offset(4): cluster_offset(4) + len(deleted_content)] = deleted_content

    # Cluster 5 & 7: Fragmented file (NoFatChain = 0)
    frag_part1 = (b"EXFAT_FRAGMENTED_PART_1_CLUSTER_5_" * 152)[:4096]
    frag_part2 = b"EXFAT_FRAGMENTED_PART_2_CLUSTER_7_" * 25
    image[cluster_offset(5): cluster_offset(5) + len(frag_part1)] = frag_part1
    image[cluster_offset(7): cluster_offset(7) + len(frag_part2)] = frag_part2

    # 4. Root Directory Entry Sets at Cluster 2
    root_offset = cluster_offset(2)

    # Entry Set 1: Contiguous Active File ("document.pdf", 0x85/0xC0/0xC1)
    _write_exfat_entry_set(
        image,
        offset=root_offset,
        filename="document.pdf",
        first_cluster=3,
        data_len=len(contig_content),
        no_fat_chain=True,
        is_deleted=False,
    )

    # Entry Set 2: Deleted Contiguous File ("deleted_case.txt", 0x05/0x40/0x41)
    _write_exfat_entry_set(
        image,
        offset=root_offset + 96,
        filename="deleted_case.txt",
        first_cluster=4,
        data_len=len(deleted_content),
        no_fat_chain=True,
        is_deleted=True,
    )

    # Entry Set 3: Fragmented Active File ("fragmented_exfat.bin", 0x85/0xC0/0xC1, NoFatChain=0)
    _write_exfat_entry_set(
        image,
        offset=root_offset + 224,
        filename="fragmented_exfat.bin",
        first_cluster=5,
        data_len=len(frag_part1) + len(frag_part2),
        no_fat_chain=False,
        is_deleted=False,
    )

    return bytes(image)


def _write_exfat_entry_set(
    image: bytearray,
    offset: int,
    filename: str,
    first_cluster: int,
    data_len: int,
    no_fat_chain: bool,
    is_deleted: bool = False,
) -> None:
    """Helper to synthesize an exFAT Entry Set (Primary, Stream, and File Name entries)."""
    # Split filename into 15-char chunks
    fn_chunks = [filename[i: i + 15] for i in range(0, len(filename), 15)]
    sec_count = 1 + len(fn_chunks)  # 1 stream extension + N filename entries

    # 1. Primary Directory Entry (32 bytes)
    prim = bytearray(32)
    prim[0] = 0x05 if is_deleted else 0x85  # Primary File Entry
    prim[1] = sec_count                     # SecondaryCount
    struct.pack_into("<H", prim, 4, 0x20)   # FileAttributes = Archive
    image[offset: offset + 32] = prim

    # 2. Stream Extension Entry (32 bytes)
    stream = bytearray(32)
    stream[0] = 0x40 if is_deleted else 0xC0  # Stream Extension Entry
    stream[1] = 0x03 if no_fat_chain else 0x01  # Bit 0=AllocPossible, Bit 1=NoFatChain
    stream[3] = len(filename)                 # NameLength
    struct.pack_into("<I", stream, 20, first_cluster)
    struct.pack_into("<Q", stream, 24, data_len)
    image[offset + 32: offset + 64] = stream

    # 3. File Name Directory Entries (32 bytes each)
    for idx, chunk in enumerate(fn_chunks):
        fn = bytearray(32)
        fn[0] = 0x41 if is_deleted else 0xC1  # File Name Entry
        fn[1] = 0x00
        name_utf16 = (chunk + "\x00" * 15)[:15].encode("utf-16-le")
        fn[2: 2 + len(name_utf16)] = name_utf16
        fn_offset = offset + 64 + (idx * 32)
        image[fn_offset: fn_offset + 32] = fn


def test_exfat_contiguous_active_recovery():
    """Verify exFAT NoFatChain contiguous stream parsing and byte-exact extraction."""
    image_bytes = create_synthetic_exfat_image()
    source = SyntheticFixtureSource(image_bytes)
    parser = ExfatParser(source, partition_offset=0)
    assert parser.is_initialized is True

    candidates = parser.scan_all_entries()
    assert len(candidates) >= 3

    doc_pdf = next(c for c in candidates if c.filename == "document.pdf")
    assert doc_pdf.is_deleted is False
    assert doc_pdf.extent_state == ExtentState.VERIFIED_EXTENTS
    assert len(doc_pdf.extents) == 1
    assert doc_pdf.extents[0].cluster_index == 3

    recovered = parser.read_candidate_bytes(doc_pdf)
    expected = b"EXFAT_CONTIGUOUS_ACTIVE_STREAM_DATA_CLUSTER_3_1234567890" * 20
    assert recovered == expected
    assert hashlib.sha256(recovered).hexdigest() == hashlib.sha256(expected).hexdigest()


def test_exfat_deleted_entry_set_recovery():
    """Verify deleted entry set (0x05/0x40/0x41) discovery and recovery."""
    image_bytes = create_synthetic_exfat_image()
    source = SyntheticFixtureSource(image_bytes)
    parser = ExfatParser(source, partition_offset=0)

    candidates = parser.scan_all_entries()
    del_file = next(c for c in candidates if c.filename == "deleted_case.txt")
    assert del_file.is_deleted is True
    assert del_file.extent_state == ExtentState.VERIFIED_EXTENTS

    recovered = parser.read_candidate_bytes(del_file)
    expected = b"EXFAT_DELETED_SENSITIVE_CASE_EVIDENCE_RECORD_2026.TXT" * 15
    assert recovered == expected
    assert hashlib.sha256(recovered).hexdigest() == hashlib.sha256(expected).hexdigest()


def test_exfat_fragmented_fat_chain_recovery():
    """Verify exFAT non-contiguous stream traversal via FAT table."""
    image_bytes = create_synthetic_exfat_image()
    source = SyntheticFixtureSource(image_bytes)
    parser = ExfatParser(source, partition_offset=0)

    candidates = parser.scan_all_entries()
    frag_file = next(c for c in candidates if c.filename == "fragmented_exfat.bin")
    assert frag_file.extent_state == ExtentState.FRAGMENTED_EXTENTS
    assert len(frag_file.extents) == 2
    assert frag_file.extents[0].cluster_index == 5
    assert frag_file.extents[1].cluster_index == 7

    recovered = parser.read_candidate_bytes(frag_file)
    expected_p1 = (b"EXFAT_FRAGMENTED_PART_1_CLUSTER_5_" * 152)[:4096]
    expected_p2 = b"EXFAT_FRAGMENTED_PART_2_CLUSTER_7_" * 25
    expected = expected_p1 + expected_p2
    assert recovered == expected
    assert hashlib.sha256(recovered).hexdigest() == hashlib.sha256(expected).hexdigest()
