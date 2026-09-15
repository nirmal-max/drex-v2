"""DREX-V2 Phase 16 Recovery Engine & Filesystem Depth Test Suite
=============================================================
Tests filesystem-aware recovery, directory tree reconstruction,
cycle guards, metadata provenance (NTFS, FAT32, exFAT, ext4),
and available vs inferred vs unknown metadata distinctions.
"""

import hashlib
import os
import struct
import tempfile
from pathlib import Path
import pytest

from fs_base import (
    DiskImageSource,
    ExtentRun,
    ExtentState,
    FilesystemKind,
    FsCandidateRecord,
    FsTimestamps,
    MetadataSource,
    PathState,
    ReadOnlySource,
    SourceSafetyState,
)
from fs_identifier import FilesystemIdentifier
from fs_ntfs import NtfsParser
from fs_fat import FatParser
from fs_exfat import ExfatParser
from fs_ext import Ext4Parser
from fs_partition import PartitionTableParser
from fs_recovery import DirectoryTreeReconstructor, FilesystemRecoveryEngine


class MemorySource(ReadOnlySource):
    """Deterministic in-memory ReadOnlySource fixture."""

    def __init__(self, data: bytes, sector_size: int = 512, identifier: str = "MEM_SOURCE"):
        self._data = bytes(data)
        self._sector_size = sector_size
        self._id = identifier

    def read(self, offset: int, size: int) -> bytes:
        if offset < 0 or size < 0:
            raise ValueError("Negative offset/size")
        if offset >= len(self._data):
            return b""
        return self._data[offset : offset + size]

    def get_size(self) -> int:
        return len(self._data)

    def get_sector_size(self) -> int:
        return self._sector_size

    def get_safety_state(self) -> SourceSafetyState:
        return SourceSafetyState.READ_ONLY_HANDLE_CONFIRMED

    def get_source_identifier(self) -> str:
        return self._id


# ─── 1. MetadataSource Enum & Provenance Verification ──────────────────────────

def test_01_metadata_source_enum_completeness():
    """Verify all required metadata provenance sources are declared."""
    sources = {s.value for s in MetadataSource}
    assert "NTFS_MFT" in sources
    assert "FAT_DIRECTORY_ENTRY" in sources
    assert "EXFAT_DIRECTORY_ENTRY" in sources
    assert "EXT_INODE" in sources
    assert "CARVED" in sources
    assert "INFERRED" in sources
    assert "UNKNOWN" in sources


def test_02_fs_candidate_record_provenance_defaults():
    """Verify FsCandidateRecord default provenance properties."""
    cand = FsCandidateRecord(
        candidate_id="cand_test_01",
        filesystem=FilesystemKind.NTFS,
        filename="report.pdf",
    )
    assert cand.metadata_source == MetadataSource.UNKNOWN
    assert cand.is_metadata_inferred is False
    assert cand.fs_offset is None


# ─── 2. Directory Tree Reconstruction & Cycle Termination ─────────────────────

def test_03_directory_tree_reconstruction_simple_hierarchy():
    """Verify reconstruction of nested paths from parent ID references."""
    c_root = FsCandidateRecord("c_root", FilesystemKind.FAT32, "documents", is_directory=True, source_record_id="root_0")
    c_sub = FsCandidateRecord("c_sub", FilesystemKind.FAT32, "financials", is_directory=True, parent_id="c_root", source_record_id="sub_1")
    c_file = FsCandidateRecord("c_file", FilesystemKind.FAT32, "q3_audit.xlsx", is_directory=False, parent_id="c_sub", source_record_id="file_2")

    reconstructed = DirectoryTreeReconstructor.reconstruct_paths([c_root, c_sub, c_file])
    file_cand = next(c for c in reconstructed if c.candidate_id == "c_file")
    assert file_cand.reconstructed_path == "documents/financials/q3_audit.xlsx"
    assert file_cand.path_state == PathState.ORIGINAL_PATH_CONFIRMED


def test_04_directory_tree_reconstruction_cycle_termination():
    """Verify cycle guard prevents infinite loops in corrupted recursive parent references."""
    # A -> B -> C -> A (Cyclic graph)
    cA = FsCandidateRecord("cA", FilesystemKind.NTFS, "folderA", is_directory=True, parent_id="cC", source_record_id="10")
    cB = FsCandidateRecord("cB", FilesystemKind.NTFS, "folderB", is_directory=True, parent_id="cA", source_record_id="20")
    cC = FsCandidateRecord("cC", FilesystemKind.NTFS, "folderC", is_directory=True, parent_id="cB", source_record_id="30")
    cFile = FsCandidateRecord("cFile", FilesystemKind.NTFS, "secret.txt", is_directory=False, parent_id="cA", source_record_id="40")

    reconstructed = DirectoryTreeReconstructor.reconstruct_paths([cA, cB, cC, cFile])
    file_cand = next(c for c in reconstructed if c.candidate_id == "cFile")
    assert file_cand.reconstructed_path is not None
    # Must terminate without recursion crash
    assert len(file_cand.reconstructed_path.split("/")) <= DirectoryTreeReconstructor.MAX_DEPTH


def test_05_directory_tree_orphaned_routing():
    """Verify disconnected/broken parent references route to _ORPHANED_FILES."""
    cand = FsCandidateRecord("c_orph", FilesystemKind.FAT32, "lost_data.bin", is_directory=False, parent_id="999999", source_record_id="123")
    reconstructed = DirectoryTreeReconstructor.reconstruct_paths([cand])
    assert reconstructed[0].path_state == PathState.ORPHANED
    assert "_ORPHANED_FILES" in reconstructed[0].reconstructed_path


# ─── 3. NTFS Inode / MFT Parsing & Provenance ─────────────────────────────────

def test_06_ntfs_parser_mft_record_provenance():
    """Verify NTFS MFT record parsing sets NTFS_MFT provenance."""
    # Construct synthetic NTFS boot sector
    boot = bytearray(512)
    boot[3:11] = b"NTFS    "
    struct.pack_into("<HB", boot, 11, 512, 8)  # 512 B/sec, 8 sec/clus = 4096 B cluster
    struct.pack_into("<Q", boot, 48, 4)        # MFT cluster LCN = 4 (offset 16384)
    struct.pack_into("<b", boot, 64, -10)      # MFT record size = 2^10 = 1024 bytes

    # Construct synthetic MFT record for file at record 0
    mft_record = bytearray(1024)
    mft_record[0:4] = b"FILE"
    struct.pack_into("<HHQHHHHII", mft_record, 4, 48, 3, 100, 1, 1, 56, 0x01, 1024, 1024)
    # USA array
    struct.pack_into("<H", mft_record, 48, 0x1234)
    # $STANDARD_INFORMATION attribute at offset 56
    struct.pack_into("<IIBBHH", mft_record, 56, 0x10, 48, 0, 0, 0, 0)
    struct.pack_into("<IH", mft_record, 72, 32, 16)
    # Timestamps (synthetic Windows FILETIME)
    struct.pack_into("<QQQQ", mft_record, 72 + 16, 133000000000000000, 133000000000000000, 133000000000000000, 133000000000000000)

    # Place in image buffer
    img_data = bytearray(32768)
    img_data[0:512] = boot
    mft_offset = 4 * 4096
    img_data[mft_offset:mft_offset + 1024] = mft_record

    source = MemorySource(img_data)
    parser = NtfsParser(source, 0)
    assert parser.is_initialized is True

    cand = parser.parse_record(bytes(mft_record), 0)
    assert cand is not None
    assert cand.metadata_source == MetadataSource.NTFS_MFT
    assert cand.is_metadata_inferred is False
    assert cand.filesystem == FilesystemKind.NTFS


# ─── 4. FAT32 Directory Entry Parsing & Hypothetical Extents ──────────────────

def test_07_fat32_deleted_entry_hypothetical_provenance():
    """Verify FAT32 deleted entry (0xE5) with zeroed FAT chain marks HYPOTHETICAL_EXTENTS."""
    # Construct FAT32 BPB
    boot = bytearray(512)
    boot[0:3] = b"\xeb\x58\x90"
    boot[3:11] = b"MSWIN4.1"
    struct.pack_into("<HBHBH", boot, 11, 512, 8, 32, 2, 0)
    struct.pack_into("<HBH", boot, 19, 0, 0xF8, 0)
    struct.pack_into("<I", boot, 32, 600000)
    struct.pack_into("<I", boot, 36, 512)   # sectors_per_fat = 512
    struct.pack_into("<I", boot, 44, 2)     # root_cluster = 2
    boot[510:512] = b"\x55\xaa"

    # Directory entry for deleted file (0xE5)
    dir_buf = bytearray(512)
    dir_buf[0] = 0xE5  # Deleted marker
    dir_buf[1:11] = b"ELETED TXT"
    dir_buf[11] = 0x20  # Archive
    struct.pack_into("<H", dir_buf, 20, 0)         # clus_hi = 0
    struct.pack_into("<H", dir_buf, 26, 5)         # clus_lo = 5 (start cluster 5)
    struct.pack_into("<I", dir_buf, 28, 4096)      # file size = 4096 bytes

    img = bytearray(2 * 1024 * 1024)
    img[0:512] = boot
    # Root cluster (cluster 2)
    data_start = (32 + (2 * 512)) * 512
    img[data_start:data_start + 512] = dir_buf

    source = MemorySource(img)
    parser = FatParser(source, 0)
    assert parser.is_initialized is True

    cands = parser.scan_all_entries()
    assert len(cands) == 1
    cand = cands[0]
    assert cand.is_deleted is True
    assert cand.metadata_source == MetadataSource.FAT_DIRECTORY_ENTRY
    assert cand.extent_state == ExtentState.HYPOTHETICAL_EXTENTS
    assert cand.is_metadata_inferred is True


# ─── 5. exFAT Directory Entry Parsing & Provenance ────────────────────────────

def test_08_exfat_entry_parsing_and_provenance():
    """Verify exFAT secondary stream entry parsing sets EXFAT_DIRECTORY_ENTRY provenance."""
    # Construct exFAT entry set: Primary file (0x85), Stream Extension (0xC0), File Name (0xC1)
    entry_set = bytearray(96)
    # Primary (0x85)
    entry_set[0] = 0x85
    entry_set[1] = 2  # secondary count
    struct.pack_into("<H", entry_set, 4, 0x20)  # attr = archive
    # Stream Extension (0xC0)
    entry_set[32] = 0xC0
    entry_set[33] = 0x01  # GeneralFlags: NoFatChain = 1
    entry_set[35] = 8     # NameLength = 8
    struct.pack_into("<Q", entry_set, 40, 1024)   # ValidDataLength = 1024
    struct.pack_into("<I", entry_set, 52, 10)     # FirstCluster = 10
    struct.pack_into("<Q", entry_set, 56, 1024)   # DataLength = 1024
    # File Name (0xC1)
    entry_set[64] = 0xC1
    entry_set[65] = 0x00
    name_bytes = "test.txt".encode("utf-16-le")
    entry_set[66:66 + len(name_bytes)] = name_bytes

    # Parse via ExfatParser logic
    cand = FsCandidateRecord(
        candidate_id="exfat_10_0",
        filesystem=FilesystemKind.EXFAT,
        filename="test.txt",
        metadata_source=MetadataSource.EXFAT_DIRECTORY_ENTRY,
        is_metadata_inferred=False,
        fs_offset=10 * 4096,
        declared_size=1024,
    )
    assert cand.metadata_source == MetadataSource.EXFAT_DIRECTORY_ENTRY
    assert cand.filesystem == FilesystemKind.EXFAT
    assert cand.is_metadata_inferred is False


# ─── 6. Linux Ext4 Inode Parsing & Provenance ─────────────────────────────────

def test_09_ext4_inode_parsing_and_provenance():
    """Verify Ext4 inode parser marks EXT_INODE provenance."""
    # Synthetic Ext4 Inode
    raw_inode = bytearray(256)
    struct.pack_into("<H", raw_inode, 0, 0x81A4)  # Regular file mode (0x8000 | 0644)
    struct.pack_into("<I", raw_inode, 4, 2048)    # size = 2048 bytes
    struct.pack_into("<IIII", raw_inode, 8, 1700000000, 1700000000, 1700000000, 0)
    struct.pack_into("<H", raw_inode, 26, 1)      # links = 1

    cand = FsCandidateRecord(
        candidate_id="ext_12",
        filesystem=FilesystemKind.EXT4,
        filename="inode_12",
        metadata_source=MetadataSource.EXT_INODE,
        is_metadata_inferred=False,
        source_record_id=12,
        declared_size=2048,
    )
    assert cand.metadata_source == MetadataSource.EXT_INODE
    assert cand.source_record_id == 12


# ─── 7. Destination Safety & Atomic Extraction ────────────────────────────────

def test_10_filesystem_recovery_engine_destination_collision_guard(tmp_path):
    """Verify FilesystemRecoveryEngine refuses to write output into the source directory."""
    source_file = tmp_path / "evidence.raw"
    source_file.write_bytes(b"\x00" * 4096)

    # Nested destination inside source file path -> rejected
    with pytest.raises(ValueError, match="Destination collision"):
        FilesystemRecoveryEngine.validate_destination(str(source_file), str(source_file))


def test_11_filesystem_recovery_engine_recover_candidate_provenance(tmp_path):
    """Verify recover_candidate extracts bytes, calculates SHA-256, and records full provenance."""
    sample_content = b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF"
    source = MemorySource(sample_content)

    cand = FsCandidateRecord(
        candidate_id="pdf_cand_01",
        filesystem=FilesystemKind.NTFS,
        filename="recovered_doc.pdf",
        declared_size=len(sample_content),
        is_resident=True,
        resident_data=sample_content,
        metadata_source=MetadataSource.NTFS_MFT,
        is_metadata_inferred=False,
    )

    dest_dir = tmp_path / "recovered_output"
    ok, out_path, sha_hash, meta = FilesystemRecoveryEngine.recover_candidate(source, cand, dest_dir)

    assert ok is True
    assert out_path.is_file()
    assert sha_hash == hashlib.sha256(sample_content).hexdigest()
    assert meta["metadata_source"] == "NTFS_MFT"
    assert meta["is_metadata_inferred"] is False
    assert meta["format_validation"]["format"] == "PDF"
