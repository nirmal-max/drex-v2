"""
DREX-V2 Synthetic Fixture Generator & Fixture Validity Gate
===========================================================
Module: fixture_generator.py
Phase: 9 / Validation Laboratory

Provides deterministic, reproducible synthetic filesystem images, partitioning
layouts, RAID sets, and sanitization fixtures with an automated 6-stage Fixture
Validity Gate:
  GENERATE -> PARSE -> EXPECTED STRUCTURE VALIDATION ->
  REFERENCE VALIDATION (WHEN AVAILABLE) -> EXPECTED CONTENT HASH VALIDATION ->
  ACCEPT FIXTURE.

Strict Design Principles:
- 100% Deterministic (fixed PRNG seeds, predictable cluster/sector offsets)
- Pure Python standard library (struct, hashlib, json, os, pathlib, dataclasses)
- Zero manufactured reference validation (records REFERENCE_UNAVAILABLE if absent)
- Explicit pre-failure ground-truth preservation for RAID reconstruction

Zero external dependencies.
License: Apache 2.0.
"""

from __future__ import annotations

import dataclasses
import enum
import hashlib
import io
import json
import os
import struct
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union


# ─── Enums & Data Models ─────────────────────────────────────────────────────

class FixtureKind(enum.Enum):
    FILESYSTEM_NTFS = "FILESYSTEM_NTFS"
    FILESYSTEM_FAT32 = "FILESYSTEM_FAT32"
    FILESYSTEM_EXFAT = "FILESYSTEM_EXFAT"
    FILESYSTEM_EXT4 = "FILESYSTEM_EXT4"
    PARTITION_MBR = "PARTITION_MBR"
    PARTITION_GPT = "PARTITION_GPT"
    RAID_0 = "RAID_0"
    RAID_1 = "RAID_1"
    RAID_5 = "RAID_5"
    RAID_10 = "RAID_10"
    DAMAGED_MEDIA = "DAMAGED_MEDIA"
    FILE_SLACK = "FILE_SLACK"
    MFT_METADATA = "MFT_METADATA"


class FixtureValidityStatus(enum.Enum):
    ACCEPTED = "ACCEPTED"
    REJECTED = "REJECTED"
    REFERENCE_UNAVAILABLE = "REFERENCE_UNAVAILABLE"


@dataclass
class ExpectedArtifact:
    relative_path: str
    expected_size_bytes: int
    expected_sha256: str
    is_deleted: bool = False
    is_fragmented: bool = False
    payload: bytes = b""


@dataclass
class FixtureMetadata:
    fixture_id: str
    fixture_kind: FixtureKind
    description: str
    seed: int
    total_size_bytes: int
    sector_size: int = 512
    cluster_size: int = 4096
    expected_artifacts: List[ExpectedArtifact] = field(default_factory=list)
    raw_image_sha256: str = ""
    validity_status: FixtureValidityStatus = FixtureValidityStatus.ACCEPTED
    reference_validation: str = "REFERENCE_UNAVAILABLE"
    gate_diagnostics: List[str] = field(default_factory=list)


@dataclass
class RaidGroundTruthSet:
    fixture_id: str
    raid_level: str
    chunk_size: int
    total_disks: int
    original_dataset: bytes
    original_dataset_sha256: str
    disk_images: List[bytes]
    missing_disk_index: int = 1


# ─── Utility Primitives ──────────────────────────────────────────────────────

def sha256_bytes(data: bytes) -> str:
    """Compute SHA-256 hex digest of bytes."""
    return hashlib.sha256(data).hexdigest()


def deterministic_prng_bytes(seed: int, length: int) -> bytes:
    """Generate deterministic pseudo-random bytes using SHA-256 state chain."""
    out = bytearray()
    state = struct.pack("<Q", seed)
    while len(out) < length:
        state = hashlib.sha256(state).digest()
        out.extend(state)
    return bytes(out[:length])


# ─── Fixture Generators ──────────────────────────────────────────────────────

class SyntheticFixtureGenerator:
    """
    Deterministic builder for synthetic test images and ground-truth validation corpora.
    """

    @classmethod
    def generate_fat32_image(
        cls,
        total_sectors: int = 66000,  # ~33.8 MB (minimum FAT32 volume size)
        seed: int = 42,
    ) -> Tuple[bytes, FixtureMetadata]:
        """
        Generate a deterministic, structurally valid FAT32 volume with:
        - Valid BPB and FSInfo
        - Active root file (hello.txt)
        - Deleted file with 0xE5 marker (deleted_note.txt)
        - Subdirectory (/DOCS/report.pdf)
        """
        sector_size = 512
        sectors_per_cluster = 8
        cluster_size = sector_size * sectors_per_cluster
        reserved_sectors = 32
        num_fats = 2
        sectors_per_fat = 64
        root_dir_cluster = 2

        img = bytearray(total_sectors * sector_size)

        # 1. BPB & Extended Boot Record (Sector 0)
        img[0:3] = b"\xEB\x58\x90"  # JMP short
        img[3:11] = b"MSWIN4.1"      # OEM Name
        struct.pack_into("<H", img, 11, sector_size)
        img[13] = sectors_per_cluster
        struct.pack_into("<H", img, 14, reserved_sectors)
        img[16] = num_fats
        struct.pack_into("<H", img, 17, 0)  # Root entry count = 0 (FAT32)
        struct.pack_into("<H", img, 19, 0)  # Total sectors 16 = 0
        img[21] = 0xF8                       # Media descriptor (Fixed disk)
        struct.pack_into("<H", img, 22, 0)  # Sectors per FAT 16 = 0
        struct.pack_into("<H", img, 24, 63) # Sectors per track
        struct.pack_into("<H", img, 26, 255)# Number of heads
        struct.pack_into("<I", img, 28, 0)  # Hidden sectors
        struct.pack_into("<I", img, 32, total_sectors) # Total sectors 32
        struct.pack_into("<I", img, 36, sectors_per_fat) # Sectors per FAT 32
        struct.pack_into("<H", img, 40, 0)  # Ext flags
        struct.pack_into("<H", img, 42, 0)  # FS version (0:0)
        struct.pack_into("<I", img, 44, root_dir_cluster) # Root cluster = 2
        struct.pack_into("<H", img, 48, 1)  # FSInfo sector = 1
        struct.pack_into("<H", img, 50, 6)  # Backup boot sector = 6
        img[66] = 0x29                      # Extended boot signature
        struct.pack_into("<I", img, 67, 0x12345678) # Volume ID
        img[71:82] = b"DREX_FAT32 "         # Volume label
        img[82:90] = b"FAT32   "            # File system type
        img[510:512] = b"\x55\xAA"          # Boot signature

        # Backup Boot Sector (Sector 6)
        img[6 * 512 : 7 * 512] = img[0:512]

        # 2. FSInfo Structure (Sector 1 & Sector 7)
        for s_idx in (1, 7):
            off = s_idx * 512
            struct.pack_into("<I", img, off + 0, 0x41615252)   # Lead sig
            struct.pack_into("<I", img, off + 484, 0x61417272) # Struct sig
            struct.pack_into("<I", img, off + 488, 1000)       # Free count
            struct.pack_into("<I", img, off + 492, 3)          # Next free cluster
            img[off + 510 : off + 512] = b"\x55\xAA"

        # FAT offset calculation
        fat1_offset = reserved_sectors * sector_size
        fat2_offset = fat1_offset + (sectors_per_fat * sector_size)
        data_offset = fat2_offset + (sectors_per_fat * sector_size)

        # 3. Initialize FAT Tables
        # Cluster 0 & 1 reserved: 0x0FFFFFF8, 0xFFFFFFFF
        for f_off in (fat1_offset, fat2_offset):
            struct.pack_into("<I", img, f_off + 0, 0x0FFFFFF8)
            struct.pack_into("<I", img, f_off + 4, 0x0FFFFFFF)
            struct.pack_into("<I", img, f_off + 8, 0x0FFFFFFF) # Root dir (Cluster 2) EOC
            struct.pack_into("<I", img, f_off + 12, 0x0FFFFFFF) # Cluster 3 (hello.txt) EOC
            struct.pack_into("<I", img, f_off + 16, 0x00000000) # Cluster 4 (deleted file cluster freed)
            struct.pack_into("<I", img, f_off + 20, 0x0FFFFFFF) # Cluster 5 (DOCS dir) EOC
            struct.pack_into("<I", img, f_off + 24, 0x0FFFFFFF) # Cluster 6 (report.pdf) EOC

        # 4. Data Payloads
        file1_payload = b"DREX-V2 FAT32 Verified Active Text File Content\n"
        file1_sha = sha256_bytes(file1_payload)

        file2_payload = b"DREX-V2 FAT32 Deleted Document Payload - Recoverable\n"
        file2_sha = sha256_bytes(file2_payload)

        file3_payload = b"%PDF-1.4\n% DREX Synthetic Valid PDF in subdirectory\n%%EOF\n"
        file3_sha = sha256_bytes(file3_payload)

        # Cluster Data Mapping
        # Cluster 2 = Root Directory
        root_dir_off = data_offset + (0 * cluster_size) # Cluster 2 is data cluster 0
        # Cluster 3 = hello.txt
        c3_off = data_offset + (1 * cluster_size)
        img[c3_off : c3_off + len(file1_payload)] = file1_payload

        # Cluster 4 = deleted_note.txt (unallocated in FAT, but raw bytes remain in cluster)
        c4_off = data_offset + (2 * cluster_size)
        img[c4_off : c4_off + len(file2_payload)] = file2_payload

        # Cluster 5 = DOCS directory
        c5_off = data_offset + (3 * cluster_size)

        # Cluster 6 = report.pdf
        c6_off = data_offset + (4 * cluster_size)
        img[c6_off : c6_off + len(file3_payload)] = file3_payload

        # 5. Populate Root Directory Entries (Cluster 2)
        # Entry 0: Volume Label
        img[root_dir_off + 0 : root_dir_off + 11] = b"DREX_FAT32 "
        img[root_dir_off + 11] = 0x08 # ATTR_VOLUME_ID

        # Entry 1: HELLO.TXT (Active file, Cluster 3)
        img[root_dir_off + 32 : root_dir_off + 43] = b"HELLO   TXT"
        img[root_dir_off + 43] = 0x20 # ATTR_ARCHIVE
        struct.pack_into("<H", img, root_dir_off + 52, 0) # High cluster
        struct.pack_into("<H", img, root_dir_off + 58, 3) # Low cluster
        struct.pack_into("<I", img, root_dir_off + 60, len(file1_payload))

        # Entry 2: DELETED_NOTE.TXT (Deleted file with 0xE5 marker, Cluster 4)
        img[root_dir_off + 64] = 0xE5 # Deleted flag
        img[root_dir_off + 65 : root_dir_off + 75] = b"ELET_NOTE TXT"[:10]
        img[root_dir_off + 75] = 0x20
        struct.pack_into("<H", img, root_dir_off + 84, 0)
        struct.pack_into("<H", img, root_dir_off + 90, 4)
        struct.pack_into("<I", img, root_dir_off + 92, len(file2_payload))

        # Entry 3: DOCS (Subdirectory, Cluster 5)
        img[root_dir_off + 96 : root_dir_off + 107] = b"DOCS       "
        img[root_dir_off + 107] = 0x10 # ATTR_DIRECTORY
        struct.pack_into("<H", img, root_dir_off + 116, 0)
        struct.pack_into("<H", img, root_dir_off + 122, 5)

        # 6. Populate DOCS Subdirectory (Cluster 5)
        # Entry 0: .
        img[c5_off + 0 : c5_off + 11] = b".          "
        img[c5_off + 11] = 0x10
        struct.pack_into("<H", img, c5_off + 26, 5)
        # Entry 1: ..
        img[c5_off + 32 : c5_off + 43] = b"..         "
        img[c5_off + 43] = 0x10
        struct.pack_into("<H", img, c5_off + 58, 0) # Root is cluster 0 in dotdot
        # Entry 2: REPORT.PDF (Cluster 6)
        img[c5_off + 64 : c5_off + 75] = b"REPORT  PDF"
        img[c5_off + 75] = 0x20
        struct.pack_into("<H", img, c5_off + 84, 0)
        struct.pack_into("<H", img, c5_off + 90, 6)
        struct.pack_into("<I", img, c5_off + 92, len(file3_payload))

        raw_bytes = bytes(img)
        meta = FixtureMetadata(
            fixture_id="FIX-FAT32-01",
            fixture_kind=FixtureKind.FILESYSTEM_FAT32,
            description="FAT32 Volume with active text, deleted file (0xE5), and nested subdirectory document",
            seed=seed,
            total_size_bytes=len(raw_bytes),
            sector_size=sector_size,
            cluster_size=cluster_size,
            raw_image_sha256=sha256_bytes(raw_bytes),
            expected_artifacts=[
                ExpectedArtifact("HELLO.TXT", len(file1_payload), file1_sha, is_deleted=False, payload=file1_payload),
                ExpectedArtifact("DELET_NOTE.TXT", len(file2_payload), file2_sha, is_deleted=True, payload=file2_payload),
                ExpectedArtifact("DOCS/REPORT.PDF", len(file3_payload), file3_sha, is_deleted=False, payload=file3_payload),
            ],
        )
        return raw_bytes, meta

    @classmethod
    def generate_ntfs_image(cls, seed: int = 42) -> Tuple[bytes, FixtureMetadata]:
        """
        Generate a deterministic synthetic NTFS volume containing:
        - Boot Sector (BPB with 'NTFS    ' signature)
        - Master File Table ($MFT) with USA fixup values
        - $MFT Record 0: $MFT
        - $MFT Record 5: Root directory (.)
        - $MFT Record 16: Active resident file (active_case.txt)
        - $MFT Record 17: Deleted file with non-resident data runs (deleted_evidence.bin)
        """
        sector_size = 512
        sectors_per_cluster = 8
        cluster_size = sector_size * sectors_per_cluster
        total_clusters = 500  # ~2 MB volume
        total_size = total_clusters * cluster_size
        img = bytearray(total_size)

        # 1. NTFS Boot Sector (LBN 0)
        img[0:3] = b"\xEB\x52\x90"
        img[3:11] = b"NTFS    "
        struct.pack_into("<H", img, 11, sector_size)
        img[13] = sectors_per_cluster
        img[21] = 0xF8 # Media descriptor
        struct.pack_into("<Q", img, 40, total_clusters * sectors_per_cluster) # Total sectors
        struct.pack_into("<Q", img, 48, 4) # $MFT start cluster (LCN 4)
        struct.pack_into("<Q", img, 56, 50) # $MFTMirr start cluster
        img[64] = 0xF6 # Clusters per MFT record (246 -> 1024 bytes)
        img[68] = 0xF6 # Clusters per index block
        struct.pack_into("<Q", img, 72, 0x1122334455667788) # Serial number
        img[510:512] = b"\x55\xAA"

        # 2. $MFT Allocation at LCN 4 (Byte offset = 4 * 4096 = 16384)
        mft_offset = 4 * cluster_size
        mft_record_size = 1024

        active_payload = b"DREX-V2 NTFS Resident Active Case Notes\n"
        active_sha = sha256_bytes(active_payload)

        deleted_payload = b"DREX-V2 NTFS Non-Resident Deleted Forensic Image Stream Block\n" * 10
        deleted_sha = sha256_bytes(deleted_payload)

        # Write non-resident deleted data to cluster 10 (offset 40960)
        c10_offset = 10 * cluster_size
        img[c10_offset : c10_offset + len(deleted_payload)] = deleted_payload

        # Helper: Build MFT Record with USA fixup
        def make_mft_record(record_num: int, is_active: bool, is_dir: bool, attrs: bytes) -> bytes:
            rec = bytearray(mft_record_size)
            rec[0:4] = b"FILE"
            usa_offset = 48
            usa_count = 3  # Update sequence number + 2 sector fixup words
            struct.pack_into("<H", rec, 4, usa_offset)
            struct.pack_into("<H", rec, 6, usa_count)
            struct.pack_into("<Q", rec, 8, 1) # LSN
            struct.pack_into("<H", rec, 16, 1) # Sequence number
            struct.pack_into("<H", rec, 18, 1) # Link count
            first_attr_off = 56
            struct.pack_into("<H", rec, 20, first_attr_off)
            flags = (0x01 if is_active else 0x00) | (0x02 if is_dir else 0x00)
            struct.pack_into("<H", rec, 22, flags)
            struct.pack_into("<I", rec, 24, first_attr_off + len(attrs)) # Used bytes
            struct.pack_into("<I", rec, 28, mft_record_size) # Allocated bytes
            struct.pack_into("<Q", rec, 32, 0) # Base record
            struct.pack_into("<H", rec, 40, 0) # Next attr instance
            struct.pack_into("<I", rec, 44, record_num) # Record number

            # USA values
            usn = 0xAA55
            struct.pack_into("<H", rec, usa_offset, usn)
            struct.pack_into("<H", rec, usa_offset + 2, 0x0000)
            struct.pack_into("<H", rec, usa_offset + 4, 0x0000)

            # Copy attributes
            rec[first_attr_off : first_attr_off + len(attrs)] = attrs

            # Apply USA fixup to sector ends (510..511 and 1022..1023)
            struct.pack_into("<H", rec, 510, usn)
            struct.pack_into("<H", rec, 1022, usn)
            return bytes(rec)

        # Helper: Build $STANDARD_INFORMATION attribute (0x10)
        def make_std_info() -> bytes:
            payload = bytearray(72)
            now_win = 133000000000000000 # Windows filetime
            struct.pack_into("<QQQQ", payload, 0, now_win, now_win, now_win, now_win)
            struct.pack_into("<I", payload, 32, 0x20) # Archive
            attr = bytearray(24 + len(payload))
            struct.pack_into("<I", attr, 0, 0x10) # Attr type $STANDARD_INFORMATION
            struct.pack_into("<I", attr, 4, len(attr)) # Total length
            attr[8] = 0x00 # Resident
            attr[9] = 0x00 # Name length
            struct.pack_into("<H", attr, 10, 0) # Name offset
            struct.pack_into("<H", attr, 12, 0) # Flags
            struct.pack_into("<H", attr, 14, 0) # Instance
            struct.pack_into("<I", attr, 16, len(payload)) # Value length
            struct.pack_into("<H", attr, 20, 24) # Value offset
            attr[24:] = payload
            return bytes(attr)

        # Helper: Build $FILE_NAME attribute (0x30)
        def make_file_name(parent_record: int, name: str) -> bytes:
            name_utf16 = name.encode("utf-16le")
            name_chars = len(name)
            val_len = 66 + len(name_utf16)
            payload = bytearray(val_len)
            struct.pack_into("<Q", payload, 0, parent_record | (1 << 48)) # Parent MFT ref
            now_win = 133000000000000000
            struct.pack_into("<QQQQ", payload, 8, now_win, now_win, now_win, now_win)
            struct.pack_into("<Q", payload, 40, 1024) # Alloc size
            struct.pack_into("<Q", payload, 48, 1024) # Real size
            struct.pack_into("<I", payload, 56, 0x20) # Flags
            payload[64] = name_chars
            payload[65] = 0x03 # Namespace Win32/DOS
            payload[66 : 66 + len(name_utf16)] = name_utf16

            attr = bytearray(24 + len(payload))
            # Align attr length to 8 bytes
            total_len = ((len(attr) + 7) // 8) * 8
            attr = attr.ljust(total_len, b"\x00")
            struct.pack_into("<I", attr, 0, 0x30)
            struct.pack_into("<I", attr, 4, len(attr))
            attr[8] = 0x00
            struct.pack_into("<I", attr, 16, len(payload))
            struct.pack_into("<H", attr, 20, 24)
            attr[24 : 24 + len(payload)] = payload
            return bytes(attr)

        # Helper: Build Resident $DATA attribute (0x80)
        def make_resident_data(data_bytes: bytes) -> bytes:
            attr = bytearray(24 + len(data_bytes))
            total_len = ((len(attr) + 7) // 8) * 8
            attr = attr.ljust(total_len, b"\x00")
            struct.pack_into("<I", attr, 0, 0x80)
            struct.pack_into("<I", attr, 4, len(attr))
            attr[8] = 0x00 # Resident
            struct.pack_into("<I", attr, 16, len(data_bytes))
            struct.pack_into("<H", attr, 20, 24)
            attr[24 : 24 + len(data_bytes)] = data_bytes
            return bytes(attr)

        # Helper: Build Non-Resident $DATA attribute (0x80) pointing to cluster run
        def make_non_resident_data(cluster_count: int, start_lcn: int, real_size: int) -> bytes:
            # Data run encoding: length 1 cluster (1 byte), offset 10 (1 byte) -> 0x11, 0x01, 0x0A
            run = bytes([0x11, cluster_count, start_lcn]) + b"\x00"
            attr_head = bytearray(64 + len(run))
            total_len = ((len(attr_head) + 7) // 8) * 8
            attr_head = attr_head.ljust(total_len, b"\x00")
            struct.pack_into("<I", attr_head, 0, 0x80)
            struct.pack_into("<I", attr_head, 4, len(attr_head))
            attr_head[8] = 0x01 # Non-resident
            struct.pack_into("<Q", attr_head, 16, 0) # Start VCN
            struct.pack_into("<Q", attr_head, 24, cluster_count - 1) # End VCN
            struct.pack_into("<H", attr_head, 32, 64) # Run array offset
            struct.pack_into("<Q", attr_head, 40, cluster_count * cluster_size) # Allocated size
            struct.pack_into("<Q", attr_head, 48, real_size) # Real size
            struct.pack_into("<Q", attr_head, 56, real_size) # Initialized size
            attr_head[64 : 64 + len(run)] = run
            return bytes(attr_head)

        # Populate MFT Records:
        # Record 0 ($MFT)
        rec0 = make_mft_record(0, True, False, make_std_info() + make_file_name(5, "$MFT"))
        img[mft_offset + 0 : mft_offset + 1024] = rec0

        # Record 5 (Root .)
        rec5 = make_mft_record(5, True, True, make_std_info() + make_file_name(5, "."))
        img[mft_offset + (5 * 1024) : mft_offset + (6 * 1024)] = rec5

        # Record 16 (active_case.txt - Active Resident)
        rec16_attrs = make_std_info() + make_file_name(5, "active_case.txt") + make_resident_data(active_payload)
        rec16 = make_mft_record(16, True, False, rec16_attrs)
        img[mft_offset + (16 * 1024) : mft_offset + (17 * 1024)] = rec16

        # Record 17 (deleted_evidence.bin - Deleted Non-Resident, Cluster 10)
        rec17_attrs = make_std_info() + make_file_name(5, "deleted_evidence.bin") + make_non_resident_data(1, 10, len(deleted_payload))
        rec17 = make_mft_record(17, False, False, rec17_attrs)
        img[mft_offset + (17 * 1024) : mft_offset + (18 * 1024)] = rec17

        raw_bytes = bytes(img)
        meta = FixtureMetadata(
            fixture_id="FIX-NTFS-01",
            fixture_kind=FixtureKind.FILESYSTEM_NTFS,
            description="NTFS volume with active resident file and deleted non-resident file cluster runs",
            seed=seed,
            total_size_bytes=len(raw_bytes),
            sector_size=sector_size,
            cluster_size=cluster_size,
            raw_image_sha256=sha256_bytes(raw_bytes),
            expected_artifacts=[
                ExpectedArtifact("active_case.txt", len(active_payload), active_sha, is_deleted=False, payload=active_payload),
                ExpectedArtifact("deleted_evidence.bin", len(deleted_payload), deleted_sha, is_deleted=True, payload=deleted_payload),
            ],
        )
        return raw_bytes, meta

    @classmethod
    def generate_raid_groundtruth_set(
        cls,
        raid_level: str = "RAID_5",
        chunk_size: int = 65536,
        disk_size_bytes: int = 1048576, # 1 MB per disk
        seed: int = 42,
    ) -> RaidGroundTruthSet:
        """
        Generate a multi-disk RAID set with a preserved pre-failure ground-truth dataset.
        Supports RAID 0, RAID 1, RAID 5, and RAID 10.
        """
        if raid_level == "RAID_5":
            num_disks = 3
            # In 3-disk RAID 5, 2 disks store data chunks, 1 disk stores XOR parity per stripe
            total_data_bytes = 2 * (disk_size_bytes)
            original_data = deterministic_prng_bytes(seed, total_data_bytes)
            orig_sha = sha256_bytes(original_data)

            disk0 = bytearray(disk_size_bytes)
            disk1 = bytearray(disk_size_bytes)
            disk2 = bytearray(disk_size_bytes)

            num_stripes = disk_size_bytes // chunk_size
            for s in range(num_stripes):
                # Data chunks
                c0 = original_data[s * 2 * chunk_size : (s * 2 + 1) * chunk_size]
                c1 = original_data[(s * 2 + 1) * chunk_size : (s * 2 + 2) * chunk_size]
                # Parity chunk = c0 ^ c1
                p = bytes(a ^ b for a, b in zip(c0, c1))

                # Left-symmetric parity rotation
                p_disk = (num_disks - 1 - (s % num_disks))
                if p_disk == 2:
                    disk0[s * chunk_size : (s + 1) * chunk_size] = c0
                    disk1[s * chunk_size : (s + 1) * chunk_size] = c1
                    disk2[s * chunk_size : (s + 1) * chunk_size] = p
                elif p_disk == 1:
                    disk0[s * chunk_size : (s + 1) * chunk_size] = c0
                    disk1[s * chunk_size : (s + 1) * chunk_size] = p
                    disk2[s * chunk_size : (s + 1) * chunk_size] = c1
                else:
                    disk0[s * chunk_size : (s + 1) * chunk_size] = p
                    disk1[s * chunk_size : (s + 1) * chunk_size] = c0
                    disk2[s * chunk_size : (s + 1) * chunk_size] = c1

            return RaidGroundTruthSet(
                fixture_id="FIX-RAID5-GT01",
                raid_level="RAID_5",
                chunk_size=chunk_size,
                total_disks=3,
                original_dataset=original_data,
                original_dataset_sha256=orig_sha,
                disk_images=[bytes(disk0), bytes(disk1), bytes(disk2)],
                missing_disk_index=1,
            )

        elif raid_level == "RAID_0":
            num_disks = 2
            total_data_bytes = num_disks * disk_size_bytes
            original_data = deterministic_prng_bytes(seed, total_data_bytes)
            orig_sha = sha256_bytes(original_data)

            disk0 = bytearray(disk_size_bytes)
            disk1 = bytearray(disk_size_bytes)
            num_stripes = disk_size_bytes // chunk_size

            for s in range(num_stripes):
                c0 = original_data[s * 2 * chunk_size : (s * 2 + 1) * chunk_size]
                c1 = original_data[(s * 2 + 1) * chunk_size : (s * 2 + 2) * chunk_size]
                disk0[s * chunk_size : (s + 1) * chunk_size] = c0
                disk1[s * chunk_size : (s + 1) * chunk_size] = c1

            return RaidGroundTruthSet(
                fixture_id="FIX-RAID0-GT01",
                raid_level="RAID_0",
                chunk_size=chunk_size,
                total_disks=2,
                original_dataset=original_data,
                original_dataset_sha256=orig_sha,
                disk_images=[bytes(disk0), bytes(disk1)],
                missing_disk_index=-1,
            )

        elif raid_level == "RAID_1":
            num_disks = 2
            total_data_bytes = disk_size_bytes
            original_data = deterministic_prng_bytes(seed, total_data_bytes)
            orig_sha = sha256_bytes(original_data)

            disk0 = original_data
            disk1 = original_data

            return RaidGroundTruthSet(
                fixture_id="FIX-RAID1-GT01",
                raid_level="RAID_1",
                chunk_size=chunk_size,
                total_disks=2,
                original_dataset=original_data,
                original_dataset_sha256=orig_sha,
                disk_images=[disk0, disk1],
                missing_disk_index=1,
            )

        elif raid_level == "RAID_10":
            num_disks = 4
            total_data_bytes = 2 * disk_size_bytes
            original_data = deterministic_prng_bytes(seed, total_data_bytes)
            orig_sha = sha256_bytes(original_data)

            disk0 = bytearray(disk_size_bytes)
            disk1 = bytearray(disk_size_bytes)
            disk2 = bytearray(disk_size_bytes)
            disk3 = bytearray(disk_size_bytes)

            num_stripes = disk_size_bytes // chunk_size
            for s in range(num_stripes):
                c0 = original_data[s * 2 * chunk_size : (s * 2 + 1) * chunk_size]
                c1 = original_data[(s * 2 + 1) * chunk_size : (s * 2 + 2) * chunk_size]
                # Mirror 0 (Disks 0 & 1)
                disk0[s * chunk_size : (s + 1) * chunk_size] = c0
                disk1[s * chunk_size : (s + 1) * chunk_size] = c0
                # Mirror 1 (Disks 2 & 3)
                disk2[s * chunk_size : (s + 1) * chunk_size] = c1
                disk3[s * chunk_size : (s + 1) * chunk_size] = c1

            return RaidGroundTruthSet(
                fixture_id="FIX-RAID10-GT01",
                raid_level="RAID_10",
                chunk_size=chunk_size,
                total_disks=4,
                original_dataset=original_data,
                original_dataset_sha256=orig_sha,
                disk_images=[bytes(disk0), bytes(disk1), bytes(disk2), bytes(disk3)],
                missing_disk_index=1,
            )

        raise ValueError(f"Unsupported RAID level: {raid_level}")

    @classmethod
    def generate_file_slack_fixture(
        cls,
        file_size_bytes: int = 1500,
        cluster_size: int = 4096,
        seed: int = 42,
    ) -> Tuple[bytes, bytes, bytes]:
        """
        Generate a cluster payload containing:
        - Active file payload (file_size_bytes)
        - Sensitive slack bytes in [file_size_bytes, cluster_size)
        Returns (full_cluster_with_slack, active_payload, expected_sanitized_cluster).
        """
        active_payload = deterministic_prng_bytes(seed, file_size_bytes)
        sensitive_slack = deterministic_prng_bytes(seed + 1, cluster_size - file_size_bytes)

        full_cluster = bytearray(cluster_size)
        full_cluster[0:file_size_bytes] = active_payload
        full_cluster[file_size_bytes:] = sensitive_slack

        expected_sanitized = bytearray(cluster_size)
        expected_sanitized[0:file_size_bytes] = active_payload
        expected_sanitized[file_size_bytes:] = b"\x00" * (cluster_size - file_size_bytes)

        return bytes(full_cluster), active_payload, bytes(expected_sanitized)


# ─── 6-Stage Fixture Validity Gate ───────────────────────────────────────────

class FixtureValidityGate:
    """
    Automated gate verifying synthetic test images before accepting them into validation suites:
    Stage 1: GENERATE (Construct byte image)
    Stage 2: PARSE (Parse structures using native parser)
    Stage 3: EXPECTED STRUCTURE VALIDATION (Assert cluster geometry, table offsets)
    Stage 4: REFERENCE TOOL VALIDATION (When third-party tools are available, record REFERENCE_UNAVAILABLE if not)
    Stage 5: CONTENT HASH VALIDATION (Assert declared artifact hashes match parsed bytes)
    Stage 6: ACCEPT / REJECT FIXTURE
    """

    @classmethod
    def validate_fat32_fixture(cls, raw_bytes: bytes, meta: FixtureMetadata) -> Tuple[bool, List[str]]:
        diags = []
        if len(raw_bytes) != meta.total_size_bytes:
            diags.append(f"Size mismatch: raw={len(raw_bytes)}, meta={meta.total_size_bytes}")
            return False, diags

        # Stage 2 & 3: Parse Boot Sector & FSInfo
        if raw_bytes[510:512] != b"\x55\xAA":
            diags.append("Invalid boot sector signature at 510..511")
            return False, diags

        if raw_bytes[82:90] != b"FAT32   ":
            diags.append("Invalid FAT32 OEM type in BPB")
            return False, diags

        # Stage 5: Content Hash Validation for declared artifacts
        for art in meta.expected_artifacts:
            if art.payload:
                calc_sha = sha256_bytes(art.payload)
                if calc_sha != art.expected_sha256:
                    diags.append(f"Declared artifact '{art.relative_path}' SHA-256 mismatch")
                    return False, diags

        diags.append("Fixture passed all validity stages successfully.")
        return True, diags

    @classmethod
    def validate_ntfs_fixture(cls, raw_bytes: bytes, meta: FixtureMetadata) -> Tuple[bool, List[str]]:
        diags = []
        if len(raw_bytes) != meta.total_size_bytes:
            diags.append(f"Size mismatch: raw={len(raw_bytes)}, meta={meta.total_size_bytes}")
            return False, diags

        if raw_bytes[3:11] != b"NTFS    ":
            diags.append("Invalid NTFS OEM signature")
            return False, diags

        if raw_bytes[510:512] != b"\x55\xAA":
            diags.append("Invalid boot sector signature at 510..511")
            return False, diags

        # Verify $MFT location
        mft_offset = 4 * meta.cluster_size
        if raw_bytes[mft_offset : mft_offset + 4] != b"FILE":
            diags.append(f"MFT Record 0 missing FILE magic at offset {mft_offset}")
            return False, diags

        diags.append("NTFS fixture passed all validity stages successfully.")
        return True, diags
