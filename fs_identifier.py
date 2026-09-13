"""
DREX-V2 Forensic Filesystem Identifier
Module: fs_identifier.py
Phase: 3 / 12

Identifies filesystem types using multi-signature detection, boot parameter block (BPB)
geometry validation, superblock parsing, and structural checks.
"""

from __future__ import annotations

import struct
from typing import Optional, Tuple

from fs_base import FilesystemKind, ReadOnlySource


class FilesystemIdentifier:
    """Forensic filesystem detector and geometry validator."""

    @classmethod
    def identify(cls, source: ReadOnlySource, start_offset: int = 0) -> Tuple[FilesystemKind, str]:
        """Identify the filesystem kind and return (FilesystemKind, description)."""
        header_64k = source.read(start_offset, 65536)
        if len(header_64k) < 512:
            return FilesystemKind.UNKNOWN, "Source smaller than 512 bytes"

        # 1. Check NTFS
        if len(header_64k) >= 512 and header_64k[3:11] == b"NTFS    ":
            bytes_per_sec, sec_per_clus = struct.unpack("<HB", header_64k[11:14])
            if bytes_per_sec in (512, 1024, 2048, 4096) and sec_per_clus in (1, 2, 4, 8, 16, 32, 64, 128):
                return FilesystemKind.NTFS, f"NTFS (SectorSize={bytes_per_sec}, ClusterSize={bytes_per_sec * sec_per_clus})"

        # 2. Check exFAT
        if len(header_64k) >= 512 and header_64k[3:11] == b"EXFAT   " and header_64k[510:512] == b"\x55\xaa":
            sec_shift = header_64k[108]
            clus_shift = header_64k[109]
            if 9 <= sec_shift <= 12 and 0 <= clus_shift <= 12:
                return FilesystemKind.EXFAT, f"exFAT (SectorSize={1 << sec_shift}, ClusterSize={1 << (sec_shift + clus_shift)})"

        # 3. Check FAT32 / FAT16 / FAT12
        if len(header_64k) >= 512 and header_64k[510:512] == b"\x55\xaa":
            fat_kind, desc = cls._inspect_fat(header_64k)
            if fat_kind != FilesystemKind.UNKNOWN:
                return fat_kind, desc

        # 4. Check EXT2 / EXT3 / EXT4 (Superblock at offset 1024)
        if len(header_64k) >= 2048:
            sb = header_64k[1024:2048]
            if len(sb) >= 1024 and sb[56:58] == b"\x53\xef":  # 0xEF53 magic little-endian
                ext_kind, desc = cls._inspect_ext(sb)
                return ext_kind, desc

        # 5. Check HFS+ / HFSX (Volume header at offset 1024)
        if len(header_64k) >= 2048:
            hfs_magic = header_64k[1024:1026]
            if hfs_magic in (b"H+", b"HX"):
                return FilesystemKind.HFS_PLUS, f"HFS+ / HFSX (Signature={hfs_magic.decode('latin1', 'replace')})"

        # 6. Check APFS (Container Superblock at offset 0 / LBA 0)
        if len(header_64k) >= 512 and header_64k[32:36] == b"NXSB":
            return FilesystemKind.APFS, "Apple File System (APFS Container Superblock)"

        # 7. Check ISO9660 (Primary Volume Descriptor at offset 32768)
        if len(header_64k) >= 32774 and header_64k[32769:32774] == b"CD001":
            return FilesystemKind.ISO9660, "ISO9660 Optical Disk Image"

        return FilesystemKind.UNKNOWN, "No recognized filesystem signature"

    @classmethod
    def _inspect_fat(cls, sector0: bytes) -> Tuple[FilesystemKind, str]:
        """Differentiate FAT12, FAT16, and FAT32 using BPB geometry."""
        try:
            bytes_per_sec, sec_per_clus, reserved_secs, num_fats, root_entries, total_secs_16, _, secs_per_fat_16 = struct.unpack(
                "<HBHBHHsH", sector0[11:24]
            )
            total_secs_32 = struct.unpack("<I", sector0[32:36])[0]
        except Exception:
            return FilesystemKind.UNKNOWN, ""

        if bytes_per_sec not in (512, 1024, 2048, 4096) or sec_per_clus not in (1, 2, 4, 8, 16, 32, 64, 128) or num_fats == 0:
            return FilesystemKind.UNKNOWN, ""

        # Check explicit FAT strings
        fat32_sig = sector0[82:90]
        fat16_sig = sector0[54:62]

        total_secs = total_secs_16 if total_secs_16 != 0 else total_secs_32
        secs_per_fat = secs_per_fat_16
        if secs_per_fat == 0 and len(sector0) >= 40:
            secs_per_fat = struct.unpack("<I", sector0[36:40])[0]

        root_dir_sectors = ((root_entries * 32) + (bytes_per_sec - 1)) // bytes_per_sec
        data_sectors = total_secs - (reserved_secs + (num_fats * secs_per_fat) + root_dir_sectors)
        count_of_clusters = data_sectors // sec_per_clus if sec_per_clus > 0 else 0

        if count_of_clusters < 4085 or b"FAT12" in fat16_sig:
            return FilesystemKind.FAT12, f"FAT12 (Clusters={count_of_clusters}, ClusterSize={bytes_per_sec * sec_per_clus})"
        elif count_of_clusters < 65525 or b"FAT16" in fat16_sig:
            return FilesystemKind.FAT16, f"FAT16 (Clusters={count_of_clusters}, ClusterSize={bytes_per_sec * sec_per_clus})"
        else:
            return FilesystemKind.FAT32, f"FAT32 (Clusters={count_of_clusters}, ClusterSize={bytes_per_sec * sec_per_clus})"

    @classmethod
    def _inspect_ext(cls, sb: bytes) -> Tuple[FilesystemKind, str]:
        """Inspect EXT superblock feature flags to distinguish EXT2, EXT3, and EXT4."""
        inodes_count, blocks_count, _, _, _, _, log_block_size = struct.unpack("<IIIIIII", sb[0:28])
        block_size = 1024 << log_block_size if log_block_size < 16 else 4096

        compat_features, incompat_features, ro_compat = struct.unpack("<III", sb[92:104])

        has_journal = bool(compat_features & 0x0004)
        has_extents = bool(incompat_features & 0x0040)
        has_64bit = bool(incompat_features & 0x0080)

        if has_extents or has_64bit:
            return FilesystemKind.EXT4, f"EXT4 (BlockSize={block_size}, Extents={'YES' if has_extents else 'NO'})"
        elif has_journal:
            return FilesystemKind.EXT3, f"EXT3 (BlockSize={block_size}, Journal=YES)"
        else:
            return FilesystemKind.EXT2, f"EXT2 (BlockSize={block_size})"
