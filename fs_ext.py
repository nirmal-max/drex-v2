"""
DREX-V2 Native EXT2 / EXT3 / EXT4 Parser & Forensic Recovery Engine
Module: fs_ext.py
Phase: 3 / 12

Parses EXT superblocks, block group descriptors, inode tables, Ext4 Extent Trees (0xF30A),
direct/indirect block tables, directory entry records, and deleted inodes (dtime != 0).
"""

from __future__ import annotations

import datetime
import struct
from typing import Any, Dict, List, Optional, Set, Tuple

from fs_base import (
    ExtentRun,
    ExtentState,
    FilesystemKind,
    FsCandidateRecord,
    FsTimestamps,
    PathState,
    ReadOnlySource,
)


class Ext4Parser:
    """Forensic parser for Linux EXT2, EXT3, and EXT4 filesystems."""

    SUPERBLOCK_MAGIC = 0xEF53
    EXT4_EXTENTS_MAGIC = 0xF30A
    EXT4_EXTENTS_FL = 0x00080000

    INODE_FILE_TYPE_REGULAR = 0x8000
    INODE_FILE_TYPE_DIR = 0x4000

    def __init__(self, source: ReadOnlySource, partition_offset: int = 0):
        self.source = source
        self.partition_offset = partition_offset
        self.block_size = 4096
        self.inodes_count = 0
        self.blocks_count = 0
        self.first_data_block = 0
        self.blocks_per_group = 0
        self.inodes_per_group = 0
        self.inode_size = 256
        self.group_desc_block = 1
        self.group_count = 0
        self.group_desc_size = 32
        self.ext_kind = FilesystemKind.EXT4
        self.is_initialized = False
        self.inode_tables: List[int] = []
        self._initialize()

    def _initialize(self) -> None:
        """Parse EXT Superblock and Block Group Descriptor Table."""
        sb_bytes = self.source.read(self.partition_offset + 1024, 1024)
        if len(sb_bytes) < 1024:
            return

        magic = struct.unpack("<H", sb_bytes[56:58])[0]
        if magic != self.SUPERBLOCK_MAGIC:
            return

        self.inodes_count, self.blocks_count, _, _, _, self.first_data_block, log_block_size = struct.unpack(
            "<IIIIIII", sb_bytes[0:28]
        )
        self.blocks_per_group = struct.unpack("<I", sb_bytes[32:36])[0]
        self.inodes_per_group = struct.unpack("<I", sb_bytes[40:44])[0]
        self.inode_size = struct.unpack("<H", sb_bytes[88:90])[0] if len(sb_bytes) >= 90 else 128
        if self.inode_size == 0:
            self.inode_size = 128

        self.block_size = 1024 << log_block_size if log_block_size < 16 else 4096
        self.group_desc_block = 1 if self.block_size > 1024 else 2

        compat, incompat, _ = struct.unpack("<III", sb_bytes[92:104])
        has_journal = bool(compat & 0x0004)
        has_extents = bool(incompat & 0x0040)
        has_64bit = bool(incompat & 0x0080)
        self.group_desc_size = 64 if has_64bit else 32

        if has_extents or has_64bit:
            self.ext_kind = FilesystemKind.EXT4
        elif has_journal:
            self.ext_kind = FilesystemKind.EXT3
        else:
            self.ext_kind = FilesystemKind.EXT2

        self.group_count = (self.blocks_count + self.blocks_per_group - 1) // self.blocks_per_group if self.blocks_per_group > 0 else 0

        # Read Block Group Descriptors
        bgdt_offset = self.partition_offset + (self.group_desc_block * self.block_size)
        bgdt_bytes = self.source.read(bgdt_offset, self.group_count * self.group_desc_size)

        self.inode_tables = []
        for g in range(self.group_count):
            desc_offset = g * self.group_desc_size
            desc = bgdt_bytes[desc_offset: desc_offset + self.group_desc_size]
            if len(desc) >= 32:
                itable_lo = struct.unpack("<I", desc[8:12])[0]
                itable_hi = struct.unpack("<I", desc[40:44])[0] if self.group_desc_size >= 64 else 0
                itable_block = (itable_hi << 32) | itable_lo
                self.inode_tables.append(itable_block)

        self.is_initialized = True

    def block_to_byte_offset(self, block_num: int) -> int:
        """Convert logical filesystem block number to absolute byte offset."""
        return self.partition_offset + (block_num * self.block_size)

    def read_inode(self, inode_num: int) -> Optional[bytes]:
        """Read raw inode structure bytes for inode number (1-indexed)."""
        if not self.is_initialized or inode_num < 1 or inode_num > self.inodes_count or self.inodes_per_group == 0:
            return None

        group_idx = (inode_num - 1) // self.inodes_per_group
        if group_idx >= len(self.inode_tables):
            return None

        index_in_group = (inode_num - 1) % self.inodes_per_group
        itable_block = self.inode_tables[group_idx]
        inode_offset = self.block_to_byte_offset(itable_block) + (index_in_group * self.inode_size)

        data = self.source.read(inode_offset, self.inode_size)
        return data if len(data) >= self.inode_size else None

    def scan_all_inodes(self, max_inodes: int = 50000) -> List[FsCandidateRecord]:
        """Iterate inode tables and discover active and deleted inode candidates."""
        if not self.is_initialized:
            return []

        candidates: List[FsCandidateRecord] = []
        limit = min(self.inodes_count, max_inodes)

        for inode_idx in range(1, limit + 1):
            raw_inode = self.read_inode(inode_idx)
            if not raw_inode or raw_inode == b"\x00" * len(raw_inode):
                continue

            cand = self.parse_inode(raw_inode, inode_idx)
            if cand:
                candidates.append(cand)

        return candidates

    def parse_inode(self, raw_inode: bytes, inode_number: int) -> Optional[FsCandidateRecord]:
        """Parse raw inode bytes, resolving extents via Extent Tree or Direct/Indirect block tables."""
        if len(raw_inode) < 128:
            return None

        i_mode = struct.unpack("<H", raw_inode[0:2])[0]
        if i_mode == 0:
            return None

        is_dir = bool((i_mode & 0xF000) == self.INODE_FILE_TYPE_DIR)
        is_reg = bool((i_mode & 0xF000) == self.INODE_FILE_TYPE_REGULAR)

        if not (is_dir or is_reg):
            return None

        size_lo = struct.unpack("<I", raw_inode[4:8])[0]
        atime, ctime, mtime, dtime = struct.unpack("<IIII", raw_inode[8:24])
        links_count = struct.unpack("<H", raw_inode[26:28])[0]
        flags = struct.unpack("<I", raw_inode[32:36])[0]

        size_hi = 0
        if len(raw_inode) >= 112 and self.inode_size >= 256:
            size_hi = struct.unpack("<I", raw_inode[108:112])[0]
        real_size = (size_hi << 32) | size_lo

        is_deleted = bool(dtime != 0 or links_count == 0)

        # Timestamps
        timestamps = FsTimestamps(
            accessed=self._unix_to_iso(atime),
            created=self._unix_to_iso(ctime),
            modified=self._unix_to_iso(mtime),
            deleted=self._unix_to_iso(dtime) if dtime != 0 else None,
        )

        # Block & Extent Resolution
        block_bytes = raw_inode[40:100]  # 60 bytes i_block area
        uses_extents = bool(flags & self.EXT4_EXTENTS_FL) or (block_bytes[0:2] == struct.pack("<H", self.EXT4_EXTENTS_MAGIC))

        extents: List[ExtentRun] = []
        limitations: List[str] = []
        extent_state = ExtentState.VERIFIED_EXTENTS

        if uses_extents:
            extents = self._parse_extent_tree(block_bytes)
            if len(extents) > 1:
                extent_state = ExtentState.FRAGMENTED_EXTENTS
        else:
            extents = self._parse_direct_indirect_blocks(block_bytes, real_size)
            if len(extents) > 1:
                extent_state = ExtentState.FRAGMENTED_EXTENTS

        if is_deleted:
            limitations.append("EXT_DELETED_INODE_CANDIDATE")

        filename = f"inode_{inode_number}"
        return FsCandidateRecord(
            candidate_id=f"ext_{inode_number}",
            filesystem=self.ext_kind,
            filename=filename,
            original_path=filename,
            reconstructed_path=filename,
            path_state=PathState.ORIGINAL_PATH_CONFIRMED if not is_deleted else PathState.PATH_UNKNOWN,
            declared_size=real_size if not is_dir else 0,
            recovered_size=sum(e.length_bytes for e in extents),
            is_directory=is_dir,
            is_deleted=is_deleted,
            is_resident=False,
            extent_state=extent_state,
            extents=extents,
            timestamps=timestamps,
            source_record_id=inode_number,
            limitations=limitations,
        )

    def _parse_extent_tree(self, block_bytes: bytes) -> List[ExtentRun]:
        """Parse Ext4 Extent Tree header and leaf/index nodes."""
        if len(block_bytes) < 12:
            return []

        magic, entries, max_entries, depth = struct.unpack("<HHHH", block_bytes[0:8])
        if magic != self.EXT4_EXTENTS_MAGIC:
            return []

        extents: List[ExtentRun] = []
        if depth == 0:
            # Leaf nodes
            for i in range(min(entries, max_entries, 4)):
                ext_offset = 12 + (i * 12)
                if ext_offset + 12 > len(block_bytes):
                    break
                ee_block, ee_len, ee_start_hi, ee_start_lo = struct.unpack("<IHHI", block_bytes[ext_offset: ext_offset + 12])
                if ee_len == 0:
                    continue

                phys_block = (ee_start_hi << 32) | ee_start_lo
                phys_byte = self.block_to_byte_offset(phys_block)
                length_bytes = ee_len * self.block_size

                extents.append(
                    ExtentRun(
                        logical_offset=ee_block * self.block_size,
                        physical_offset=phys_byte,
                        length_bytes=length_bytes,
                        is_sparse=False,
                        cluster_index=phys_block,
                        cluster_count=ee_len,
                    )
                )
        else:
            # Index nodes
            for i in range(min(entries, max_entries, 4)):
                idx_offset = 12 + (i * 12)
                if idx_offset + 12 > len(block_bytes):
                    break
                ei_block, ei_leaf_lo, ei_leaf_hi = struct.unpack("<IIH", block_bytes[idx_offset: idx_offset + 10])
                child_block = (ei_leaf_hi << 32) | ei_leaf_lo
                child_bytes = self.source.read(self.block_to_byte_offset(child_block), self.block_size)
                child_exts = self._parse_extent_tree(child_bytes[:60])
                extents.extend(child_exts)

        return extents

    def _parse_direct_indirect_blocks(self, block_bytes: bytes, file_size: int) -> List[ExtentRun]:
        """Resolve direct i_block[0..11] and single indirect block table."""
        extents: List[ExtentRun] = []
        logical_offset = 0

        # 12 direct blocks
        for i in range(12):
            if logical_offset >= file_size and file_size > 0:
                break
            b_offset = i * 4
            blk = struct.unpack("<I", block_bytes[b_offset: b_offset + 4])[0]
            if blk != 0:
                extents.append(
                    ExtentRun(
                        logical_offset=logical_offset,
                        physical_offset=self.block_to_byte_offset(blk),
                        length_bytes=self.block_size,
                        is_sparse=False,
                        cluster_index=blk,
                        cluster_count=1,
                    )
                )
            logical_offset += self.block_size

        # Single indirect block (i_block[12])
        if len(block_bytes) >= 52 and logical_offset < file_size:
            ind_blk = struct.unpack("<I", block_bytes[48:52])[0]
            if ind_blk != 0:
                ind_bytes = self.source.read(self.block_to_byte_offset(ind_blk), self.block_size)
                ptrs_count = len(ind_bytes) // 4
                for j in range(ptrs_count):
                    if logical_offset >= file_size:
                        break
                    p_blk = struct.unpack("<I", ind_bytes[j * 4: (j * 4) + 4])[0]
                    if p_blk != 0:
                        extents.append(
                            ExtentRun(
                                logical_offset=logical_offset,
                                physical_offset=self.block_to_byte_offset(p_blk),
                                length_bytes=self.block_size,
                                is_sparse=False,
                                cluster_index=p_blk,
                                cluster_count=1,
                            )
                        )
                    logical_offset += self.block_size

        return extents

    def read_candidate_bytes(self, candidate: FsCandidateRecord, max_bytes: Optional[int] = None) -> bytes:
        """Extract full binary content of candidate inode."""
        target_size = candidate.declared_size
        if max_bytes:
            target_size = min(target_size, max_bytes)

        out_buffer = bytearray()
        bytes_left = target_size

        for ext in candidate.extents:
            if bytes_left <= 0:
                break
            chunk_len = min(bytes_left, ext.length_bytes)
            data = self.source.read(ext.physical_offset, chunk_len)
            out_buffer.extend(data)
            bytes_left -= chunk_len

        return bytes(out_buffer)

    @classmethod
    def _unix_to_iso(cls, epoch_sec: int) -> Optional[str]:
        """Convert 32-bit Unix epoch seconds to ISO timestamp string."""
        if epoch_sec == 0:
            return None
        try:
            dt = datetime.datetime.fromtimestamp(epoch_sec, tz=datetime.timezone.utc)
            return dt.isoformat()
        except Exception:
            return None
