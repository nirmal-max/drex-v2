"""
Acceptance Tests for Native EXT2 / EXT3 / EXT4 Forensic Recovery Engine
File: tests/test_fs_ext.py
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
from fs_ext import Ext4Parser


def create_synthetic_ext4_image() -> bytes:
    """Create a minimal synthetic EXT4 image with Superblock, BGDT, Inode table, and Extent Trees."""
    block_size = 4096
    inodes_count = 64
    blocks_count = 64
    blocks_per_group = 64
    inodes_per_group = 64
    inode_size = 256

    image_size = blocks_count * block_size
    image = bytearray(image_size)

    # 1. Superblock at Block 0 (offset 1024)
    sb = bytearray(1024)
    struct.pack_into("<IIIIIII", sb, 0, inodes_count, blocks_count, 0, 0, 0, 0, 2)  # log_block_size = 2 -> 4096 bytes
    struct.pack_into("<I", sb, 32, blocks_per_group)
    struct.pack_into("<I", sb, 40, inodes_per_group)
    struct.pack_into("<H", sb, 56, 0xEF53)  # Superblock magic
    struct.pack_into("<H", sb, 88, inode_size)  # Inode size = 256 bytes
    struct.pack_into("<III", sb, 92, 0x0004, 0x0040, 0)  # compat=HAS_JOURNAL, incompat=EXTENTS
    image[1024:2048] = sb

    # 2. Block Group Descriptor Table at Block 1 (offset 4096)
    bgdt = bytearray(32)
    itable_block = 3  # Inode table at Block 3
    struct.pack_into("<I", bgdt, 8, itable_block)
    image[4096:4096 + 32] = bgdt

    # 3. Data Blocks
    # Block 10: Extent File 1 Data (Active)
    ext_data1 = b"EXT4_EXTENT_TREE_ACTIVE_FILE_CONTENT_BLOCK_10_EVIDENCE_12345" * 20
    image[10 * block_size: 10 * block_size + len(ext_data1)] = ext_data1

    # Block 12 & 14: Fragmented Deleted Extent File
    frag_ext1 = (b"EXT4_DELETED_FRAGMENT_PART_1_BLOCK_12_" * 152)[:4096]
    frag_ext2 = b"EXT4_DELETED_FRAGMENT_PART_2_BLOCK_14_" * 25
    image[12 * block_size: 12 * block_size + len(frag_ext1)] = frag_ext1
    image[14 * block_size: 14 * block_size + len(frag_ext2)] = frag_ext2

    # Block 20: Direct Block EXT2-style File
    direct_data = b"EXT2_DIRECT_BLOCKS_LEGACY_EVIDENCE_FILE_CONTENT_BLOCK_20" * 15
    image[20 * block_size: 20 * block_size + len(direct_data)] = direct_data

    # 4. Inode Table at Block 3 (offset 3 * 4096 = 12288)
    itable_offset = 3 * block_size

    def write_inode(
        inode_num: int,
        is_dir: bool,
        size: int,
        is_deleted: bool,
        extents_list: list = None,
        direct_blocks: list = None,
    ):
        offset = itable_offset + ((inode_num - 1) * inode_size)
        raw_in = bytearray(inode_size)
        mode = 0x41ED if is_dir else 0x81A4
        struct.pack_into("<H", raw_in, 0, mode)
        struct.pack_into("<I", raw_in, 4, size)  # size_lo
        dtime = 1700000000 if is_deleted else 0
        struct.pack_into("<IIII", raw_in, 8, 1700000000, 1700000000, 1700000000, dtime)
        struct.pack_into("<H", raw_in, 26, 0 if is_deleted else 1)  # links_count

        if extents_list:
            struct.pack_into("<I", raw_in, 32, 0x00080000)  # EXT4_EXTENTS_FL
            # Write Extent Header
            eh = raw_in[40:100]
            struct.pack_into("<HHHH", eh, 0, 0xF30A, len(extents_list), 4, 0)  # magic, entries, max, depth=0
            for idx, (lblk, blen, pblk) in enumerate(extents_list):
                e_off = 12 + (idx * 12)
                struct.pack_into("<IHHI", eh, e_off, lblk, blen, 0, pblk)
            raw_in[40:100] = eh
        elif direct_blocks:
            struct.pack_into("<I", raw_in, 32, 0)  # No extents flag
            for idx, blk in enumerate(direct_blocks):
                struct.pack_into("<I", raw_in, 40 + (idx * 4), blk)

        image[offset: offset + inode_size] = raw_in

    # Inode 2: Root Directory
    write_inode(2, is_dir=True, size=4096, is_deleted=False)

    # Inode 11: Active Extent File ("inode_11", Block 10)
    write_inode(11, is_dir=False, size=len(ext_data1), is_deleted=False, extents_list=[(0, 1, 10)])

    # Inode 12: Deleted Fragmented Extent File ("inode_12", Block 12 & 14)
    write_inode(
        12,
        is_dir=False,
        size=len(frag_ext1) + len(frag_ext2),
        is_deleted=True,
        extents_list=[(0, 1, 12), (1, 1, 14)],
    )

    # Inode 13: Direct Block File ("inode_13", Block 20)
    write_inode(13, is_dir=False, size=len(direct_data), is_deleted=False, direct_blocks=[20])

    return bytes(image)


def test_ext4_active_extent_tree_recovery():
    """Verify EXT4 extent tree parsing and byte-exact active file extraction."""
    image_bytes = create_synthetic_ext4_image()
    source = SyntheticFixtureSource(image_bytes)
    parser = Ext4Parser(source, partition_offset=0)
    assert parser.is_initialized is True
    assert parser.ext_kind == FilesystemKind.EXT4

    candidates = parser.scan_all_inodes()
    assert len(candidates) >= 4

    in11 = next(c for c in candidates if c.candidate_id == "ext_11")
    assert in11.is_deleted is False
    assert in11.extent_state == ExtentState.VERIFIED_EXTENTS
    assert len(in11.extents) == 1
    assert in11.extents[0].cluster_index == 10

    recovered = parser.read_candidate_bytes(in11)
    expected = b"EXT4_EXTENT_TREE_ACTIVE_FILE_CONTENT_BLOCK_10_EVIDENCE_12345" * 20
    assert recovered == expected
    assert hashlib.sha256(recovered).hexdigest() == hashlib.sha256(expected).hexdigest()


def test_ext4_deleted_inode_dtime_candidate():
    """Verify deleted inode discovery (dtime != 0) and fragmented extent reassembly."""
    image_bytes = create_synthetic_ext4_image()
    source = SyntheticFixtureSource(image_bytes)
    parser = Ext4Parser(source, partition_offset=0)

    candidates = parser.scan_all_inodes()
    in12 = next(c for c in candidates if c.candidate_id == "ext_12")
    assert in12.is_deleted is True
    assert in12.extent_state == ExtentState.FRAGMENTED_EXTENTS
    assert len(in12.extents) == 2
    assert in12.extents[0].cluster_index == 12
    assert in12.extents[1].cluster_index == 14
    assert "EXT_DELETED_INODE_CANDIDATE" in in12.limitations

    recovered = parser.read_candidate_bytes(in12)
    expected_p1 = (b"EXT4_DELETED_FRAGMENT_PART_1_BLOCK_12_" * 152)[:4096]
    expected_p2 = b"EXT4_DELETED_FRAGMENT_PART_2_BLOCK_14_" * 25
    expected = expected_p1 + expected_p2
    assert recovered == expected
    assert hashlib.sha256(recovered).hexdigest() == hashlib.sha256(expected).hexdigest()


def test_ext2_direct_blocks_resolution():
    """Verify legacy direct block mapping extraction."""
    image_bytes = create_synthetic_ext4_image()
    source = SyntheticFixtureSource(image_bytes)
    parser = Ext4Parser(source, partition_offset=0)

    candidates = parser.scan_all_inodes()
    in13 = next(c for c in candidates if c.candidate_id == "ext_13")
    assert in13.is_deleted is False
    assert len(in13.extents) == 1
    assert in13.extents[0].cluster_index == 20

    recovered = parser.read_candidate_bytes(in13)
    expected = b"EXT2_DIRECT_BLOCKS_LEGACY_EVIDENCE_FILE_CONTENT_BLOCK_20" * 15
    assert recovered == expected
    assert hashlib.sha256(recovered).hexdigest() == hashlib.sha256(expected).hexdigest()
