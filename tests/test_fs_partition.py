"""
Acceptance Tests for Forensic Partition Table Parser (MBR, EBR, GPT)
File: tests/test_fs_partition.py
Phase: 3 / 12
"""

import struct
import uuid
import zlib
import pytest

from fs_base import (
    PartitionRecord,
    PartitionType,
    PartitionValidationOutcome,
    SyntheticFixtureSource,
)
from fs_partition import PartitionTableParser


def create_synthetic_mbr_with_ebr() -> bytes:
    """Create a synthetic disk image with MBR primary and EBR logical partitions."""
    sector_size = 512
    total_sectors = 1000
    image = bytearray(total_sectors * sector_size)

    # MBR at Sector 0
    mbr = bytearray(512)
    # Entry 1: Primary NTFS partition at LBA 100, length 200 sectors
    struct.pack_into("<BBBBBBBBII", mbr, 446, 0x80, 0, 0, 0, 0x07, 0, 0, 0, 100, 200)
    # Entry 2: Extended partition (EBR root) at LBA 400, length 500 sectors
    struct.pack_into("<BBBBBBBBII", mbr, 462, 0x00, 0, 0, 0, 0x05, 0, 0, 0, 400, 500)
    mbr[510:512] = b"\x55\xaa"
    image[0:512] = mbr

    # EBR 1 at Sector 400
    ebr1 = bytearray(512)
    # Logical partition 1: starts 10 sectors after EBR (LBA 410), length 100 sectors
    struct.pack_into("<BBBBBBBBII", ebr1, 446, 0x00, 0, 0, 0, 0x83, 0, 0, 0, 10, 100)
    # Pointer to next EBR: relative to extended root LBA 400 -> offset +200 = LBA 600
    struct.pack_into("<BBBBBBBBII", ebr1, 462, 0x00, 0, 0, 0, 0x05, 0, 0, 0, 200, 200)
    ebr1[510:512] = b"\x55\xaa"
    image[400 * sector_size: 400 * sector_size + 512] = ebr1

    # EBR 2 at Sector 600
    ebr2 = bytearray(512)
    # Logical partition 2: starts 10 sectors after EBR (LBA 610), length 80 sectors
    struct.pack_into("<BBBBBBBBII", ebr2, 446, 0x00, 0, 0, 0, 0x0B, 0, 0, 0, 10, 80)
    # End of EBR chain (entry 2 is 0)
    ebr2[510:512] = b"\x55\xaa"
    image[600 * sector_size: 600 * sector_size + 512] = ebr2

    return bytes(image)


def create_synthetic_gpt_image() -> bytes:
    """Create a synthetic disk image with Protective MBR and Primary GPT."""
    sector_size = 512
    total_sectors = 500
    image = bytearray(total_sectors * sector_size)

    # Protective MBR at Sector 0
    mbr = bytearray(512)
    struct.pack_into("<BBBBBBBBII", mbr, 446, 0x00, 0, 0, 0, 0xEE, 0, 0, 0, 1, 499)
    mbr[510:512] = b"\x55\xaa"
    image[0:512] = mbr

    # Primary GPT Header at LBA 1 (Sector 1)
    gpt_header = bytearray(92)
    gpt_header[0:8] = b"EFI PART"
    struct.pack_into("<I", gpt_header, 8, 0x00010000)   # Revision 1.0
    struct.pack_into("<I", gpt_header, 12, 92)          # Header size
    struct.pack_into("<Q", gpt_header, 24, 1)           # Current LBA
    struct.pack_into("<Q", gpt_header, 32, 499)         # Backup LBA
    struct.pack_into("<Q", gpt_header, 40, 34)          # First usable LBA
    struct.pack_into("<Q", gpt_header, 48, 465)         # Last usable LBA
    struct.pack_into("<Q", gpt_header, 72, 2)           # Partition entries starting LBA
    struct.pack_into("<I", gpt_header, 80, 2)           # Number of partition entries
    struct.pack_into("<I", gpt_header, 84, 128)         # Size of each entry

    # Partition Entry Array at LBA 2 (Sector 2)
    entries = bytearray(256)
    # Entry 0: Basic Data Partition (LBA 50 to 200)
    type_guid = uuid.UUID("EBD0A0A2-B9E5-4433-87C0-68B6B72699C7").bytes_le
    unique_guid = uuid.UUID("11111111-2222-3333-4444-555555555555").bytes_le
    entries[0:16] = type_guid
    entries[16:32] = unique_guid
    struct.pack_into("<QQQ", entries, 32, 50, 200, 0)
    name_utf16 = "DataPartition".encode("utf-16-le")
    entries[56:56 + len(name_utf16)] = name_utf16

    # Calculate entries CRC32
    entries_crc = zlib.crc32(entries) & 0xFFFFFFFF
    struct.pack_into("<I", gpt_header, 88, entries_crc)

    # Calculate header CRC32 with CRC field at bytes 16:20 zeroed
    header_crc = zlib.crc32(gpt_header) & 0xFFFFFFFF
    struct.pack_into("<I", gpt_header, 16, header_crc)

    image[1 * sector_size: 1 * sector_size + 92] = gpt_header
    image[2 * sector_size: 2 * sector_size + 256] = entries

    return bytes(image)


def test_mbr_and_ebr_parsing():
    """Verify MBR primary and EBR logical partition extraction."""
    image_bytes = create_synthetic_mbr_with_ebr()
    source = SyntheticFixtureSource(image_bytes)
    partitions = PartitionTableParser.parse(source)

    assert len(partitions) == 3

    # Primary partition
    p0 = partitions[0]
    assert p0.partition_type == PartitionType.MBR_PRIMARY
    assert p0.start_lba == 100
    assert p0.end_lba == 299
    assert p0.is_bootable is True
    assert p0.type_code == 0x07

    # Logical partition 1
    p1 = partitions[1]
    assert p1.partition_type == PartitionType.MBR_LOGICAL
    assert p1.start_lba == 410
    assert p1.size_bytes == 100 * 512
    assert p1.type_code == 0x83

    # Logical partition 2
    p2 = partitions[2]
    assert p2.partition_type == PartitionType.MBR_LOGICAL
    assert p2.start_lba == 610
    assert p2.size_bytes == 80 * 512
    assert p2.type_code == 0x0B


def test_gpt_crc32_and_guid_parsing():
    """Verify GPT CRC32 verification and GUID partition record extraction."""
    image_bytes = create_synthetic_gpt_image()
    source = SyntheticFixtureSource(image_bytes)
    partitions = PartitionTableParser.parse(source)

    assert len(partitions) == 1
    p0 = partitions[0]
    assert p0.partition_type == PartitionType.GPT
    assert p0.start_lba == 50
    assert p0.end_lba == 200
    assert p0.size_bytes == (200 - 50 + 1) * 512
    assert p0.name == "DataPartition"
    assert p0.type_guid.upper() == "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7"
    assert p0.validation == PartitionValidationOutcome.VALID
