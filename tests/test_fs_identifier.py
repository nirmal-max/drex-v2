"""
Acceptance Tests for Filesystem Identification Engine
File: tests/test_fs_identifier.py
Phase: 3 / 12
"""

import struct
import pytest

from fs_base import FilesystemKind, SyntheticFixtureSource
from fs_identifier import FilesystemIdentifier


def test_identify_ntfs():
    """Verify NTFS signature and geometry identification."""
    data = bytearray(512)
    data[3:11] = b"NTFS    "
    struct.pack_into("<HB", data, 11, 512, 8)
    data[510:512] = b"\x55\xaa"
    source = SyntheticFixtureSource(bytes(data))
    fs_kind, desc = FilesystemIdentifier.identify(source)
    assert fs_kind == FilesystemKind.NTFS
    assert "SectorSize=512" in desc


def test_identify_exfat():
    """Verify exFAT signature and shift geometry identification."""
    data = bytearray(512)
    data[3:11] = b"EXFAT   "
    data[108] = 9  # 512 bytes
    data[109] = 3  # 8 sectors
    data[510:512] = b"\x55\xaa"
    source = SyntheticFixtureSource(bytes(data))
    fs_kind, desc = FilesystemIdentifier.identify(source)
    assert fs_kind == FilesystemKind.EXFAT
    assert "ClusterSize=4096" in desc


def test_identify_fat32():
    """Verify FAT32 signature identification."""
    data = bytearray(512)
    struct.pack_into("<HBHBH", data, 11, 512, 8, 32, 2, 0)
    struct.pack_into("<I", data, 32, 1000000)  # total sectors
    struct.pack_into("<I", data, 36, 1000)     # sectors per fat
    data[82:90] = b"FAT32   "
    data[510:512] = b"\x55\xaa"
    source = SyntheticFixtureSource(bytes(data))
    fs_kind, desc = FilesystemIdentifier.identify(source)
    assert fs_kind == FilesystemKind.FAT32


def test_identify_ext4():
    """Verify EXT4 superblock magic and feature flags identification."""
    data = bytearray(2048)
    # Superblock at offset 1024
    struct.pack_into("<IIIIIII", data, 1024, 100, 100, 0, 0, 0, 0, 2)  # 4096 block size
    struct.pack_into("<H", data, 1024 + 56, 0xEF53)                     # Magic
    struct.pack_into("<III", data, 1024 + 92, 0x0004, 0x0040, 0)       # extents flag
    source = SyntheticFixtureSource(bytes(data))
    fs_kind, desc = FilesystemIdentifier.identify(source)
    assert fs_kind == FilesystemKind.EXT4
    assert "Extents=YES" in desc


def test_identify_hfs_plus():
    """Verify HFS+ volume header signature identification."""
    data = bytearray(2048)
    data[1024:1026] = b"H+"
    source = SyntheticFixtureSource(bytes(data))
    fs_kind, desc = FilesystemIdentifier.identify(source)
    assert fs_kind == FilesystemKind.HFS_PLUS


def test_identify_apfs():
    """Verify APFS container superblock signature identification."""
    data = bytearray(512)
    data[32:36] = b"NXSB"
    source = SyntheticFixtureSource(bytes(data))
    fs_kind, desc = FilesystemIdentifier.identify(source)
    assert fs_kind == FilesystemKind.APFS


def test_identify_iso9660():
    """Verify ISO9660 primary volume descriptor signature identification."""
    data = bytearray(33000)
    data[32769:32774] = b"CD001"
    source = SyntheticFixtureSource(bytes(data))
    fs_kind, desc = FilesystemIdentifier.identify(source)
    assert fs_kind == FilesystemKind.ISO9660
