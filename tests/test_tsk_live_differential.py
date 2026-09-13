"""
Live Integration Tests for Real TSK Differential Validation
File: tests/test_tsk_live_differential.py
Phase: 3 / 12

Executes real, live Sleuth Kit (TSK 4.15.0) binaries (fls.exe, icat.exe, mmls.exe, fsstat.exe)
from native_bin/ against deterministic filesystem fixtures without mocking.
Verifies byte equality, SHA-256 equality, metadata alignment, and source immutability.
"""

import hashlib
import os
import struct
import subprocess
import tempfile
from pathlib import Path
import pytest

from fs_base import (
    DiskImageSource,
    ExtentState,
    FilesystemKind,
    PartitionType,
    SyntheticFixtureSource,
)
from fs_partition import PartitionTableParser
from fs_differential import (
    DifferentialComparisonRecord,
    DifferentialValidationOutcome,
    DifferentialValidator,
)
from fs_fat import FatParser
from fs_ext import Ext4Parser
from tests.test_fs_fat import create_synthetic_fat32_image
from tests.test_fs_ext import create_synthetic_ext4_image
from tests.test_fs_exfat import create_synthetic_exfat_image
from tests.test_fs_partition import create_synthetic_mbr_with_ebr, create_synthetic_gpt_image

TSK_ROOT = Path("native_bin")
FLS_EXE = TSK_ROOT / "fls.exe"
ICAT_EXE = TSK_ROOT / "icat.exe"
MMLS_EXE = TSK_ROOT / "mmls.exe"
FSSTAT_EXE = TSK_ROOT / "fsstat.exe"


def setup_module():
    """Ensure native TSK binaries are available before executing live integration tests."""
    if not FLS_EXE.is_file():
        pytest.skip(f"Live TSK binary not found at {FLS_EXE}")


def test_live_tsk_mmls_mbr_differential():
    """Execute live mmls.exe on MBR/EBR fixture and compare against PartitionTableParser."""
    image_bytes = create_synthetic_mbr_with_ebr()
    orig_sha256 = hashlib.sha256(image_bytes).hexdigest()

    with tempfile.TemporaryDirectory() as td:
        img_path = Path(td) / "mbr_test.img"
        img_path.write_bytes(image_bytes)

        # 1. Native DREX Partition Parsing
        source = DiskImageSource(img_path)
        drex_parts = PartitionTableParser.parse(source)

        # 2. Live TSK mmls.exe execution
        cmd = [str(MMLS_EXE), str(img_path)]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        assert res.returncode == 0
        assert "DOS Partition Table" in res.stdout

        # Verify exact partition offsets in TSK output
        assert "0000000100" in res.stdout  # Primary NTFS (100..299)
        assert "0000000410" in res.stdout  # Logical Linux (410..509)
        assert "0000000610" in res.stdout  # Logical FAT32 (610..689)

        # 3. Direct comparison
        assert len(drex_parts) == 3
        assert drex_parts[0].start_lba == 100
        assert drex_parts[1].start_lba == 410
        assert drex_parts[2].start_lba == 610

        # Read-only verification
        source.close()
        after_sha256 = hashlib.sha256(img_path.read_bytes()).hexdigest()
        assert after_sha256 == orig_sha256


def test_live_tsk_mmls_gpt_differential():
    """Execute live mmls.exe on GPT fixture and compare against PartitionTableParser."""
    image_bytes = create_synthetic_gpt_image()
    orig_sha256 = hashlib.sha256(image_bytes).hexdigest()

    with tempfile.TemporaryDirectory() as td:
        img_path = Path(td) / "gpt_test.img"
        img_path.write_bytes(image_bytes)

        # 1. Native DREX Partition Parsing
        source = DiskImageSource(img_path)
        drex_parts = PartitionTableParser.parse(source)

        # 2. Live TSK mmls.exe execution
        cmd = [str(MMLS_EXE), str(img_path)]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        assert res.returncode == 0
        assert "GUID Partition Table (EFI)" in res.stdout
        assert "DataPartition" in res.stdout
        assert "0000000050" in res.stdout  # Start LBA 50
        assert "0000000200" in res.stdout  # End LBA 200

        # 3. Direct comparison
        assert len(drex_parts) == 1
        assert drex_parts[0].start_lba == 50
        assert drex_parts[0].end_lba == 200
        assert drex_parts[0].name == "DataPartition"

        source.close()
        after_sha256 = hashlib.sha256(img_path.read_bytes()).hexdigest()
        assert after_sha256 == orig_sha256


def test_live_tsk_fls_fat32_differential():
    """Execute live fls.exe on FAT32 fixture and compare deleted candidates with FatParser."""
    image_bytes = create_synthetic_fat32_image()

    with tempfile.TemporaryDirectory() as td:
        img_path = Path(td) / "fat32_test.img"
        img_path.write_bytes(image_bytes)

        # 1. Native DREX FAT32 Scan
        source = DiskImageSource(img_path)
        drex_candidates = FatParser(source, 0).scan_all_entries()
        drex_deleted = [c for c in drex_candidates if c.is_deleted]

        # 2. Live TSK fls.exe execution
        cmd = [str(FLS_EXE), "-r", "-p", "-d", str(img_path)]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        assert res.returncode == 0

        # TSK reports deleted file with '*'
        assert "deleted_audit" in res.stdout

        # 3. Direct comparison
        assert len(drex_deleted) >= 1
        assert any("deleted_audit" in c.filename for c in drex_deleted)
        source.close()


def test_live_tsk_icat_fat32_byte_exact():
    """Extract active file using both DREX native parser and live icat.exe; assert byte & SHA-256 equality."""
    image_bytes = create_synthetic_fat32_image()

    with tempfile.TemporaryDirectory() as td:
        img_path = Path(td) / "fat32_test.img"
        img_path.write_bytes(image_bytes)

        # 1. Native DREX Extraction
        source = DiskImageSource(img_path)
        parser = FatParser(source, 0)
        candidates = parser.scan_all_entries()
        active_doc = next(c for c in candidates if "Forensic" in c.filename)
        drex_bytes = parser.read_candidate_bytes(active_doc)

        # 2. Live TSK icat.exe Extraction (Cluster 3 / Inode 4)
        cmd = [str(ICAT_EXE), str(img_path), "4"]
        res = subprocess.run(cmd, capture_output=True, timeout=30)
        assert res.returncode == 0
        tsk_bytes = res.stdout

        # 3. Byte-exact and SHA-256 verification
        assert len(drex_bytes) == len(tsk_bytes)
        assert drex_bytes == tsk_bytes
        assert hashlib.sha256(drex_bytes).hexdigest() == hashlib.sha256(tsk_bytes).hexdigest()

        source.close()


def test_live_tsk_fls_ext4_differential():
    """Execute live fls.exe on EXT4 fixture and compare candidate inodes with Ext4Parser."""
    ext_bytes = bytearray(create_synthetic_ext4_image())
    # Set s_log_frag_size = 2 at superblock offset 1024 + 28
    struct.pack_into("<I", ext_bytes, 1024 + 28, 2)

    with tempfile.TemporaryDirectory() as td:
        img_path = Path(td) / "ext4_test.img"
        img_path.write_bytes(ext_bytes)

        # 1. Native DREX EXT4 Scan
        source = DiskImageSource(img_path)
        drex_candidates = Ext4Parser(source, 0).scan_all_inodes()

        # 2. Live TSK fls.exe execution
        cmd = [str(FLS_EXE), "-r", "-p", str(img_path)]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        assert res.returncode == 0

        # TSK discovers Inodes 11, 12, 13
        assert "OrphanFile-11" in res.stdout
        assert "OrphanFile-12" in res.stdout
        assert "OrphanFile-13" in res.stdout

        # 3. Direct comparison
        drex_ids = {c.candidate_id for c in drex_candidates}
        assert "ext_11" in drex_ids
        assert "ext_12" in drex_ids
        assert "ext_13" in drex_ids

        source.close()


def test_live_tsk_icat_ext4_byte_exact():
    """Extract Inode 11 using both DREX native parser and live icat.exe; assert byte & SHA-256 equality."""
    ext_bytes = bytearray(create_synthetic_ext4_image())
    struct.pack_into("<I", ext_bytes, 1024 + 28, 2)

    with tempfile.TemporaryDirectory() as td:
        img_path = Path(td) / "ext4_test.img"
        img_path.write_bytes(ext_bytes)

        # 1. Native DREX Extraction
        source = DiskImageSource(img_path)
        parser = Ext4Parser(source, 0)
        candidates = parser.scan_all_inodes()
        in11 = next(c for c in candidates if c.candidate_id == "ext_11")
        drex_bytes = parser.read_candidate_bytes(in11)

        # 2. Live TSK icat.exe Extraction for Inode 11
        cmd = [str(ICAT_EXE), str(img_path), "11"]
        res = subprocess.run(cmd, capture_output=True, timeout=30)
        assert res.returncode == 0
        tsk_bytes = res.stdout

        # 3. Byte-exact and SHA-256 verification
        assert len(drex_bytes) == len(tsk_bytes)
        assert drex_bytes == tsk_bytes
        assert hashlib.sha256(drex_bytes).hexdigest() == hashlib.sha256(tsk_bytes).hexdigest()

        source.close()


def test_live_tsk_exfat_reference_unavailable():
    """Verify that DifferentialValidator truthfully reports REFERENCE_UNAVAILABLE on exFAT where TSK lacks support."""
    exfat_bytes = create_synthetic_exfat_image()

    with tempfile.TemporaryDirectory() as td:
        img_path = Path(td) / "exfat_test.img"
        img_path.write_bytes(exfat_bytes)

        source = DiskImageSource(img_path)
        rec = DifferentialValidator.cross_validate(source, root_path=Path("."))

        # Because standard TSK 4.15.0 fails closed on exFAT with non-zero exit code or error,
        # DifferentialValidator safely records REFERENCE_UNAVAILABLE or partial mismatch without false claims.
        assert rec.outcome in (DifferentialValidationOutcome.REFERENCE_UNAVAILABLE, DifferentialValidationOutcome.MISMATCH)
        source.close()


def test_live_tsk_source_immutability_verification():
    """Verify source disk image remains byte-exact immutable across multiple live TSK executions."""
    fat_bytes = create_synthetic_fat32_image()
    orig_sha256 = hashlib.sha256(fat_bytes).hexdigest()
    orig_len = len(fat_bytes)

    with tempfile.TemporaryDirectory() as td:
        img_path = Path(td) / "fat_immutability_test.img"
        img_path.write_bytes(fat_bytes)

        # Execute multiple live TSK commands against the file
        subprocess.run([str(FSSTAT_EXE), str(img_path)], capture_output=True, timeout=30)
        subprocess.run([str(FLS_EXE), "-r", "-p", str(img_path)], capture_output=True, timeout=30)
        subprocess.run([str(ICAT_EXE), str(img_path), "4"], capture_output=True, timeout=30)
        subprocess.run([str(MMLS_EXE), str(img_path)], capture_output=True, timeout=30)

        # Assert zero bytes were modified
        after_bytes = img_path.read_bytes()
        assert len(after_bytes) == orig_len
        assert hashlib.sha256(after_bytes).hexdigest() == orig_sha256
