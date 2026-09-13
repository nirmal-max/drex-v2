"""
Forensic Safety, Source Immutability, and Adversarial Acceptance Tests
File: tests/test_fs_safety.py
Phase: 3 / 12
"""

import hashlib
import tempfile
from pathlib import Path
import pytest

from fs_base import (
    ExtentRun,
    ExtentState,
    FilesystemKind,
    FsCandidateRecord,
    PathState,
    SyntheticFixtureSource,
)
from fs_partition import PartitionTableParser
from fs_recovery import DirectoryTreeReconstructor, FilesystemRecoveryEngine
from tests.test_fs_ntfs import create_synthetic_ntfs_image


def test_source_sha256_and_length_immutability_before_after():
    """Verify source disk image remains byte-exact immutable (delta Hash == 0) across recovery operations."""
    source_bytes = create_synthetic_ntfs_image()
    orig_length = len(source_bytes)
    orig_sha256 = hashlib.sha256(source_bytes).hexdigest()

    source = SyntheticFixtureSource(source_bytes)

    # 1. Execute full source scan
    candidates = FilesystemRecoveryEngine.scan_source(source)
    assert len(candidates) > 0

    # 2. Execute recovery of discovered candidate to temp directory
    with tempfile.TemporaryDirectory() as tmp_dir:
        del_note = next(c for c in candidates if c.filename == "deleted_note.txt")
        ok, out_path, sha256_hash, meta = FilesystemRecoveryEngine.recover_candidate(
            source=source,
            candidate=del_note,
            destination_dir=tmp_dir,
        )
        assert ok is True
        assert out_path.exists()
        assert out_path.read_bytes() == b"DELETED_RESIDENT_CONFIDENTIAL_FORENSIC_NOTE_2026.TXT"

    # 3. Post-recovery Immutability Invariant Verification
    after_bytes = source.read(0, source.get_size())
    after_length = len(after_bytes)
    after_sha256 = hashlib.sha256(after_bytes).hexdigest()

    assert after_length == orig_length
    assert after_sha256 == orig_sha256


def test_destination_collision_rejection():
    """Verify destination collision safety interlock rejects dangerous paths."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        dest_path = Path(tmp_dir).resolve()
        source_same = str(dest_path)

        # 1. Rejects identical source and destination
        with pytest.raises(ValueError, match="Destination collision: Destination cannot be identical to source"):
            FilesystemRecoveryEngine.validate_destination(source_same, dest_path)

        # 2. Rejects destination nested inside source
        sub_dest = dest_path / "sub_folder"
        with pytest.raises(ValueError, match="Destination collision"):
            FilesystemRecoveryEngine.validate_destination(source_same, sub_dest)


def test_path_traversal_sanitization():
    """Verify directory traversal and illegal characters are stripped safely."""
    assert DirectoryTreeReconstructor.sanitize_name("../../etc/passwd") == "_.._etc_passwd"
    assert DirectoryTreeReconstructor.sanitize_name("C:\\Windows\\System32\\cmd.exe") == "C__Windows_System32_cmd.exe"
    assert DirectoryTreeReconstructor.sanitize_name("..") == "unnamed_artifact"
    assert DirectoryTreeReconstructor.sanitize_name("test<file>:name|?.txt") == "test_file__name__.txt"


def test_cyclic_directory_loop_termination():
    """Verify cyclic directory references terminate safely without infinite recursion."""
    # Synthesize cyclic candidate references (A -> B -> C -> A)
    cand_a = FsCandidateRecord(
        candidate_id="cand_a",
        filesystem=FilesystemKind.NTFS,
        filename="folder_a",
        is_directory=True,
        parent_id="cand_c",
        source_record_id="cand_a",
    )
    cand_b = FsCandidateRecord(
        candidate_id="cand_b",
        filesystem=FilesystemKind.NTFS,
        filename="folder_b",
        is_directory=True,
        parent_id="cand_a",
        source_record_id="cand_b",
    )
    cand_c = FsCandidateRecord(
        candidate_id="cand_c",
        filesystem=FilesystemKind.NTFS,
        filename="folder_c",
        is_directory=True,
        parent_id="cand_b",
        source_record_id="cand_c",
    )
    cand_file = FsCandidateRecord(
        candidate_id="cand_file",
        filesystem=FilesystemKind.NTFS,
        filename="file.txt",
        is_directory=False,
        parent_id="cand_a",
        source_record_id="cand_file",
    )

    reconstructed = DirectoryTreeReconstructor.reconstruct_paths([cand_a, cand_b, cand_c, cand_file])
    file_cand = next(c for c in reconstructed if c.candidate_id == "cand_file")
    assert file_cand.reconstructed_path is not None
    assert len(file_cand.reconstructed_path.split("/")) <= DirectoryTreeReconstructor.MAX_DEPTH


def test_partition_bounds_and_truncated_image_safety():
    """Verify parser fails closed safely on truncated or malformed partition tables."""
    # Source with fewer than 512 bytes
    short_source = SyntheticFixtureSource(b"\x00" * 128)
    parts = PartitionTableParser.parse(short_source)
    assert len(parts) == 1
    assert parts[0].size_bytes == 128

    # Source with corrupted partition table signatures
    corrupt_source = SyntheticFixtureSource(b"\x00" * 4096)
    parts_corrupt = PartitionTableParser.parse(corrupt_source)
    assert len(parts_corrupt) == 1
    assert parts_corrupt[0].name == "RAW_VOLUME"
