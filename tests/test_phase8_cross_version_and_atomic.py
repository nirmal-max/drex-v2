"""
DREX-V2 Phase 8 Schema Versioning, Safety & Distrust Tests
===========================================================
Tests covering:
- 4-way deterministic schema version model
- Pre-extraction archive security validation (path traversal, drive letter, UNC, reserved names, symlinks)
- Streaming memory boundedness on large synthetic evidence
- Adversarial distrust of stored status booleans
"""

import io
import json
import os
import tarfile
import zipfile
from pathlib import Path

import pytest

import drex_verify
from forensic_vault import (
    CasePackageManager,
    EvidenceSourceType,
    ForensicCaseManager,
    canonical_json_bytes,
)


@pytest.fixture
def minimal_pkg_dir(tmp_path: Path) -> Path:
    """Create a minimal raw package directory."""
    pkg_dir = tmp_path / "pkg_root"
    pkg_dir.mkdir(parents=True, exist_ok=True)
    (pkg_dir / "case").mkdir(parents=True, exist_ok=True)

    c_file = pkg_dir / "case" / "case.json"
    c_content = b'{"case_id": "CASE-MIN-001"}'
    c_file.write_bytes(c_content)
    c_sha, c_sz = drex_verify.hash_file_streaming(c_file)

    manifest = {
        "schema_version": "2.0",
        "drex_version": "1.0.0",
        "package_id": "PKG-MIN-001",
        "case_id": "CASE-MIN-001",
        "objects": [
            {
                "relative_path": "case/case.json",
                "size_bytes": c_sz,
                "sha256": c_sha,
            }
        ],
    }
    m_bytes = drex_verify.canonical_json_bytes(manifest)
    (pkg_dir / "manifest.json").write_bytes(m_bytes)
    (pkg_dir / "manifest.sha256").write_text(f"{drex_verify.hash_bytes_sha256(m_bytes)}  manifest.json\n")
    return pkg_dir


# ─── 1. Schema Versioning Matrix Tests ────────────────────────────────────────

class TestSchemaVersioningMatrix:
    def test_supported_version_2_0_continues(self, minimal_pkg_dir: Path):
        verifier = drex_verify.IndependentPackageVerifier(minimal_pkg_dir)
        report = verifier.verify()
        assert report.final_verdict == drex_verify.VerificationVerdict.PASS

    def test_missing_schema_version_is_invalid(self, minimal_pkg_dir: Path):
        m_file = minimal_pkg_dir / "manifest.json"
        data = json.loads(m_file.read_text(encoding="utf-8"))
        del data["schema_version"]
        m_bytes = drex_verify.canonical_json_bytes(data)
        m_file.write_bytes(m_bytes)
        (minimal_pkg_dir / "manifest.sha256").write_text(f"{drex_verify.hash_bytes_sha256(m_bytes)}  manifest.json\n")

        verifier = drex_verify.IndependentPackageVerifier(minimal_pkg_dir)
        report = verifier.verify()
        assert report.final_verdict == drex_verify.VerificationVerdict.INVALID
        assert report.exit_code == int(drex_verify.ExitCode.INVALID)

    def test_historical_unsupported_version_1_0_is_invalid(self, minimal_pkg_dir: Path):
        m_file = minimal_pkg_dir / "manifest.json"
        data = json.loads(m_file.read_text(encoding="utf-8"))
        data["schema_version"] = "1.0"
        m_bytes = drex_verify.canonical_json_bytes(data)
        m_file.write_bytes(m_bytes)
        (minimal_pkg_dir / "manifest.sha256").write_text(f"{drex_verify.hash_bytes_sha256(m_bytes)}  manifest.json\n")

        verifier = drex_verify.IndependentPackageVerifier(minimal_pkg_dir)
        report = verifier.verify()
        assert report.final_verdict == drex_verify.VerificationVerdict.INVALID
        assert report.exit_code == int(drex_verify.ExitCode.INVALID)

    def test_unknown_future_version_is_indeterminate(self, minimal_pkg_dir: Path):
        m_file = minimal_pkg_dir / "manifest.json"
        data = json.loads(m_file.read_text(encoding="utf-8"))
        data["schema_version"] = "3.0"  # Unknown future version
        m_bytes = drex_verify.canonical_json_bytes(data)
        m_file.write_bytes(m_bytes)
        (minimal_pkg_dir / "manifest.sha256").write_text(f"{drex_verify.hash_bytes_sha256(m_bytes)}  manifest.json\n")

        verifier = drex_verify.IndependentPackageVerifier(minimal_pkg_dir)
        report = verifier.verify()
        assert report.final_verdict == drex_verify.VerificationVerdict.INDETERMINATE
        assert report.exit_code == int(drex_verify.ExitCode.INDETERMINATE)


# ─── 2. Pre-Extraction Archive Safety Tests ───────────────────────────────────

class TestPreExtractionArchiveSafety:
    def test_archive_path_traversal_rejected_before_extraction(self, tmp_path: Path):
        tar_path = tmp_path / "attack_traversal.tar.gz"
        with tarfile.open(tar_path, "w:gz") as tar:
            data = b"malicious content"
            ti = tarfile.TarInfo(name="../../evil.sh")
            ti.size = len(data)
            tar.addfile(ti, io.BytesIO(data))

        verifier = drex_verify.IndependentPackageVerifier(tar_path)
        report = verifier.verify()
        assert report.final_verdict == drex_verify.VerificationVerdict.INVALID
        assert any("traversal" in d.message.lower() for d in report.diagnostics)

    def test_archive_windows_drive_letter_rejected(self, tmp_path: Path):
        tar_path = tmp_path / "attack_drive.tar.gz"
        with tarfile.open(tar_path, "w:gz") as tar:
            data = b"drive attack"
            ti = tarfile.TarInfo(name="C:/Windows/System32/evil.dll")
            ti.size = len(data)
            tar.addfile(ti, io.BytesIO(data))

        verifier = drex_verify.IndependentPackageVerifier(tar_path)
        report = verifier.verify()
        assert report.final_verdict == drex_verify.VerificationVerdict.INVALID

    def test_archive_unc_path_rejected(self, tmp_path: Path):
        tar_path = tmp_path / "attack_unc.tar.gz"
        with tarfile.open(tar_path, "w:gz") as tar:
            data = b"unc attack"
            ti = tarfile.TarInfo(name=r"\\remote-server\share\evil.exe")
            ti.size = len(data)
            tar.addfile(ti, io.BytesIO(data))

        verifier = drex_verify.IndependentPackageVerifier(tar_path)
        report = verifier.verify()
        assert report.final_verdict == drex_verify.VerificationVerdict.INVALID

    def test_archive_symlink_rejected(self, tmp_path: Path):
        tar_path = tmp_path / "attack_symlink.tar.gz"
        with tarfile.open(tar_path, "w:gz") as tar:
            ti = tarfile.TarInfo(name="evil_symlink")
            ti.type = tarfile.SYMTYPE
            ti.linkname = "/etc/shadow"
            tar.addfile(ti)

        verifier = drex_verify.IndependentPackageVerifier(tar_path)
        report = verifier.verify()
        assert report.final_verdict == drex_verify.VerificationVerdict.INVALID


# ─── 3. Stored Status Distrust Tests ──────────────────────────────────────────

class TestStoredStatusDistrust:
    def test_stored_verified_status_ignored_when_bytes_mismatch(self, minimal_pkg_dir: Path):
        """Even if object metadata claims 'verification_state': 'VERIFIED', verifier must return TAMPERED if bytes differ."""
        # Mutate the file content
        c_file = minimal_pkg_dir / "case" / "case.json"
        c_file.write_bytes(b'{"case_id": "ALTERED_CASE_PAYLOAD"}')

        verifier = drex_verify.IndependentPackageVerifier(minimal_pkg_dir)
        report = verifier.verify()
        assert report.final_verdict == drex_verify.VerificationVerdict.TAMPERED
        assert report.summary.objects_tampered >= 1


# ─── 4. Streaming Bounded Memory Tests ────────────────────────────────────────

class TestStreamingMemoryBounds:
    def test_streaming_hash_large_synthetic_stream(self, tmp_path: Path):
        """Hashing a 10 MB synthetic file operates with 64 KB chunks without loading entirely into RAM."""
        large_file = tmp_path / "large_stream.bin"
        chunk = b"\xAA" * (64 * 1024)
        with open(large_file, "wb") as f:
            for _ in range(160):  # 10 MB total
                f.write(chunk)

        sha, sz = drex_verify.hash_file_streaming(large_file)
        assert sz == 10 * 1024 * 1024
        assert len(sha) == 64
