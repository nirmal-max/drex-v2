"""
DREX-V2 Phase 8 Manifest & Package Integrity Tests
===================================================
Tests covering:
- Canonical manifest serialization & sorting
- Manifest SHA-256 root digest calculation
- Deterministic digest for identical manifest content
- Structural package files vs declared objects
"""

import hashlib
import json
import tarfile
from pathlib import Path

import pytest

import drex_verify
from forensic_vault import (
    CasePackageManager,
    EvidenceSourceType,
    ForensicCaseManager,
    StreamingHasher,
    canonical_json_bytes,
)


@pytest.fixture
def sample_case_package(tmp_path: Path) -> Path:
    """Create a fully populated Schema 2.0 evidence package for testing."""
    vault_base = tmp_path / "vault_base"
    mgr = ForensicCaseManager(vault_base)
    case = mgr.create_case("CASE-2026-MAN01", "Manifest Test Case", "Examiner Alpha", "Forensics Div")

    # Create dummy evidence file
    ev_file = tmp_path / "disk_evidence.bin"
    ev_file.write_bytes(b"\x55\xAA" * 1024)
    mgr.register_evidence(case.case_id, EvidenceSourceType.FILE, str(ev_file), "Examiner Alpha")

    cdir = mgr._case_path(case.case_id)
    pkg_tar = tmp_path / "exported_pkg.tar.gz"
    CasePackageManager.export_package(cdir, pkg_tar, schema_version="2.0")
    return pkg_tar


class TestManifestIntegrity:
    def test_canonical_manifest_serialization_determinism(self):
        """Identical dictionary data must produce identical canonical JSON bytes and SHA-256."""
        data_a = {
            "schema_version": "2.0",
            "package_id": "PKG-001",
            "case_id": "CASE-001",
            "total_objects": 2,
            "objects": [
                {"relative_path": "a.txt", "size_bytes": 10, "sha256": "abc"},
                {"relative_path": "b.txt", "size_bytes": 20, "sha256": "def"},
            ],
        }
        # Inverted key order in input dictionary
        data_b = {
            "objects": [
                {"sha256": "abc", "size_bytes": 10, "relative_path": "a.txt"},
                {"size_bytes": 20, "relative_path": "b.txt", "sha256": "def"},
            ],
            "total_objects": 2,
            "case_id": "CASE-001",
            "package_id": "PKG-001",
            "schema_version": "2.0",
        }

        bytes_a = drex_verify.canonical_json_bytes(data_a)
        bytes_b = drex_verify.canonical_json_bytes(data_b)

        assert bytes_a == bytes_b
        assert hashlib.sha256(bytes_a).hexdigest() == hashlib.sha256(bytes_b).hexdigest()

    def test_manifest_sha256_root_binding(self, sample_case_package: Path):
        """Exported package must contain manifest.sha256 matching manifest.json."""
        verifier = drex_verify.IndependentPackageVerifier(sample_case_package)
        report = verifier.verify()

        assert report.final_verdict == drex_verify.VerificationVerdict.PASS
        assert report.exit_code == int(drex_verify.ExitCode.PASS)
        assert report.manifest_sha256 is not None
        assert len(report.manifest_sha256) == 64

    def test_structural_files_distinguished_from_declared_objects(self, tmp_path: Path):
        """Structural files (manifest.json, manifest.sha256, README.txt) must not be flagged as unexpected."""
        pkg_dir = tmp_path / "raw_pkg_dir"
        pkg_dir.mkdir()
        (pkg_dir / "case").mkdir()

        # Create declared object
        obj_file = pkg_dir / "case" / "case.json"
        obj_content = b'{"case_id": "CASE-001"}'
        obj_file.write_bytes(obj_content)
        obj_sha = hashlib.sha256(obj_content).hexdigest()

        # Create manifest declaring only case/case.json
        manifest = {
            "schema_version": "2.0",
            "package_id": "PKG-001",
            "case_id": "CASE-001",
            "objects": [
                {
                    "relative_path": "case/case.json",
                    "size_bytes": len(obj_content),
                    "sha256": obj_sha,
                }
            ],
        }
        manifest_bytes = drex_verify.canonical_json_bytes(manifest)
        (pkg_dir / "manifest.json").write_bytes(manifest_bytes)
        (pkg_dir / "manifest.sha256").write_text(f"{hashlib.sha256(manifest_bytes).hexdigest()}  manifest.json\n")
        (pkg_dir / "README.txt").write_text("DREX Evidence Package Readme\n")

        verifier = drex_verify.IndependentPackageVerifier(pkg_dir)
        report = verifier.verify()

        assert report.final_verdict == drex_verify.VerificationVerdict.PASS
        assert report.summary.objects_declared == 1
        assert report.summary.objects_verified == 1
        assert report.summary.objects_unexpected == 0
