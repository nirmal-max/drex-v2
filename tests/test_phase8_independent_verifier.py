"""
DREX-V2 Phase 8 Independent Verifier Tests
===========================================
Tests covering:
- Headless CLI interface (args, --json, --out, --verbose)
- Exit codes (0=PASS, 1=TAMPERED, 2=INCOMPLETE, 3=INVALID, 4=INDETERMINATE)
- Generation of machine-readable verification_report.json and .sha256
- Zero GUI/hardware dependencies verification
"""

import json
import subprocess
import sys
from pathlib import Path

import pytest

import drex_verify
from forensic_vault import (
    CasePackageManager,
    EvidenceSourceType,
    ForensicCaseManager,
)


@pytest.fixture
def valid_package_path(tmp_path: Path) -> Path:
    vault_base = tmp_path / "valid_vault"
    mgr = ForensicCaseManager(vault_base)
    case = mgr.create_case("CASE-VERIF-01", "Verifier Test Case", "Examiner Verif", "Cyber Forensics")

    ev_file = tmp_path / "sample_ev.txt"
    ev_file.write_bytes(b"Evidence file payload data for independent verification.")
    mgr.register_evidence(case.case_id, EvidenceSourceType.FILE, str(ev_file), "Examiner Verif")

    cdir = mgr._case_path(case.case_id)
    pkg_path = tmp_path / "test_pkg.tar.gz"
    CasePackageManager.export_package(cdir, pkg_path, schema_version="2.0")
    return pkg_path


class TestIndependentVerifier:
    def test_programmatic_verification_pass(self, valid_package_path: Path):
        """Programmatic verification on a valid package must return PASS with exit code 0."""
        verifier = drex_verify.IndependentPackageVerifier(valid_package_path)
        report = verifier.verify()

        assert report.final_verdict == drex_verify.VerificationVerdict.PASS
        assert report.exit_code == 0
        assert report.summary.objects_declared > 0
        assert report.summary.objects_verified == report.summary.objects_declared
        assert report.summary.objects_missing == 0
        assert report.summary.objects_tampered == 0
        assert report.summary.audit_events_verified > 0

    def test_cli_execution_human_output(self, valid_package_path: Path):
        """CLI invocation without flags prints human-readable table and exits with code 0."""
        verifier_script = Path(__file__).resolve().parent.parent / "drex_verify.py"
        res = subprocess.run(
            [sys.executable, str(verifier_script), str(valid_package_path)],
            capture_output=True,
            text=True,
        )

        assert res.returncode == 0
        assert "FINAL VERDICT:   [PASS]" in res.stdout
        assert "Objects Verified:" in res.stdout

    def test_cli_execution_json_output(self, valid_package_path: Path):
        """CLI invocation with --json outputs valid parseable JSON."""
        verifier_script = Path(__file__).resolve().parent.parent / "drex_verify.py"
        res = subprocess.run(
            [sys.executable, str(verifier_script), str(valid_package_path), "--json"],
            capture_output=True,
            text=True,
        )

        assert res.returncode == 0
        data = json.loads(res.stdout)
        assert data["final_verdict"] == "PASS"
        assert data["exit_code"] == 0
        assert "summary" in data
        assert "truth_model_summary" in data

    def test_report_generation_with_sha256(self, valid_package_path: Path, tmp_path: Path):
        """Verifier --out flag generates verification_report.json and verification_report.sha256."""
        out_report = tmp_path / "verification_report.json"
        verifier_script = Path(__file__).resolve().parent.parent / "drex_verify.py"

        res = subprocess.run(
            [sys.executable, str(verifier_script), str(valid_package_path), "--out", str(out_report)],
            capture_output=True,
            text=True,
        )

        assert res.returncode == 0
        assert out_report.is_file()
        sha_file = out_report.with_suffix(".sha256")
        assert sha_file.is_file()

        # Validate sha256 binding on report
        report_bytes = out_report.read_bytes()
        expected_sha = drex_verify.hash_bytes_sha256(report_bytes)
        recorded_sha = sha_file.read_text(encoding="utf-8").strip().split()[0]
        assert recorded_sha == expected_sha

    def test_missing_manifest_json_invalid(self, tmp_path: Path):
        """Missing manifest.json must produce INVALID with exit code 3."""
        pkg_dir = tmp_path / "pkg_no_manifest"
        pkg_dir.mkdir()
        (pkg_dir / "manifest.sha256").write_text("0" * 64)
        verifier = drex_verify.IndependentPackageVerifier(pkg_dir)
        report = verifier.verify()
        assert report.final_verdict == drex_verify.VerificationVerdict.INVALID
        assert report.exit_code == int(drex_verify.ExitCode.INVALID)

    def test_missing_manifest_sha256_invalid(self, tmp_path: Path):
        """Missing manifest.sha256 must produce INVALID with exit code 3."""
        pkg_dir = tmp_path / "pkg_no_sha"
        pkg_dir.mkdir()
        (pkg_dir / "manifest.json").write_text(json.dumps({
            "schema_version": "2.0",
            "package_id": "PKG-001",
            "case_id": "CASE-001",
            "objects": []
        }))
        verifier = drex_verify.IndependentPackageVerifier(pkg_dir)
        report = verifier.verify()
        assert report.final_verdict == drex_verify.VerificationVerdict.INVALID
        assert report.exit_code == int(drex_verify.ExitCode.INVALID)

    def test_missing_declared_evidence_incomplete(self, tmp_path: Path):
        """Valid Schema 2.0 package with missing declared evidence object must produce INCOMPLETE with exit code 2."""
        pkg_dir = tmp_path / "pkg_missing_ev"
        pkg_dir.mkdir()
        (pkg_dir / "case").mkdir()
        case_file = pkg_dir / "case" / "case_metadata.json"
        case_file.write_text(json.dumps({"case_id": "CASE-001"}))
        case_sha, case_size = drex_verify.hash_file_streaming(case_file)

        manifest = {
            "schema_version": "2.0",
            "package_id": "PKG-001",
            "case_id": "CASE-001",
            "objects": [
                {"relative_path": "case/case_metadata.json", "sha256": case_sha, "size_bytes": case_size},
                {"relative_path": "evidence/missing_drive.raw", "sha256": "a" * 64, "size_bytes": 1024}
            ]
        }
        m_bytes = drex_verify.canonical_json_bytes(manifest)
        (pkg_dir / "manifest.json").write_bytes(m_bytes)
        (pkg_dir / "manifest.sha256").write_text(f"{drex_verify.hash_bytes_sha256(m_bytes)}  manifest.json\n")

        verifier = drex_verify.IndependentPackageVerifier(pkg_dir)
        report = verifier.verify()
        assert report.final_verdict == drex_verify.VerificationVerdict.INCOMPLETE
        assert report.exit_code == int(drex_verify.ExitCode.INCOMPLETE)
        assert report.summary.objects_missing == 1
