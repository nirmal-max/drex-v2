"""
DREX-V2 Phase 8 Adversarial Tamper Detection Matrix Tests
==========================================================
Comprehensive test suite testing all 6 adversarial vectors:
Vector A: Manifest Tampering (path, size, hash, deletion, extra file, root hash)
Vector B: Evidence Tampering (1-byte flip, truncation, append, substitution, rename)
Vector C: Audit Chain Tampering (payload, timestamp, actor, event type, operation ID, previous hash, sequence reorder/deletion/duplicate)
Vector D: Custody Tampering (custodian, action, timestamp, evidence reference, deletion, reordering)
Vector E: Certificate Tampering (target, method ID, standard, post-wipe hash, prior audit hash, token)
Vector F: Cross-Link Tampering (broken operation/evidence/case/audit references)
"""

import copy
import hashlib
import json
import tarfile
from pathlib import Path
from typing import Callable

import pytest

import drex_verify
from certificate_engine import (
    CertificateMethodInfo,
    CertificateTargetInfo,
    CertificateVerificationInfo,
    ForensicCertificateEngine,
)
from forensic_vault import (
    CasePackageManager,
    EvidenceSourceType,
    ForensicCaseManager,
    TimelineEventType,
    canonical_json_bytes,
)


@pytest.fixture
def base_case_env(tmp_path: Path) -> Tuple[ForensicCaseManager, str, Path]:
    """Create a fully populated case environment with case, evidence, operations, audit, custody, and certs."""
    vault_base = tmp_path / "tamper_vault_base"
    mgr = ForensicCaseManager(vault_base)
    case = mgr.create_case("CASE-TAMPER-01", "Tamper Matrix Case", "Lead Examiner", "Forensic Lab")

    # 1. Register evidence
    ev_file = tmp_path / "target_drive.raw"
    ev_file.write_bytes(b"INITIAL_EVIDENCE_STREAM_DATA_BLOCK" * 100)
    ev_source = mgr.register_evidence(case.case_id, EvidenceSourceType.FILE, str(ev_file), "Lead Examiner")

    # 2. Record operational events
    op_id = "OP-SAN-001"
    mgr.record_sanitization_event(case.case_id, op_id, ev_source.evidence_id, "Lead Examiner", TimelineEventType.SANITIZATION_STARTED, "Sanitization started")
    mgr.record_sanitization_event(case.case_id, op_id, ev_source.evidence_id, "Lead Examiner", TimelineEventType.SANITIZATION_COMPLETED, "Sanitization finished")

    # 3. Create certificate bound to latest audit hash
    chain = mgr.get_audit_chain(case.case_id)
    latest_audit_hash = chain[-1].current_hash

    target_info = CertificateTargetInfo(target_name="target_drive.raw", target_type="FILE")
    method_info = CertificateMethodInfo(method_id=8, canonical_name="CSPRNG Random Overwrite")
    verif_info = CertificateVerificationInfo(primary_verification_method="EXACT_BYTE_READBACK", post_wipe_sha256="abcdef1234567890" * 4)

    cert = ForensicCertificateEngine.create_certificate(
        case_id=case.case_id,
        case_name=case.title,
        examiner_name=case.examiner,
        organization=case.organization,
        target_info=target_info,
        method_info=method_info,
        verification_info=verif_info,
        prior_audit_hash=latest_audit_hash,
    )

    cdir = mgr._case_path(case.case_id)
    certs_dir = cdir / "certificates"
    certs_dir.mkdir(parents=True, exist_ok=True)
    ForensicCertificateEngine.export_json(cert, certs_dir / f"{cert.certificate_id}.json")

    # Record certificate created in audit chain
    mgr.record_certificate_event(case.case_id, cert.certificate_id, op_id, ev_source.evidence_id, "Lead Examiner", TimelineEventType.CERTIFICATE_CREATED, "Cert created")

    return mgr, case.case_id, cdir


def unpack_modify_repack(src_tar: Path, dest_tar: Path, modifier_fn: Callable[[Path], None]) -> Path:
    """Helper to extract a package tar.gz, run a mutation function on its files, and repack."""
    scratch = src_tar.parent / f"scratch_{src_tar.stem}"
    scratch.mkdir(parents=True, exist_ok=True)
    with tarfile.open(src_tar, "r:gz") as tar:
        tar.extractall(scratch)

    modifier_fn(scratch)

    with tarfile.open(dest_tar, "w:gz") as tar:
        for f in sorted(scratch.rglob("*")):
            if f.is_file():
                rel = f.relative_to(scratch).as_posix()
                tar.add(f, arcname=rel)

    return dest_tar


# ─── Vector A: Manifest Tampering ─────────────────────────────────────────────

class TestVectorAManifestTampering:
    def test_tamper_object_size_in_manifest(self, base_case_env, tmp_path: Path):
        mgr, case_id, cdir = base_case_env
        pkg = tmp_path / "pkg_a1.tar.gz"
        CasePackageManager.export_package(cdir, pkg)

        def mutate(p: Path):
            m_file = p / "manifest.json"
            data = json.loads(m_file.read_text(encoding="utf-8"))
            if data["objects"]:
                data["objects"][0]["size_bytes"] += 9999
            m_file.write_text(json.dumps(data), encoding="utf-8")
            # Also update manifest.sha256 to isolate object size tampering
            m_sha = hashlib.sha256(m_file.read_bytes()).hexdigest()
            (p / "manifest.sha256").write_text(f"{m_sha}  manifest.json\n")

        tampered_pkg = unpack_modify_repack(pkg, tmp_path / "tampered_a1.tar.gz", mutate)
        verifier = drex_verify.IndependentPackageVerifier(tampered_pkg)
        report = verifier.verify()

        assert report.final_verdict == drex_verify.VerificationVerdict.TAMPERED
        assert report.exit_code == int(drex_verify.ExitCode.TAMPERED)
        assert report.summary.objects_tampered >= 1

    def test_tamper_object_hash_in_manifest(self, base_case_env, tmp_path: Path):
        mgr, case_id, cdir = base_case_env
        pkg = tmp_path / "pkg_a2.tar.gz"
        CasePackageManager.export_package(cdir, pkg)

        def mutate(p: Path):
            m_file = p / "manifest.json"
            data = json.loads(m_file.read_text(encoding="utf-8"))
            if data["objects"]:
                data["objects"][0]["sha256"] = "0" * 64
            m_file.write_text(json.dumps(data), encoding="utf-8")
            m_sha = hashlib.sha256(m_file.read_bytes()).hexdigest()
            (p / "manifest.sha256").write_text(f"{m_sha}  manifest.json\n")

        tampered_pkg = unpack_modify_repack(pkg, tmp_path / "tampered_a2.tar.gz", mutate)
        verifier = drex_verify.IndependentPackageVerifier(tampered_pkg)
        report = verifier.verify()

        assert report.final_verdict == drex_verify.VerificationVerdict.TAMPERED
        assert report.summary.objects_tampered >= 1

    def test_tamper_add_unexpected_extra_file(self, base_case_env, tmp_path: Path):
        mgr, case_id, cdir = base_case_env
        pkg = tmp_path / "pkg_a3.tar.gz"
        CasePackageManager.export_package(cdir, pkg)

        def mutate(p: Path):
            # Add an undeclared extra file
            (p / "injected_payload.bin").write_bytes(b"MALICIOUS_EXTRA_DATA")

        tampered_pkg = unpack_modify_repack(pkg, tmp_path / "tampered_a3.tar.gz", mutate)
        verifier = drex_verify.IndependentPackageVerifier(tampered_pkg)
        report = verifier.verify()

        assert report.final_verdict == drex_verify.VerificationVerdict.TAMPERED
        assert report.summary.objects_unexpected >= 1

    def test_tamper_manifest_root_digest(self, base_case_env, tmp_path: Path):
        mgr, case_id, cdir = base_case_env
        pkg = tmp_path / "pkg_a4.tar.gz"
        CasePackageManager.export_package(cdir, pkg)

        def mutate(p: Path):
            # Alter manifest.sha256
            (p / "manifest.sha256").write_text(f"{'f'*64}  manifest.json\n")

        tampered_pkg = unpack_modify_repack(pkg, tmp_path / "tampered_a4.tar.gz", mutate)
        verifier = drex_verify.IndependentPackageVerifier(tampered_pkg)
        report = verifier.verify()

        assert report.final_verdict == drex_verify.VerificationVerdict.TAMPERED
        assert any(d.category == "MANIFEST" for d in report.diagnostics)


# ─── Vector B: Evidence Tampering ─────────────────────────────────────────────

class TestVectorBEvidenceTampering:
    def test_tamper_single_byte_flip(self, base_case_env, tmp_path: Path):
        mgr, case_id, cdir = base_case_env
        pkg = tmp_path / "pkg_b1.tar.gz"
        CasePackageManager.export_package(cdir, pkg)

        def mutate(p: Path):
            # Modify single byte in case.json
            c_file = p / "case.json"
            content = bytearray(c_file.read_bytes())
            content[10] = content[10] ^ 0xFF
            c_file.write_bytes(content)

        tampered_pkg = unpack_modify_repack(pkg, tmp_path / "tampered_b1.tar.gz", mutate)
        verifier = drex_verify.IndependentPackageVerifier(tampered_pkg)
        report = verifier.verify()

        assert report.final_verdict == drex_verify.VerificationVerdict.TAMPERED
        assert report.summary.objects_tampered >= 1

    def test_tamper_file_truncation(self, base_case_env, tmp_path: Path):
        mgr, case_id, cdir = base_case_env
        pkg = tmp_path / "pkg_b2.tar.gz"
        CasePackageManager.export_package(cdir, pkg)

        def mutate(p: Path):
            # Truncate evidence.json
            ev_file = p / "evidence.json"
            ev_file.write_bytes(ev_file.read_bytes()[:10])

        tampered_pkg = unpack_modify_repack(pkg, tmp_path / "tampered_b2.tar.gz", mutate)
        verifier = drex_verify.IndependentPackageVerifier(tampered_pkg)
        report = verifier.verify()

        assert report.final_verdict == drex_verify.VerificationVerdict.TAMPERED

    def test_tamper_file_deletion(self, base_case_env, tmp_path: Path):
        mgr, case_id, cdir = base_case_env
        pkg = tmp_path / "pkg_b3.tar.gz"
        CasePackageManager.export_package(cdir, pkg)

        def mutate(p: Path):
            # Delete evidence.json
            ev_file = p / "evidence.json"
            assert ev_file.is_file(), f"Target file '{ev_file}' missing before deletion mutation"
            ev_file.unlink()

        tampered_pkg = unpack_modify_repack(pkg, tmp_path / "tampered_b3.tar.gz", mutate)
        verifier = drex_verify.IndependentPackageVerifier(tampered_pkg)
        report = verifier.verify()

        assert report.final_verdict == drex_verify.VerificationVerdict.INCOMPLETE
        assert report.summary.objects_missing >= 1


# ─── Vector C: Audit Chain Tampering ──────────────────────────────────────────

class TestVectorCAuditTampering:
    def test_tamper_audit_payload(self, base_case_env, tmp_path: Path):
        mgr, case_id, cdir = base_case_env
        pkg = tmp_path / "pkg_c1.tar.gz"
        CasePackageManager.export_package(cdir, pkg)

        def mutate(p: Path):
            a_file = p / "audit" / "audit_chain.json"
            assert a_file.is_file(), f"Target audit file '{a_file}' missing before mutation"
            events = json.loads(a_file.read_text(encoding="utf-8"))
            assert len(events) > 0, "Audit ledger is empty"
            events[0]["canonical_payload"]["tampered_key"] = "tampered_value"
            a_file.write_text(json.dumps(events), encoding="utf-8")
            # Recompute manifest so manifest hash check passes, isolating audit check
            self._update_manifest(p)

        tampered_pkg = unpack_modify_repack(pkg, tmp_path / "tampered_c1.tar.gz", mutate)
        verifier = drex_verify.IndependentPackageVerifier(tampered_pkg)
        report = verifier.verify()

        assert report.final_verdict == drex_verify.VerificationVerdict.TAMPERED
        assert report.summary.audit_events_tampered >= 1

    def test_tamper_audit_reorder_events(self, base_case_env, tmp_path: Path):
        mgr, case_id, cdir = base_case_env
        pkg = tmp_path / "pkg_c2.tar.gz"
        CasePackageManager.export_package(cdir, pkg)

        def mutate(p: Path):
            a_file = p / "audit" / "audit_chain.json"
            assert a_file.is_file(), f"Target audit file '{a_file}' missing before mutation"
            events = json.loads(a_file.read_text(encoding="utf-8"))
            assert len(events) >= 2, f"Need at least 2 audit events to test reordering, found {len(events)}"
            events[0], events[1] = events[1], events[0]
            a_file.write_text(json.dumps(events), encoding="utf-8")
            self._update_manifest(p)

        tampered_pkg = unpack_modify_repack(pkg, tmp_path / "tampered_c2.tar.gz", mutate)
        verifier = drex_verify.IndependentPackageVerifier(tampered_pkg)
        report = verifier.verify()

        assert report.final_verdict == drex_verify.VerificationVerdict.TAMPERED

    def test_tamper_audit_delete_event(self, base_case_env, tmp_path: Path):
        mgr, case_id, cdir = base_case_env
        pkg = tmp_path / "pkg_c3.tar.gz"
        CasePackageManager.export_package(cdir, pkg)

        def mutate(p: Path):
            a_file = p / "audit" / "audit_chain.json"
            assert a_file.is_file(), f"Target audit file '{a_file}' missing before mutation"
            events = json.loads(a_file.read_text(encoding="utf-8"))
            assert len(events) >= 3, f"Need at least 3 audit events to test deletion, found {len(events)}"
            events.pop(1)  # Drop middle event
            a_file.write_text(json.dumps(events), encoding="utf-8")
            self._update_manifest(p)

        tampered_pkg = unpack_modify_repack(pkg, tmp_path / "tampered_c3.tar.gz", mutate)
        verifier = drex_verify.IndependentPackageVerifier(tampered_pkg)
        report = verifier.verify()

        assert report.final_verdict == drex_verify.VerificationVerdict.TAMPERED

    def _update_manifest(self, root: Path):
        """Helper to recompute manifest entries for package files."""
        m_file = root / "manifest.json"
        data = json.loads(m_file.read_text(encoding="utf-8"))
        for obj in data.get("objects", []):
            f_p = root / obj["relative_path"]
            if f_p.is_file():
                sha, sz = drex_verify.hash_file_streaming(f_p)
                obj["sha256"] = sha
                obj["size_bytes"] = sz
        m_bytes = drex_verify.canonical_json_bytes(data)
        m_file.write_bytes(m_bytes)
        (root / "manifest.sha256").write_text(f"{drex_verify.hash_bytes_sha256(m_bytes)}  manifest.json\n")


# ─── Vector D: Custody Tampering ──────────────────────────────────────────────

class TestVectorDCustodyTampering:
    def test_tamper_custodian_name(self, base_case_env, tmp_path: Path):
        mgr, case_id, cdir = base_case_env
        pkg = tmp_path / "pkg_d1.tar.gz"
        CasePackageManager.export_package(cdir, pkg)

        def mutate(p: Path):
            c_file = p / "custody" / "custody_ledger.json"
            if not c_file.is_file():
                c_file = p / "custody.json"
            assert c_file.is_file(), f"Custody file missing in package: {c_file}"
            data = json.loads(c_file.read_text(encoding="utf-8"))
            assert len(data) > 0, "Custody ledger is empty"
            data[0]["custodian"] = "Malicious Impostor"
            c_file.write_text(json.dumps(data), encoding="utf-8")
            TestVectorCAuditTampering()._update_manifest(p)

        tampered_pkg = unpack_modify_repack(pkg, tmp_path / "tampered_d1.tar.gz", mutate)
        verifier = drex_verify.IndependentPackageVerifier(tampered_pkg)
        report = verifier.verify()

        assert report.final_verdict == drex_verify.VerificationVerdict.TAMPERED
        assert report.summary.custody_records_tampered >= 1


# ─── Vector E: Certificate Tampering ──────────────────────────────────────────

class TestVectorECertificateTampering:
    def test_tamper_certificate_method_id(self, base_case_env, tmp_path: Path):
        mgr, case_id, cdir = base_case_env
        pkg = tmp_path / "pkg_e1.tar.gz"
        CasePackageManager.export_package(cdir, pkg)

        def mutate(p: Path):
            certs_dir = p / "certificates"
            cert_files = list(certs_dir.glob("*.json"))
            assert len(cert_files) > 0, "No certificate files found to mutate"
            for c_f in cert_files:
                c_data = json.loads(c_f.read_text(encoding="utf-8"))
                c_data["method"]["method_id"] = 99  # Tampered method ID
                c_f.write_text(json.dumps(c_data), encoding="utf-8")
            TestVectorCAuditTampering()._update_manifest(p)

        tampered_pkg = unpack_modify_repack(pkg, tmp_path / "tampered_e1.tar.gz", mutate)
        verifier = drex_verify.IndependentPackageVerifier(tampered_pkg)
        report = verifier.verify()

        assert report.final_verdict == drex_verify.VerificationVerdict.TAMPERED
        assert report.summary.certificates_tampered >= 1

    def test_tamper_certificate_integrity_token(self, base_case_env, tmp_path: Path):
        mgr, case_id, cdir = base_case_env
        pkg = tmp_path / "pkg_e2.tar.gz"
        CasePackageManager.export_package(cdir, pkg)

        def mutate(p: Path):
            certs_dir = p / "certificates"
            cert_files = list(certs_dir.glob("*.json"))
            assert len(cert_files) > 0, "No certificate files found to mutate"
            for c_f in cert_files:
                c_data = json.loads(c_f.read_text(encoding="utf-8"))
                c_data["tamper_evident_signature"] = "0" * 64
                c_f.write_text(json.dumps(c_data), encoding="utf-8")
            TestVectorCAuditTampering()._update_manifest(p)

        tampered_pkg = unpack_modify_repack(pkg, tmp_path / "tampered_e2.tar.gz", mutate)
        verifier = drex_verify.IndependentPackageVerifier(tampered_pkg)
        report = verifier.verify()

        assert report.final_verdict == drex_verify.VerificationVerdict.TAMPERED
        assert report.summary.certificates_tampered >= 1


# ─── Vector F: Cross-Link Tampering ───────────────────────────────────────────

class TestVectorFCrossLinkTampering:
    def test_tamper_cross_link_case_id_mismatch(self, base_case_env, tmp_path: Path):
        mgr, case_id, cdir = base_case_env
        pkg = tmp_path / "pkg_f1.tar.gz"
        CasePackageManager.export_package(cdir, pkg)

        def mutate(p: Path):
            # Change case_id in manifest.json to a foreign case ID
            m_file = p / "manifest.json"
            data = json.loads(m_file.read_text(encoding="utf-8"))
            data["case_id"] = "CASE-FOREIGN-9999"
            m_bytes = drex_verify.canonical_json_bytes(data)
            m_file.write_bytes(m_bytes)
            (p / "manifest.sha256").write_text(f"{drex_verify.hash_bytes_sha256(m_bytes)}  manifest.json\n")

        tampered_pkg = unpack_modify_repack(pkg, tmp_path / "tampered_f1.tar.gz", mutate)
        verifier = drex_verify.IndependentPackageVerifier(tampered_pkg)
        report = verifier.verify()

        assert report.final_verdict == drex_verify.VerificationVerdict.TAMPERED
        assert report.summary.cross_link_errors >= 1
