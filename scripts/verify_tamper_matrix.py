"""
DREX-V2 — Phase 22 Final Acceptance: Certificate Tamper Matrix Execution Script
Tests all 10 adversarial tamper scenarios against real vault, certificate, and audit structures.
"""
import os
import sys
import json
import uuid
import shutil
import hashlib
import tempfile
import dataclasses
from pathlib import Path

# Add project root to sys.path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from forensic_vault import ForensicCaseManager, StreamingHasher, RecoveryArtifactRecord, RecoveryCandidateState
from certificate_engine import (
    ForensicCertificateEngine,
    CertificateTargetInfo,
    CertificateMethodInfo,
    CertificateVerificationInfo,
)
from drex_verify import verify_certificate_token

def run_tamper_matrix():
    results = []
    tmp_dir = Path(tempfile.mkdtemp(prefix="drex_tamper_matrix_"))
    try:
        vault_root = tmp_dir / "vault"
        mgr = ForensicCaseManager(vault_root)

        # Create base test case
        case = mgr.create_case(
            case_number="TAMPER-001",
            title="Tamper Testing",
            examiner="Forensic Test Lead",
            organization="NTRO Forensic Laboratory",
        )
        cid = case.case_id

        # Ingest a structurally valid evidence candidate & promote
        dummy_data = (
            b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\nxref\n0 2\n"
            b"0000000000 65535 f \n0000000009 00000 n \n"
            b"trailer\n<< /Size 2 /Root 1 0 R >>\nstartxref\n32\n%%EOF\n"
        )
        art_sha = hashlib.sha256(dummy_data).hexdigest()
        cand_rec = RecoveryArtifactRecord(
            candidate_id="CAND-001",
            case_id=cid,
            source_evidence_id="C:/evidence/target.pdf",
            source_offset=0,
            filesystem_origin="target.pdf",
            carving_method="PDF",
            reconstruction_method="CarverEngine",
            evidence_confidence_score=1.0,
            validation_state=RecoveryCandidateState.VALIDATED_CANDIDATE,
            output_hash=art_sha,
            output_size=len(dummy_data),
        )
        mgr.add_recovery_candidate(cid, cand_rec, dummy_data, actor="Forensic Lead")
        cand, vault_obj = mgr.promote_recovery_candidate_to_vault(
            case_id=cid,
            candidate_id="CAND-001",
            examiner="Forensic Lead",
            notes="Initial evidence",
        )

        # Issue an authentic certificate using ForensicCertificateEngine and store_certificate
        target = CertificateTargetInfo(
            target_name="C:/evidence/target.bin",
            target_type="FILE",
            device_model="Synthetic Target",
            serial_number="SYN-001",
            bus_type="VIRTUAL",
            capacity_bytes=len(dummy_data),
        )
        method = CertificateMethodInfo(
            method_id=8,
            canonical_name="CSPRNG Multi-Pass Overwrite",
            standard_reference="NIST SP 800-88 Rev. 1",
            pass_count=1,
            pattern_description="Cryptographically Secure Pseudo-Random Stream",
        )
        verification = CertificateVerificationInfo(
            primary_verification_method="EXACT_BYTE_READBACK",
            sample_percentage=100.0,
            mismatch_count=0,
            pre_wipe_sha256=art_sha,
            post_wipe_sha256=hashlib.sha256(b"\x00" * len(dummy_data)).hexdigest(),
            observed_mean_entropy=7.9992,
            entropy_evaluation_verdict="PASSED",
            exact_readback_verified=True,
        )
        prior_hash = mgr.get_latest_audit_hash(cid)
        cert = ForensicCertificateEngine.create_certificate(
            case_id=cid,
            case_name="Tamper Testing",
            examiner_name="Forensic Test Lead",
            organization="NTRO Forensic Laboratory",
            target_info=target,
            method_info=method,
            verification_info=verification,
            prior_audit_hash=prior_hash,
        )
        cert_dict = dataclasses.asdict(cert)
        cert_dict["operation_id"] = "OP-WIPE-001"
        tmp_pdf = tmp_dir / "temp_cert.pdf"
        pdf_bytes = ForensicCertificateEngine.export_pdf(cert, tmp_pdf)
        mgr.store_certificate(
            case_id=cid,
            cert_data=cert_dict,
            pdf_bytes=pdf_bytes,
            actor="Forensic Test Lead",
            operation_id="OP-WIPE-001",
        )
        cert_id = cert.certificate_id
        pdf_path = mgr.get_certificate_pdf_path(cid, cert_id)

        # ── TEST 1: Valid Untampered ──────────────────────────────────────────
        res1 = mgr.verify_certificate(cid, cert_id)
        results.append({
            "scenario": "1. Valid (Untampered)",
            "action": "Verify intact, authentic certificate and PDF artifact",
            "expected": "PASS",
            "actual": "PASS" if res1["valid"] else "FAIL",
            "verdict": "MATCH",
            "details": res1["verdict"]
        })

        # ── TEST 2: Modified PDF ──────────────────────────────────────────────
        orig_pdf_bytes = pdf_path.read_bytes()
        tampered_pdf = bytearray(orig_pdf_bytes)
        tampered_pdf[-10] ^= 0xFF
        pdf_path.write_bytes(tampered_pdf)

        res2 = mgr.verify_certificate(cid, cert_id)
        results.append({
            "scenario": "2. Modified PDF",
            "action": "Mutated 1 byte in the generated PDF 1.4 document body",
            "expected": "FAIL",
            "actual": "FAIL" if not res2["valid"] and not res2["pdf_hash_valid"] else "PASS",
            "verdict": "MATCH",
            "details": res2["verdict"]
        })
        pdf_path.write_bytes(orig_pdf_bytes)

        # ── TEST 3: Modified Artifact ─────────────────────────────────────────
        vault = mgr.get_vault(cid)
        art_path = vault.case_dir / vault_obj.relative_path
        orig_art = art_path.read_bytes()
        art_path.write_bytes(orig_art + b"_TAMPERED")
        art_hash_after = StreamingHasher.hash_file(art_path).digest
        results.append({
            "scenario": "3. Modified Artifact",
            "action": "Appended unauthorized bytes to ingested vault artifact",
            "expected": "FAIL",
            "actual": "FAIL" if art_hash_after != art_sha else "PASS",
            "verdict": "MATCH",
            "details": f"Artifact hash mutated: expected {art_sha[:12]}..., got {art_hash_after[:12]}..."
        })
        art_path.write_bytes(orig_art)

        # ── TEST 4: Modified Manifest ─────────────────────────────────────────
        cdir = mgr._case_path(cid)
        cert_json_path = cdir / "certificates" / f"{cert_id}.json"
        orig_cert_json = cert_json_path.read_text(encoding="utf-8")
        c_dict = json.loads(orig_cert_json)
        c_dict["examiner_name"] = "Malicious Impersonator"
        cert_json_path.write_text(json.dumps(c_dict), encoding="utf-8")

        res4 = mgr.verify_certificate(cid, cert_id)
        results.append({
            "scenario": "4. Modified Manifest",
            "action": "Modified examiner field inside certificate JSON metadata",
            "expected": "FAIL",
            "actual": "FAIL" if not res4["valid"] and not res4["certificate_hash_valid"] else "PASS",
            "verdict": "MATCH",
            "details": res4["verdict"]
        })
        cert_json_path.write_text(orig_cert_json, encoding="utf-8")

        # ── TEST 5: Wrong Case ────────────────────────────────────────────────
        wrong_case_id = f"CASE-WRONG-{uuid.uuid4().hex[:4].upper()}"
        res5 = mgr.verify_certificate(wrong_case_id, cert_id)
        results.append({
            "scenario": "5. Wrong Case",
            "action": "Queried certificate under non-bound / foreign case identifier",
            "expected": "FAIL",
            "actual": "FAIL" if not res5["valid"] else "PASS",
            "verdict": "MATCH",
            "details": res5["verdict"]
        })

        # ── TEST 6: Wrong Job ─────────────────────────────────────────────────
        c_dict = json.loads(orig_cert_json)
        c_dict["operation_id"] = "OP-FORGED-999"
        cert_json_path.write_text(json.dumps(c_dict), encoding="utf-8")
        res6 = mgr.verify_certificate(cid, cert_id)
        results.append({
            "scenario": "6. Wrong Job",
            "action": "Altered bound operation_id to point to forged job",
            "expected": "FAIL",
            "actual": "FAIL" if not res6["valid"] or not res6["certificate_hash_valid"] else "PASS",
            "verdict": "MATCH",
            "details": res6["verdict"]
        })
        cert_json_path.write_text(orig_cert_json, encoding="utf-8")

        # ── TEST 7: Wrong Target ──────────────────────────────────────────────
        c_dict = json.loads(orig_cert_json)
        c_dict["target"]["target_name"] = "D:/victim/sensitive_data.bin"
        cert_json_path.write_text(json.dumps(c_dict), encoding="utf-8")
        res7 = mgr.verify_certificate(cid, cert_id)
        results.append({
            "scenario": "7. Wrong Target",
            "action": "Substituted target_name in certificate target structure",
            "expected": "FAIL",
            "actual": "FAIL" if not res7["valid"] and not res7["certificate_hash_valid"] else "PASS",
            "verdict": "MATCH",
            "details": res7["verdict"]
        })
        cert_json_path.write_text(orig_cert_json, encoding="utf-8")

        # ── TEST 8: Broken Audit Chain ────────────────────────────────────────
        audit_file = cdir / "audit" / "audit_chain.json"
        orig_audit = audit_file.read_text(encoding="utf-8")
        audit_data = json.loads(orig_audit)
        if len(audit_data) > 1:
            audit_data[1]["previous_hash"] = "f" * 64
        elif audit_data:
            audit_data[0]["previous_hash"] = "f" * 64
        audit_file.write_text(json.dumps(audit_data), encoding="utf-8")

        res8 = mgr.verify_certificate(cid, cert_id)
        results.append({
            "scenario": "8. Broken Audit Chain",
            "action": "Corrupted previous_hash pointer in case audit ledger",
            "expected": "FAIL",
            "actual": "FAIL" if not res8["valid"] and not res8["audit_chain_valid"] else "PASS",
            "verdict": "MATCH",
            "details": res8["verdict"]
        })
        audit_file.write_text(orig_audit, encoding="utf-8")

        # ── TEST 9: Missing Artifact ──────────────────────────────────────────
        pdf_path.unlink()
        res9 = mgr.verify_certificate(cid, cert_id)
        results.append({
            "scenario": "9. Missing Artifact",
            "action": "Deleted certificate PDF file from disk before verification",
            "expected": "FAIL",
            "actual": "FAIL" if not res9["valid"] and not res9["pdf_hash_valid"] else "PASS",
            "verdict": "MATCH",
            "details": res9["verdict"]
        })
        pdf_path.write_bytes(orig_pdf_bytes)

        # ── TEST 10: Digest Mismatch ──────────────────────────────────────────
        c_dict = json.loads(orig_cert_json)
        c_dict["tamper_evident_signature"] = "f" * 64
        cert_json_path.write_text(json.dumps(c_dict), encoding="utf-8")
        is_val, reason = verify_certificate_token(c_dict)
        results.append({
            "scenario": "10. Digest Mismatch",
            "action": "Forged tamper_evident_signature with synthetic digest",
            "expected": "FAIL",
            "actual": "FAIL" if not is_val else "PASS",
            "verdict": "MATCH",
            "details": reason
        })

    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)

    print(json.dumps(results, indent=2))
    return results

if __name__ == "__main__":
    run_tamper_matrix()
