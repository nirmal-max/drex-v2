"""Unit and Integration Tests for DREX-V2 Forensic Certificate Engine (Phase 6 Track F)."""

import json
import os
import pathlib
import pytest

from certificate_engine import (
    CertificateMethodInfo,
    CertificateTargetInfo,
    CertificateVerificationInfo,
    ForensicCertificateEngine,
    ForensicSanitizationCertificate,
)


def test_create_and_verify_certificate(tmp_path):
    """Verify certificate creation, cryptographic signing, and integrity verification."""
    target = CertificateTargetInfo(
        target_name="TEST_SATA_DRIVE_0",
        target_type="DRIVE",
        device_model="Samsung SSD 870 EVO",
        serial_number="S5YJNF0R123456",
        bus_type="SATA",
        capacity_bytes=500107862016,
    )
    method = CertificateMethodInfo(
        method_id=8,
        canonical_name="CSPRNG Random Overwrite",
        standard_reference="CSPRNG",
        pass_count=1,
        pattern_description="Cryptographically Secure Pseudo-Random Byte Stream",
    )
    verification = CertificateVerificationInfo(
        primary_verification_method="EXACT_BYTE_READBACK",
        sample_percentage=100.0,
        mismatch_count=0,
        pre_wipe_sha256="1111111111111111111111111111111111111111111111111111111111111111",
        post_wipe_sha256="2222222222222222222222222222222222222222222222222222222222222222",
        observed_mean_entropy=7.9991,
        entropy_evaluation_verdict="PASSED",
        exact_readback_verified=True,
    )

    cert = ForensicCertificateEngine.create_certificate(
        case_id="CASE-2026-0914",
        case_name="Forensic Media Sanitization",
        examiner_name="Lead Forensic Analyst",
        organization="DFIR Lab",
        target_info=target,
        method_info=method,
        verification_info=verification,
        prior_audit_hash="0000000000000000000000000000000000000000000000000000000000000000",
    )

    assert cert.certificate_id.startswith("CERT-DREX-")
    assert cert.truth_model.execution == "REAL"
    assert cert.truth_model.qualification == "SOFTWARE-QUALIFIED"
    assert cert.truth_model.physical_execution == "NOT_EXECUTED"
    assert cert.truth_model.physical_qualification == "NOT_ESTABLISHED"

    # Export and verify JSON
    json_path = tmp_path / "certificate.json"
    json_str = ForensicCertificateEngine.export_json(cert, json_path)
    assert json_path.exists()

    cert_dict = json.loads(json_str)
    assert ForensicCertificateEngine.verify_certificate_integrity(cert_dict) is True

    # Tampering test: modify target name and assert signature fails
    tampered_dict = dict(cert_dict)
    tampered_dict["target"]["target_name"] = "TAMPERED_DRIVE_NAME"
    assert ForensicCertificateEngine.verify_certificate_integrity(tampered_dict) is False


def test_export_pure_python_pdf(tmp_path):
    """Verify pure Python PDF 1.4 certificate generator produces standard-compliant binary."""
    target = CertificateTargetInfo(
        target_name="C:\\Evidence\\target.bin",
        target_type="FILE",
        capacity_bytes=1048576,
    )
    method = CertificateMethodInfo(
        method_id=14,
        canonical_name="Single-Pass Zero Overwrite",
        standard_reference="NIST SP 800-88 Rev. 1 Clear",
        pass_count=1,
        pattern_description="0x00 Zero-Fill",
    )
    verification = CertificateVerificationInfo(
        primary_verification_method="EXACT_BYTE_READBACK",
        exact_readback_verified=True,
        pre_wipe_sha256="abc123",
        post_wipe_sha256="000000",
        observed_mean_entropy=0.0000,
        entropy_evaluation_verdict="PASSED",
    )

    cert = ForensicCertificateEngine.create_certificate(
        case_id="CASE-PDF-TEST",
        case_name="PDF Export Validation",
        examiner_name="Examiner One",
        organization="Forensic Lab",
        target_info=target,
        method_info=method,
        verification_info=verification,
    )

    pdf_path = tmp_path / "certificate.pdf"
    pdf_bytes = ForensicCertificateEngine.export_pdf(cert, pdf_path)

    assert pdf_path.exists()
    assert pdf_bytes.startswith(b"%PDF-1.4")
    assert b"%%EOF" in pdf_bytes
    assert b"DREX-V2 FORENSIC SANITIZATION CERTIFICATE" in pdf_bytes
    assert b"xref" in pdf_bytes
