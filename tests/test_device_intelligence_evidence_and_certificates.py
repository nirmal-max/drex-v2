"""Unit and Integration Tests for Device Intelligence Evidence & Certificate Binding (Phase 7)."""

import json
import pytest
from certificate_engine import (
    CertificateMethodInfo,
    CertificateTargetInfo,
    CertificateVerificationInfo,
    ForensicCertificateEngine,
)
from hardware_storage import (
    DeviceIntelligenceEngine,
    DriveWipeHardwareBackend,
    HardwareExecutionStatus,
    HardwareOperationResult,
)
from forensic_vault import ForensicCaseManager, EvidenceVault, CaseStatus


def test_hardware_evidence_generation_and_audit_chain(tmp_path):
    """Verify hardware operation result binds to EvidenceVault hash chain."""
    sim = {"disk_number": 2, "bus_type": "SATA", "serial_number": "HW-EVID-SN-001"}
    caps = DriveWipeHardwareBackend.identify(r"\\.\PhysicalDrive2", simulated_descriptor=sim)

    res = DriveWipeHardwareBackend.execute(
        device_path=r"\\.\PhysicalDrive2",
        method_id="M04",
        options={"confirm_destructive": True, "simulated_descriptor": sim},
        caps=caps,
        allow_simulation=True,
    )
    assert res.status == HardwareExecutionStatus.SIMULATION_QUALIFIED

    case_mgr = ForensicCaseManager(base_data_dir=tmp_path / "cases")
    case = case_mgr.create_case("CASE-HW-001", "Hardware Evidence Test", "Lead Analyst", "Lab")

    ev_record = DriveWipeHardwareBackend.evidence(res, case_mgr=case_mgr, case=case)
    assert "evidence_id" in ev_record
    assert "sha256" in ev_record
    assert ev_record["drex_physical_qualification"] == "NOT_ESTABLISHED"
    assert ev_record["drex_physical_execution"] == "NOT_EXECUTED"


def test_certificate_engine_hardware_binding(tmp_path):
    """Verify certificate engine renders hardware device identity and dual NIST standard reference."""
    target_info = CertificateTargetInfo(
        target_name=r"\\.\PhysicalDrive1",
        target_type="DRIVE",
        device_model="Samsung SSD 980 PRO",
        serial_number="S5GXNF0R999999",
        bus_type="NVME",
        capacity_bytes=1000204886016,
        sector_size=512,
    )
    method_info = CertificateMethodInfo(
        method_id=5,
        canonical_name="NVMe Secure Erase",
        standard_reference="NIST SP 800-88 Rev. 2 aligned",
        pass_count=1,
        pattern_description="NVMe Controller Sanitize / Crypto Erase",
        nist_profile="REV_2",
    )
    verif_info = CertificateVerificationInfo(
        primary_verification_method="STATUS_LOG_READBACK",
        exact_readback_verified=True,
        post_wipe_sha256="0000000000000000000000000000000000000000000000000000000000000000",
    )

    cert = ForensicCertificateEngine.create_certificate(
        case_id="CASE-CERT-HW",
        case_name="Hardware Sanitization Certificate Test",
        examiner_name="Analyst",
        organization="DFIR Lab",
        target_info=target_info,
        method_info=method_info,
        verification_info=verif_info,
    )

    # Export PDF and JSON
    pdf_bytes = ForensicCertificateEngine.export_pdf(cert, tmp_path / "cert_hw.pdf")
    json_str = ForensicCertificateEngine.export_json(cert, tmp_path / "cert_hw.json")

    assert b"Samsung SSD 980 PRO" in pdf_bytes
    assert b"NVME" in pdf_bytes
    assert b"Rev. 2 Aligned" in pdf_bytes

    cert_dict = json.loads(json_str)
    assert ForensicCertificateEngine.verify_certificate_integrity(cert_dict) is True
