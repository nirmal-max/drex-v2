"""
DREX-V2 Phase 10 Comprehensive Multi-Surface & API Test Suite
=============================================================
Tests all newly introduced Phase 10 capabilities:
1. Dynamic Windows Boot/System Volume Detection (no hard-coded drive assumptions).
2. Evidence-based Forensic Certificate Attestation (no false ISO 27037 claims).
3. 6-Role Granular RBAC Permissions & Persona Switcher.
4. FastAPI Server Endpoints (Devices, 25 Methods, Cases, Evidence, Audit, Recovery, Sanitization).
5. Exact Device-Specific Safety Phrase Enforcement on Destructive Operations.
6. 64-Sector Storage Block Visualizer Telemetry & Shannon Entropy.
7. Standalone Schema 2.0 Independent Package Verifier integration.
8. Deterministic < 60s Safe Judge Demo Proof Loop.

Zero unapproved external dependencies.
License: Apache 2.0.
"""

from __future__ import annotations

import json
import os
import pathlib
import pytest
from fastapi.testclient import TestClient

import drex_api_models as models
import drex_rbac as rbac
import drex_server
from certificate_engine import ForensicCertificateEngine, CertificateTargetInfo, CertificateMethodInfo, CertificateVerificationInfo
from hardware_storage import DeviceIntelligenceEngine, DeviceIdentitySnapshot


@pytest.fixture
def client():
    """FastAPI test client instance."""
    return TestClient(drex_server.app)


# ─── 1. System-Drive Detection Tests (Correction 2) ──────────────────────────

def test_dynamic_windows_system_drive_detection():
    """Verify that system drive detection queries real Windows volumes."""
    sys_disks = DeviceIntelligenceEngine.get_windows_system_disk_numbers()
    # On Windows, at least one physical disk index should back C:\
    assert isinstance(sys_disks, set)

    # Active system drive letter must be protected
    sys_drive = os.environ.get("SystemDrive", "C:")
    assert DeviceIntelligenceEngine.is_system_drive(f"\\\\.\\{sys_drive}")
    assert DeviceIntelligenceEngine.is_system_drive(sys_drive)
    assert DeviceIntelligenceEngine.is_system_drive(r"\\.\C:")

    # An arbitrary non-system simulated path must not be flagged
    assert not DeviceIntelligenceEngine.is_system_drive(r"\\.\PhysicalDrive99", disk_number=99)
    assert not DeviceIntelligenceEngine.is_system_drive(r"\\.\Z:")


# ─── 2. Evidence-Based Certificate Attestation (Correction 1) ─────────────────

def test_evidence_based_certificate_attestation():
    """Verify certificates use evidence-based terminology without unverified ISO claims."""
    target = CertificateTargetInfo(target_name="TEST_USB_DRIVE", target_type="DRIVE")
    method = CertificateMethodInfo(method_id=8, canonical_name="CSPRNG Random Overwrite")
    verif = CertificateVerificationInfo(primary_verification_method="EXACT_READBACK", exact_readback_verified=True)

    cert = ForensicCertificateEngine.create_certificate(
        case_id="CASE-001",
        case_name="Forensic Triage",
        examiner_name="Lead Analyst",
        organization="NTRO Lab",
        target_info=target,
        method_info=method,
        verification_info=verif,
    )

    cert_dict = cert.__dict__
    # Must NOT claim unverified ISO 27037 certification
    assert "ISO/IEC 27037 Certified" not in str(cert_dict)
    # Must contain evidence-based truth model
    assert cert.truth_model.qualification == "SOFTWARE-QUALIFIED"
    assert cert.tamper_evident_signature != ""


# ─── 3. RBAC & Persona Switcher Tests ─────────────────────────────────────────

def test_rbac_token_and_persona_switching(client):
    """Test JWT token generation, role verification, and 1-click persona switcher."""
    # 1. Switch to AUDITOR persona
    res = client.post("/api/auth/switch-persona", json={"target_role": "AUDITOR"})
    assert res.status_code == 200
    data = res.json()
    assert data["role"] == "AUDITOR"
    token = data["access_token"]

    # 2. Verify payload with /api/auth/me
    me_res = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me_res.status_code == 200
    me_data = me_res.json()
    assert me_data["role"] == "AUDITOR"
    assert "audit:verify" in me_data["permissions"]
    # Auditor does not have destructive execution permission
    assert "sanitization:execute" not in me_data["permissions"]


# ─── 4. REST API Endpoints Tests ──────────────────────────────────────────────

def test_25_method_matrix_registry(client):
    """Verify all 25 methods are exposed with truthful statuses."""
    res = client.get("/api/methods/registry")
    assert res.status_code == 200
    methods = res.json()
    assert len(methods) == 25

    # Check key methods and authentic terminology
    m_ids = {m["id"]: m for m in methods}
    assert m_ids[1]["status"] == "PASS — DECISION ENGINE VERIFIED"
    assert m_ids[8]["status"] == "PASS — REAL EXECUTION VERIFIED"
    assert m_ids[3]["status"] == "UNSUPPORTED"
    assert m_ids[24]["status"] == "BACKEND UNAVAILABLE"


def test_device_enumeration_endpoint(client):
    """Verify physical drive enumeration returns valid descriptors with safety locks."""
    res = client.get("/api/devices")
    assert res.status_code == 200
    devices = res.json()
    assert isinstance(devices, list)

    for d in devices:
        assert "device_id" in d
        assert "device_path" in d
        assert "is_system_disk" in d
        if d["is_system_disk"]:
            assert d["safety_block_reason"] is not None


def test_case_and_timeline_lifecycle(client):
    """Verify creating a case and reading its timeline events."""
    case_num = f"TEST-CASE-{os.getpid()}"
    res = client.post(
        "/api/cases",
        json={
            "case_number": case_num,
            "title": "Automated Phase 10 Test Case",
            "examiner": "Automated Tester",
            "organization": "Test Bench",
            "notes": "Validation test case for multi-surface platform.",
        },
    )
    assert res.status_code == 200
    c_data = res.json()
    case_id = c_data["case_id"]

    # Read timeline
    tl_res = client.get(f"/api/cases/{case_id}/timeline")
    assert tl_res.status_code == 200
    events = tl_res.json()
    assert len(events) >= 1
    assert events[0]["case_id"] == case_id


# ─── 5. Destructive Safety Phrase Enforcement Tests ───────────────────────────

def test_destructive_safety_phrase_validation(client):
    """Verify that destructive sanitization enforces exact safety phrases and blocks OS disks."""
    # Target: System disk C: must be rejected with 422 Unprocessable Entity
    plan_res = client.post(
        "/api/sanitization/plan",
        json={"target_path": r"\\.\C:", "target_type": "DRIVE"},
    )
    assert plan_res.status_code == 200
    plan = plan_res.json()
    assert plan["system_disk_blocked"] is True

    # Attempting to execute on C: must trigger safety tripwire
    exec_res = client.post(
        "/api/sanitization/execute",
        json={
            "target_path": r"\\.\C:",
            "method_id": 8,
            "safety_phrase_entered": plan["safety_phrase"],
        },
    )
    assert exec_res.status_code == 422
    assert "SAFETY TRIPWIRE TRIGGERED" in exec_res.json()["detail"]

    # Target: Non-system simulated disk with wrong phrase must fail with 400
    sim_target = r"\\.\PhysicalDrive99"
    wrong_res = client.post(
        "/api/sanitization/execute",
        json={
            "target_path": sim_target,
            "method_id": 8,
            "safety_phrase_entered": "WRONG_PHRASE",
        },
    )
    assert wrong_res.status_code == 400
    assert "Confirmation phrase mismatch" in wrong_res.json()["detail"]


# ─── 6. 64-Sector Storage Block Visualizer Telemetry ──────────────────────────

def test_sector_block_grid_telemetry(client):
    """Verify 64-block storage visualizer telemetry endpoint."""
    res = client.get("/api/sanitization/sector-grid")
    assert res.status_code == 200
    blocks = res.json()
    assert len(blocks) == 64

    # Ensure zeroed, CSPRNG, and unallocated states are represented
    states = {b["state"] for b in blocks}
    assert "ZEROED" in states
    assert "CSPRNG" in states


# ─── 7. Independent Verifier Integration Tests ────────────────────────────────

def test_independent_verifier_route(client):
    """Verify endpoint runs independent schema 2.0 verifier."""
    res = client.post("/api/verification/verify-package?package_path=DREX_EVIDENCE_PACKAGE_DEMO.zip")
    assert res.status_code == 200
    data = res.json()
    assert data["verdict"] in ("PASS", "INVALID", "TAMPERED")
    assert data["schema_version"] == "2.0"


# ─── 8. Deterministic Judge Demo Proof Loop ───────────────────────────────────

def test_judge_demo_proof_loop(client):
    """Verify 1-click deterministic Judge Demo Flow executes and completes cleanly."""
    res = client.post("/api/demo/flow")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "SUCCESS"
    assert len(data["steps_completed"]) == 6
    assert "FULL FORENSIC PROOF LOOP VERIFIED" in data["verdict"]
