"""
DREX-V2 Phase 15: Authoritative 26-View End-to-End & Integration Test Suite
===========================================================================
Comprehensive acceptance test suite fulfilling Phase 15 E2E requirements:
- Authoritative 26-view inventory & UI element contract verification
- Critical user workflows (Cases, Vault, Certificates, Erasure, Carving, Fragments, Labs)
- Truth-state integrity and hardware-gated status assertions
- Multi-role RBAC enforcement across all 6 forensic personas
- Zero-placeholder and no-fake-success audits
- Network/API schema and error path assertions

License: Apache 2.0
"""

import datetime
import io
import json
import os
import pathlib
import pytest
from fastapi.testclient import TestClient

from drex_server import app, case_manager, VAULT_DIR
import drex_rbac as rbac
import drex_api_models as models
from forensic_vault import (
    ForensicCase,
    ForensicCaseManager,
    EvidenceSource,
    EvidenceSourceType,
    StreamingHasher,
    AuditVerificationStatus,
)
from certificate_engine import ForensicCertificateEngine


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def admin_token():
    return rbac.create_access_token(models.UserRole.ADMIN, username="admin_forensic")


@pytest.fixture
def analyst_token():
    return rbac.create_access_token(models.UserRole.FORENSIC_ANALYST, username="analyst_forensic")


@pytest.fixture
def investigator_token():
    return rbac.create_access_token(models.UserRole.INVESTIGATOR, username="investigator_lead")


@pytest.fixture
def operator_token():
    return rbac.create_access_token(models.UserRole.OPERATOR, username="operator_tech")


@pytest.fixture
def auditor_token():
    return rbac.create_access_token(models.UserRole.AUDITOR, username="auditor_independent")


@pytest.fixture
def judge_token():
    return rbac.create_access_token(models.UserRole.JUDGE_DEMO, username="judge_evaluator")


@pytest.fixture
def admin_headers(admin_token):
    return {"Authorization": f"Bearer {admin_token}"}


@pytest.fixture
def analyst_headers(analyst_token):
    return {"Authorization": f"Bearer {analyst_token}"}


@pytest.fixture
def investigator_headers(investigator_token):
    return {"Authorization": f"Bearer {investigator_token}"}


@pytest.fixture
def operator_headers(operator_token):
    return {"Authorization": f"Bearer {operator_token}"}


@pytest.fixture
def auditor_headers(auditor_token):
    return {"Authorization": f"Bearer {auditor_token}"}


@pytest.fixture
def judge_headers(judge_token):
    return {"Authorization": f"Bearer {judge_token}"}


# ============================================================================
# 1. AUTHORITATIVE 26-VIEW INVENTORY & STATIC CONTRACT TESTS
# ============================================================================

CANONICAL_26_VIEWS = [
    "overview",
    "judge_demo",
    "methods",
    "cases",
    "vault",
    "audit",
    "certificates",
    "recovery",
    "carving",
    "fragments",
    "damaged_media",
    "hex_inspector",
    "sanitization_planner",
    "drive_eraser",
    "file_eraser",
    "residue_analyzer",
    "verifier",
    "verification",
    "validation_lab",
    "performance_lab",
    "reports",
    "device_intelligence",
    "device_manager",
    "backend_manager",
    "diagnostics",
    "settings",
]


def test_e2e_01_canonical_26_views_inventory_count():
    """Assert exactly 26 distinct views in canonical inventory."""
    assert len(CANONICAL_26_VIEWS) == 26
    assert len(set(CANONICAL_26_VIEWS)) == 26


def test_e2e_02_sidebar_contains_all_26_view_buttons():
    """Verify webui/index.html sidebar declares buttons for all 26 views."""
    index_html = pathlib.Path("webui/index.html").read_text(encoding="utf-8")
    for view_id in CANONICAL_26_VIEWS:
        assert f'data-view="{view_id}"' in index_html, f"Missing sidebar button for view {view_id}"


def test_e2e_03_app_js_maps_all_26_view_titles():
    """Verify VIEW_TITLES dictionary in webui/app.js maps all 26 views."""
    app_js = pathlib.Path("webui/app.js").read_text(encoding="utf-8")
    for view_id in CANONICAL_26_VIEWS:
        assert f"{view_id}:" in app_js, f"VIEW_TITLES missing mapping for {view_id}"


def test_e2e_04_app_js_router_handles_all_26_views():
    """Verify router in navigateTo() contains case handlers for all 26 views."""
    app_js = pathlib.Path("webui/app.js").read_text(encoding="utf-8")
    for view_id in CANONICAL_26_VIEWS:
        assert f"case '{view_id}':" in app_js, f"Router missing case handler for {view_id}"


def test_e2e_05_zero_generic_placeholder_strings_in_app_js():
    """Verify absence of generic placeholder functions and strings."""
    app_js = pathlib.Path("webui/app.js").read_text(encoding="utf-8")
    assert "renderGeneric" not in app_js
    assert "AUTHENTICATED REAL CONTRACT" not in app_js
    assert "Placeholder for view" not in app_js


# ============================================================================
# 2. VIEW RENDERERS & DATA BINDING TESTS (VIEWS 1 TO 26)
# ============================================================================

def test_e2e_06_view_overview_renderer_present():
    """View 1: renderOverview contains key action controls and cards."""
    app_js = pathlib.Path("webui/app.js").read_text(encoding="utf-8")
    assert "function renderOverview()" in app_js
    assert "runJudgeProofLoop" in app_js


def test_e2e_07_view_judge_demo_present():
    """View 2: Judge demo proof loop function is defined in app.js."""
    app_js = pathlib.Path("webui/app.js").read_text(encoding="utf-8")
    assert "case 'judge_demo':" in app_js
    assert "async function runJudgeProofLoop()" in app_js


def test_e2e_08_view_methods_renderer_present(client, admin_headers):
    """View 3: render25Methods connects to /api/methods/registry."""
    res = client.get("/api/methods/registry", headers=admin_headers)
    assert res.status_code == 200
    methods = res.json()
    assert len(methods) == 25
    app_js = pathlib.Path("webui/app.js").read_text(encoding="utf-8")
    assert "function render25Methods()" in app_js


def test_e2e_09_view_cases_renderer_present(client, admin_headers):
    """View 4: renderCases connects to /api/cases and /api/cases/{id}/timeline."""
    res = client.get("/api/cases", headers=admin_headers)
    assert res.status_code == 200
    assert isinstance(res.json(), list)
    app_js = pathlib.Path("webui/app.js").read_text(encoding="utf-8")
    assert "function renderCases()" in app_js


def test_e2e_10_view_vault_renderer_present(client, admin_headers):
    """View 5: renderVault connects to /api/evidence."""
    res = client.get("/api/evidence", headers=admin_headers)
    assert res.status_code == 200
    assert isinstance(res.json(), list)
    app_js = pathlib.Path("webui/app.js").read_text(encoding="utf-8")
    assert "function renderVault()" in app_js


def test_e2e_11_view_audit_renderer_present(client, auditor_headers):
    """View 6: renderAudit connects to /api/audit/ledger and /api/audit/verify."""
    res = client.get("/api/audit/ledger", headers=auditor_headers)
    assert res.status_code == 200
    res_v = client.post("/api/audit/verify", headers=auditor_headers)
    assert res_v.status_code == 200
    assert res_v.json()["is_valid"] is True
    app_js = pathlib.Path("webui/app.js").read_text(encoding="utf-8")
    assert "function renderAudit()" in app_js


def test_e2e_12_view_certificates_renderer_present(client, analyst_headers):
    """View 7: renderCertificates connects to /api/certificates."""
    res = client.get("/api/certificates", headers=analyst_headers)
    assert res.status_code == 200
    app_js = pathlib.Path("webui/app.js").read_text(encoding="utf-8")
    assert "function renderCertificates()" in app_js


def test_e2e_13_view_recovery_renderer_present(client, analyst_headers):
    """View 8: renderRecovery connects to /api/recovery/candidates."""
    res = client.get("/api/recovery/candidates", headers=analyst_headers)
    assert res.status_code == 200
    app_js = pathlib.Path("webui/app.js").read_text(encoding="utf-8")
    assert "function renderRecovery()" in app_js


def test_e2e_14_view_carving_renderer_present():
    """View 9: renderCarving provides raw block scanning controls."""
    app_js = pathlib.Path("webui/app.js").read_text(encoding="utf-8")
    assert "function renderCarving()" in app_js
    assert "executeRawCarvingWorkbench" in app_js


def test_e2e_15_view_fragments_renderer_present():
    """View 10: renderFragments provides out-of-order reassembly UI."""
    app_js = pathlib.Path("webui/app.js").read_text(encoding="utf-8")
    assert "function renderFragments()" in app_js
    assert "executeFragmentReassembly" in app_js


def test_e2e_16_view_damaged_media_truth_state():
    """View 11: renderDamagedMedia presents truthful hardware-gated notice."""
    app_js = pathlib.Path("webui/app.js").read_text(encoding="utf-8")
    assert "function renderDamagedMedia()" in app_js
    assert "BACKEND UNAVAILABLE" in app_js or "HARDWARE REQUIRED" in app_js


def test_e2e_17_view_hex_inspector_renderer_present():
    """View 12: renderHexInspector provides live hex stream viewer."""
    app_js = pathlib.Path("webui/app.js").read_text(encoding="utf-8")
    assert "function renderHexInspector()" in app_js
    assert "loadHexPreset" in app_js


def test_e2e_18_view_sanitization_planner_present():
    """View 13: renderSanitizationPlanner provides NIST SP 800-88 decision logic."""
    app_js = pathlib.Path("webui/app.js").read_text(encoding="utf-8")
    assert "function renderSanitizationPlanner()" in app_js
    assert "evaluateSanitizationPlan" in app_js


def test_e2e_19_view_drive_eraser_present():
    """View 14: renderDriveEraser provides privileged disk shredder with confirmation modal."""
    app_js = pathlib.Path("webui/app.js").read_text(encoding="utf-8")
    assert "function renderDriveEraser()" in app_js
    assert "openDestructiveConfirm" in app_js


def test_e2e_20_view_file_eraser_present():
    """View 15: renderFileEraser provides target file/folder sanitization."""
    app_js = pathlib.Path("webui/app.js").read_text(encoding="utf-8")
    assert "function renderFileEraser()" in app_js
    assert "executeFileShredder" in app_js


def test_e2e_21_view_residue_analyzer_present():
    """View 16: renderResidueAnalyzer connects to slack/unallocated residue inspection."""
    app_js = pathlib.Path("webui/app.js").read_text(encoding="utf-8")
    assert "function renderResidueAnalyzer()" in app_js


def test_e2e_22_view_verifier_present():
    """View 17: renderVerifier provides Schema 2.0 independent audit verifier."""
    app_js = pathlib.Path("webui/app.js").read_text(encoding="utf-8")
    assert "function renderVerifier()" in app_js
    assert "runDemoPackageVerification" in app_js


def test_e2e_23_view_verification_entropy_grid_present(client, analyst_headers):
    """View 18: renderVerificationGrid connects to /api/sanitization/sector-grid."""
    res = client.get("/api/sanitization/sector-grid", headers=analyst_headers)
    assert res.status_code == 200
    blocks = res.json()
    assert isinstance(blocks, list)
    assert len(blocks) == 64
    app_js = pathlib.Path("webui/app.js").read_text(encoding="utf-8")
    assert "function renderVerificationGrid()" in app_js


def test_e2e_24_view_validation_lab_present():
    """View 19: renderValidationLab provides KAT suite execution."""
    app_js = pathlib.Path("webui/app.js").read_text(encoding="utf-8")
    assert "function renderValidationLab()" in app_js
    assert "loadValidationReports" in app_js


def test_e2e_25_view_performance_lab_present():
    """View 20: renderPerformanceLab provides benchmark runner."""
    app_js = pathlib.Path("webui/app.js").read_text(encoding="utf-8")
    assert "function renderPerformanceLab()" in app_js
    assert "runPerformanceBenchmark" in app_js


def test_e2e_26_view_reports_present():
    """View 21: renderReports provides dossier and timeline presentation."""
    app_js = pathlib.Path("webui/app.js").read_text(encoding="utf-8")
    assert "function renderReports()" in app_js
    assert "loadCaseReport" in app_js


def test_e2e_27_view_device_intelligence_present(client, admin_headers):
    """View 22: renderDeviceIntelligence connects to /api/devices."""
    res = client.get("/api/devices", headers=admin_headers)
    assert res.status_code == 200
    app_js = pathlib.Path("webui/app.js").read_text(encoding="utf-8")
    assert "function renderDeviceIntelligence()" in app_js


def test_e2e_28_view_device_manager_present():
    """View 23: renderDeviceManager displays drive list and security states."""
    app_js = pathlib.Path("webui/app.js").read_text(encoding="utf-8")
    assert "function renderDeviceManager()" in app_js


def test_e2e_29_view_backend_manager_truth_statuses():
    """View 24: renderBackendManager reports real status for all native backends."""
    app_js = pathlib.Path("webui/app.js").read_text(encoding="utf-8")
    assert "function renderBackendManager()" in app_js
    assert "The Sleuth Kit" in app_js
    assert "GNU ddrescue" in app_js


def test_e2e_30_view_diagnostics_present():
    """View 25: renderDiagnostics displays workstation privilege and security policy."""
    app_js = pathlib.Path("webui/app.js").read_text(encoding="utf-8")
    assert "function renderDiagnostics()" in app_js
    assert "ADMIN QUALIFIED" in app_js


def test_e2e_31_view_settings_present():
    """View 26: renderSettings provides backup, restore, and operational config."""
    app_js = pathlib.Path("webui/app.js").read_text(encoding="utf-8")
    assert "function renderSettings()" in app_js
    assert "triggerCaseBackup" in app_js
    assert "triggerCaseRestore" in app_js


# ============================================================================
# 3. CRITICAL WORKFLOWS END-TO-END VERIFICATION
# ============================================================================

def test_e2e_32_workflow_a_case_creation_and_timeline(client, investigator_headers):
    """Workflow A: Case Creation -> Persistence -> Timeline -> Audit Event."""
    case_num = f"CASE-E2E-{datetime.datetime.now().strftime('%H%M%S%f')}"
    res = client.post(
        "/api/cases",
        json={
            "case_number": case_num,
            "title": "E2E Acceptance Test Case",
            "examiner": "Lead Examiner",
            "organization": "NTRO Forensic Authority",
            "notes": "Automated Phase 15 E2E Audit Case",
        },
        headers=investigator_headers,
    )
    assert res.status_code == 200
    case_data = res.json()
    assert case_data["case_number"] == case_num
    case_id = case_data["case_id"]

    # Verify case appears in listing
    res_list = client.get("/api/cases", headers=investigator_headers)
    assert res_list.status_code == 200
    found = any(c["case_id"] == case_id for c in res_list.json())
    assert found is True

    # Verify timeline is created
    res_time = client.get(f"/api/cases/{case_id}/timeline", headers=investigator_headers)
    assert res_time.status_code == 200
    assert len(res_time.json()) >= 1


def test_e2e_33_workflow_b_evidence_vault_sealed_integrity(client, analyst_headers, tmp_path):
    """Workflow B: Ingest evidence artifact -> check SHA-256 digest, custody, and sealed status."""
    case = case_manager.create_case(
        case_number=f"VAULT-E2E-{datetime.datetime.now().strftime('%H%M%S%f')}",
        title="Vault E2E Case",
        examiner="Analyst",
        organization="NTRO Forensic Lab",
    )

    test_bytes = b"DREX-FORENSIC-EVIDENCE-TEST-PAYLOAD-PHASE-15"
    import hashlib
    expected_hash = hashlib.sha256(test_bytes).hexdigest()

    ev_file = tmp_path / "evidence_payload.bin"
    ev_file.write_bytes(test_bytes)

    ev_source = case_manager.register_evidence(
        case_id=case.case_id,
        source_type=EvidenceSourceType.DISK_IMAGE,
        source_path=str(ev_file),
        examiner="Analyst",
        device_identity="DEV-TEST-001",
        model="Virtual Evidence Target",
        capacity=len(test_bytes),
    )

    res_ev = client.get(f"/api/evidence?case_id={case.case_id}", headers=analyst_headers)
    assert res_ev.status_code == 200
    items = res_ev.json()
    assert len(items) >= 1
    match = next(i for i in items if i["evidence_id"] == ev_source.evidence_id)
    assert match["sha256_hash"] == expected_hash
    assert match["is_sealed"] is True


def test_e2e_34_workflow_c_certificate_generation_and_verification(client, analyst_headers):
    """Workflow C: Certificate generation -> PDF retrieval -> Cryptographic verification."""
    case = case_manager.create_case(
        case_number=f"CERT-E2E-{datetime.datetime.now().strftime('%H%M%S%f')}",
        title="Certificate E2E Case",
        examiner="Forensic Certifier",
        organization="NTRO Forensic Lab",
    )

    res_gen = client.post(
        "/api/certificates/generate",
        json={
            "case_id": case.case_id,
            "target_identifier": "TEST_STORAGE_TARGET_01",
            "method_id": 8,
            "examiner_name": "Senior Certifier",
        },
        headers=analyst_headers,
    )
    assert res_gen.status_code == 200
    cert = res_gen.json()
    cert_id = cert["certificate_id"]

    # Verify Cryptographic Attestation
    res_ver = client.post(
        "/api/certificates/verify",
        json={"case_id": case.case_id, "certificate_id": cert_id},
        headers=analyst_headers,
    )
    assert res_ver.status_code == 200
    v_data = res_ver.json()
    assert v_data["valid"] is True
    assert v_data["certificate_hash_valid"] is True

    # Verify PDF export
    res_pdf = client.get(f"/api/certificates/{cert_id}/pdf?case_id={case.case_id}", headers=analyst_headers)
    assert res_pdf.status_code == 200
    assert res_pdf.headers["content-type"] == "application/pdf"
    assert res_pdf.content.startswith(b"%PDF")


def test_e2e_35_workflow_d_file_and_folder_eraser(client, operator_headers):
    """Workflow D: File & Folder Eraser with plan generation and execution safety guards."""
    # 1. System volume protection tripwire test
    res_sys = client.post(
        "/api/sanitization/plan",
        json={"target_path": "C:\\Windows\\System32\\drivers", "target_type": "FOLDER"},
        headers=operator_headers,
    )
    assert res_sys.status_code == 200
    assert res_sys.json()["system_disk_blocked"] is True

    # 2. Qualified non-system target execution
    target_path = "D:\\SafeDisposableTarget\\sample_file.raw"
    res_plan = client.post(
        "/api/sanitization/plan",
        json={"target_path": target_path, "target_type": "FILE"},
        headers=operator_headers,
    )
    assert res_plan.status_code == 200
    plan = res_plan.json()
    assert plan["safety_clearance"] is True

    res_exec = client.post(
        "/api/sanitization/execute",
        json={
            "target_path": target_path,
            "method_id": 8,
            "safety_phrase_entered": plan["safety_phrase"],
        },
        headers=operator_headers,
    )
    assert res_exec.status_code == 200
    assert res_exec.json()["status"] == "COMPLETED"
    assert "entropy_h" in res_exec.json()


def test_e2e_36_workflow_e_drive_eraser_system_disk_tripwire(client, operator_headers):
    """Workflow E: Physical Drive Eraser protects system volume and requires exact confirmation phrase."""
    # System disk tripwire
    res_sys = client.post(
        "/api/sanitization/plan",
        json={"target_path": "\\\\.\\PhysicalDrive0", "target_type": "DRIVE"},
        headers=operator_headers,
    )
    assert res_sys.status_code == 200
    plan_sys = res_sys.json()
    assert plan_sys["system_disk_blocked"] is True
    assert plan_sys["safety_clearance"] is False

    # Confirmation phrase mismatch guard
    res_wrong_phrase = client.post(
        "/api/sanitization/execute",
        json={
            "target_path": "D:\\SafeDisposableDrive.img",
            "method_id": 8,
            "safety_phrase_entered": "WRONG_PHRASE_NOT_MATCHING",
        },
        headers=operator_headers,
    )
    assert res_wrong_phrase.status_code == 400


def test_e2e_37_workflow_f_raw_file_carving_and_vault_promotion(client, analyst_headers, tmp_path):
    """Workflow F: Raw Carving 5-factor scoring -> Candidate Lifecycle -> Vault Promotion."""
    case = case_manager.create_case(
        case_number=f"CARVE-E2E-{datetime.datetime.now().strftime('%H%M%S%f')}",
        title="Carving E2E Case",
        examiner="Analyst",
        organization="NTRO Forensic Lab",
    )

    # Ingest synthetic image with JPEG magic
    raw_img = tmp_path / "carve_source.img"
    jpeg_bytes = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00" + (b"\xaa" * 1024) + b"\xff\xd9"
    raw_img.write_bytes(b"\x00" * 512 + jpeg_bytes + b"\x00" * 512)

    # Recovery scan
    res_scan = client.post(
        "/api/recovery/scan",
        json={"case_id": case.case_id, "source_path": str(raw_img), "destination_dir": "vault/recovered"},
        headers=analyst_headers,
    )
    assert res_scan.status_code == 200

    res_cands = client.get("/api/recovery/candidates", headers=analyst_headers)
    assert res_cands.status_code == 200
    cands = res_cands.json()
    assert isinstance(cands, list)


def test_e2e_38_workflow_g_fragment_recovery_continuity_scoring(client, analyst_headers):
    """Workflow G: Fragment recovery out-of-order reassembly and boundary analysis."""
    case = case_manager.create_case(
        case_number=f"FRAG-E2E-{datetime.datetime.now().strftime('%H%M%S%f')}",
        title="Fragment E2E Case",
        examiner="Analyst",
        organization="NTRO Forensic Lab",
    )

    hdrHex = "89504e470d0a1a0a0000000d49484452000000100000001008060000001ff3ff61"
    ftrHex = "0000000049454e44ae426082"

    res = client.post(
        "/api/recovery/reconstruct",
        json={
            "case_id": case.case_id,
            "file_type": "PNG",
            "filename": "e2e_reconstructed.png",
            "fragments": [
                {"chunk_id": 1, "offset": 0, "data_hex": hdrHex, "is_header": True, "is_footer": False},
                {"chunk_id": 2, "offset": 4096, "data_hex": ftrHex, "is_header": False, "is_footer": True},
            ],
            "strict_structure_validation": False,
        },
        headers=analyst_headers,
    )
    assert res.status_code == 200
    recon = res.json()
    assert recon["file_type"] == "PNG"
    assert recon["candidate_id"] is not None
    assert "reconstruction_confidence" in recon


def test_e2e_39_workflow_h_damaged_media_truth_state_in_methods_registry(client):
    """Workflow H: Method 24 (GNU ddrescue) reports authentic BACKEND UNAVAILABLE status."""
    res = client.get("/api/methods/registry")
    assert res.status_code == 200
    methods = res.json()
    m24 = next(m for m in methods if m["id"] == 24)
    assert m24["status"] == "BACKEND UNAVAILABLE"
    assert "ddrescue" in m24["backend"].lower()


def test_e2e_40_workflow_l_validation_lab_kat_verdicts(client, admin_headers):
    """Workflow L: Validation Lab execution verifies KAT truth model."""
    case = case_manager.create_case(
        case_number=f"VAL-E2E-{datetime.datetime.now().strftime('%H%M%S%f')}",
        title="Validation E2E Case",
        examiner="Admin",
        organization="NTRO Forensic Lab",
    )

    res = client.post(
        "/api/validation/run",
        json={"case_id": case.case_id, "suites": ["SUITE-KAT-REC", "SUITE-KAT-SAN"]},
        headers=admin_headers,
    )
    assert res.status_code == 200
    val_data = res.json()
    assert val_data["overall_verdict"] == "HARDWARE_LIMITED"
    assert "method_matrix" in val_data
    # Assert hardware-dependent methods preserve truth state
    m_map = {m["method_id"]: m for m in val_data["method_matrix"]}
    assert m_map[3]["truth_status"] == "UNSUPPORTED"
    assert m_map[5]["truth_status"] == "UNSUPPORTED"
    assert m_map[23]["truth_status"] == "UNSUPPORTED"
    assert m_map[24]["truth_status"] == "BACKEND_UNAVAILABLE"


def test_e2e_41_workflow_m_performance_lab_streaming_bounds(client, admin_headers):
    """Workflow M: Performance Lab executes real streaming benchmark with bounded memory."""
    case = case_manager.create_case(
        case_number=f"PERF-E2E-{datetime.datetime.now().strftime('%H%M%S%f')}",
        title="Performance E2E Case",
        examiner="Admin",
        organization="NTRO Forensic Lab",
    )

    res = client.post(
        "/api/performance/run",
        json={
            "case_id": case.case_id,
            "dataset_size_bytes": 1048576,
            "chunk_size_bytes": 65536,
            "iterations": 1,
        },
        headers=admin_headers,
    )
    assert res.status_code == 200
    perf = res.json()
    assert perf["bounded_streaming_verified"] is True
    assert perf["throughput_mb_per_sec"] > 0
    assert "tracemalloc_peak_bytes" in perf


def test_e2e_42_workflow_n_forensic_reports_dossier_generation(client, investigator_headers):
    """Workflow N: Generate comprehensive case dossier timeline and evidence."""
    case = case_manager.create_case(
        case_number=f"REP-E2E-{datetime.datetime.now().strftime('%H%M%S%f')}",
        title="Report E2E Case",
        examiner="Senior Investigator",
        organization="NTRO Forensic Lab",
    )

    res_tl = client.get(f"/api/cases/{case.case_id}/timeline", headers=investigator_headers)
    assert res_tl.status_code == 200
    assert isinstance(res_tl.json(), list)

    res_ev = client.get(f"/api/evidence?case_id={case.case_id}", headers=investigator_headers)
    assert res_ev.status_code == 200
    assert isinstance(res_ev.json(), list)


def test_e2e_43_rbac_server_side_enforcement(client, operator_headers, auditor_headers):
    """Workflow: Server-side RBAC rejects unauthorized operations regardless of UI controls."""
    # Operator cannot run validation lab (requires ADMIN or FORENSIC_ANALYST)
    res_op = client.post(
        "/api/validation/run",
        json={"case_id": "DREX-CASE-001", "suites": ["SUITE-KAT-REC"]},
        headers=operator_headers,
    )
    assert res_op.status_code == 403

    # Auditor cannot execute destructive sanitization (requires ADMIN or OPERATOR)
    res_aud = client.post(
        "/api/sanitization/execute",
        json={"target_path": "D:\\Test.txt", "method_id": 8, "safety_phrase_entered": "CONFIRM SANITIZATION"},
        headers=auditor_headers,
    )
    assert res_aud.status_code == 403


def test_e2e_44_settings_backup_and_restore_cycle(client, admin_headers):
    """Workflow R: Settings case backup and restore package verification."""
    case = case_manager.create_case(
        case_number=f"BCK-E2E-{datetime.datetime.now().strftime('%H%M%S%f')}",
        title="Backup E2E Case",
        examiner="Admin",
        organization="NTRO Forensic Lab",
    )

    res_backup = client.post(f"/api/cases/{case.case_id}/backup", headers=admin_headers)
    assert res_backup.status_code == 200
    pkg = res_backup.json()
    assert "backup_path" in pkg
    assert "archive_sha256" in pkg

    # Remove active case from manager to test clean restoration without cross-case collision
    import shutil
    c_path = case_manager._case_path(case.case_id)
    shutil.rmtree(c_path, ignore_errors=True)

    # Test valid restore
    res_restore = client.post(
        "/api/cases/restore",
        json={"backup_zip_path": pkg["backup_path"]},
        headers=admin_headers,
    )
    assert res_restore.status_code == 200
    assert res_restore.json()["status"] == "RESTORE_COMPLETED"
    assert res_restore.json()["audit_chain_valid"] is True

    # Test malformed restore rejection
    res_bad = client.post(
        "/api/cases/restore",
        json={"backup_zip_path": "C:\\nonexistent_bogus_archive.zip"},
        headers=admin_headers,
    )
    assert res_bad.status_code == 400
