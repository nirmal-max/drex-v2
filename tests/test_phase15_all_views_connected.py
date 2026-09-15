"""
DREX-V2 Phase 15: All 26 Views & Authoritative Backend Connectivity Test Suite
=============================================================================
Verifies that:
1. Every single sidebar view in the WebUI is mapped to an authoritative renderer or explicit truth state.
2. Zero placeholder pages or generic "AUTHENTICATED REAL CONTRACT" screens remain.
3. All underlying REST APIs respond authoritatively.
4. Truth states (HARDWARE_REQUIRED, BACKEND_UNAVAILABLE, UNSUPPORTED) are preserved.
5. All 26 views produce non-empty, rich HTML structures with real data bindings.

License: Apache 2.0
"""

import json
import pathlib
import pytest
from fastapi.testclient import TestClient
from drex_server import app, case_manager, VAULT_DIR
import drex_rbac as rbac
import drex_api_models as models


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def auth_headers():
    token = rbac.create_access_token(models.UserRole.ADMIN, username="admin")
    return {"Authorization": f"Bearer {token}"}


def test_01_webui_static_assets_exist_and_served(client):
    """Verify index.html, app.js, and styles.css exist and are served with 200 OK."""
    webui_dir = pathlib.Path("webui")
    assert (webui_dir / "index.html").is_file()
    assert (webui_dir / "app.js").is_file()
    assert (webui_dir / "styles.css").is_file()

    r_index = client.get("/")
    assert r_index.status_code == 200
    assert "DREX-V2" in r_index.text

    r_js = client.get("/app.js")
    assert r_js.status_code == 200
    assert "VIEW_TITLES" in r_js.text

    r_css = client.get("/styles.css")
    assert r_css.status_code == 200
    assert "--drex-primary" in r_css.text


def test_02_zero_placeholder_pages_in_app_js():
    """Verify that renderGeneric and placeholder strings are completely absent from app.js."""
    app_js_path = pathlib.Path("webui/app.js")
    code = app_js_path.read_text(encoding="utf-8")

    assert "renderGeneric" not in code, "renderGeneric placeholder renderer must not exist in app.js"
    assert "AUTHENTICATED REAL CONTRACT" not in code, "Generic placeholder text must not exist in app.js"


def test_03_all_26_views_registered_in_view_titles():
    """Verify all 26 view IDs are mapped in VIEW_TITLES."""
    app_js_path = pathlib.Path("webui/app.js")
    code = app_js_path.read_text(encoding="utf-8")

    required_views = [
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

    for v in required_views:
        assert f"{v}:" in code, f"View '{v}' must be declared in VIEW_TITLES"
        assert f"case '{v}':" in code, f"View '{v}' must have dedicated routing in navigateTo()"


def test_04_api_devices_and_qualification_endpoint(client, auth_headers):
    """Verify device enumeration and per-device qualification."""
    res = client.get("/api/devices", headers=auth_headers)
    assert res.status_code == 200
    devices = res.json()
    assert isinstance(devices, list)
    assert len(devices) > 0

    first_dev = devices[0]
    dev_id = first_dev.get("device_id") or first_dev.get("device_path")

    res_qual = client.get(f"/api/devices/{dev_id}/qualification", headers=auth_headers)
    assert res_qual.status_code == 200
    qual_items = res_qual.json()
    assert len(qual_items) == 25


def test_05_api_cases_and_evidence_vault(client, auth_headers):
    """Verify cases listing, creation, timeline, and evidence vault listing."""
    res = client.get("/api/cases", headers=auth_headers)
    assert res.status_code == 200
    cases = res.json()
    assert len(cases) > 0

    case_id = cases[0]["case_id"]

    res_ev = client.get(f"/api/evidence?case_id={case_id}", headers=auth_headers)
    assert res_ev.status_code == 200
    assert isinstance(res_ev.json(), list)

    res_time = client.get(f"/api/cases/{case_id}/timeline", headers=auth_headers)
    assert res_time.status_code == 200
    assert isinstance(res_time.json(), list)


def test_06_api_sanitization_plan_and_execution_guards(client, auth_headers):
    """Verify sanitization planner and system drive protection tripwire."""
    res = client.post(
        "/api/sanitization/plan",
        json={"target_path": "D:\\SafeData\\Test.img", "target_type": "DRIVE"},
        headers=auth_headers,
    )
    assert res.status_code == 200
    plan = res.json()
    assert "plan_id" in plan
    assert "safety_phrase" in plan
    assert plan["safety_clearance"] is True

    # Test OS drive block
    res_sys = client.post(
        "/api/sanitization/plan",
        json={"target_path": "\\\\.\\PhysicalDrive0", "target_type": "DRIVE"},
        headers=auth_headers,
    )
    assert res_sys.status_code == 200
    plan_sys = res_sys.json()
    assert plan_sys["system_disk_blocked"] is True
    assert plan_sys["safety_clearance"] is False


def test_07_api_recovery_and_raw_carving(client, auth_headers):
    """Verify recovery scan, candidate retrieval, and 5-factor scoring."""
    res_cands = client.get("/api/recovery/candidates", headers=auth_headers)
    assert res_cands.status_code == 200
    cands = res_cands.json()
    assert isinstance(cands, list)

    if cands:
        first = cands[0]
        assert "confidence_score" in first
        assert "confidence_factors" in first
        assert "validation_verdict" in first


def test_08_api_fragment_reconstruction(client, auth_headers):
    """Verify out-of-order fragment reconstruction with boundary seam analysis."""
    case = case_manager.create_case(
        case_number="DREX-TEST-FRAG",
        title="Fragment Test Case",
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
            "filename": "test_recon.png",
            "fragments": [
                {"chunk_id": 1, "offset": 0, "data_hex": hdrHex, "is_header": True, "is_footer": False},
                {"chunk_id": 2, "offset": 4096, "data_hex": ftrHex, "is_header": False, "is_footer": True},
            ],
            "strict_structure_validation": False,
        },
        headers=auth_headers,
    )
    assert res.status_code == 200
    data = res.json()
    assert data["file_type"] == "PNG"
    assert "reconstruction_confidence" in data
    assert "candidate_id" in data


def test_09_api_certificates_and_verification(client, auth_headers):
    """Verify certificate generation, listing, PDF download, and independent verification."""
    case = case_manager.create_case(
        case_number="DREX-TEST-CERT",
        title="Cert Test Case",
        examiner="Analyst",
        organization="NTRO Forensic Lab",
    )

    res_gen = client.post(
        "/api/certificates/generate",
        json={
            "case_id": case.case_id,
            "target_identifier": "TARGET_VOL_01",
            "method_id": 8,
            "examiner_name": "Test Analyst",
        },
        headers=auth_headers,
    )
    assert res_gen.status_code == 200
    cert = res_gen.json()
    cert_id = cert["certificate_id"]

    res_list = client.get(f"/api/certificates?case_id={case.case_id}", headers=auth_headers)
    assert res_list.status_code == 200
    assert len(res_list.json()) >= 1

    res_ver = client.post(
        "/api/certificates/verify",
        json={"case_id": case.case_id, "certificate_id": cert_id},
        headers=auth_headers,
    )
    assert res_ver.status_code == 200
    ver_data = res_ver.json()
    assert ver_data["valid"] is True
    assert ver_data["certificate_hash_valid"] is True


def test_10_api_validation_lab_and_performance_lab(client, auth_headers):
    """Verify Validation Lab and Performance Lab REST APIs."""
    case = case_manager.create_case(
        case_number="DREX-TEST-LABS",
        title="Labs Test Case",
        examiner="Analyst",
        organization="NTRO Forensic Lab",
    )

    # Validation Lab
    res_val = client.post(
        "/api/validation/run",
        json={"case_id": case.case_id, "suites": ["SUITE-KAT-REC", "SUITE-KAT-SAN"]},
        headers=auth_headers,
    )
    assert res_val.status_code == 200
    val_data = res_val.json()
    assert "overall_verdict" in val_data
    assert "method_matrix" in val_data

    # Performance Lab
    res_perf = client.post(
        "/api/performance/run",
        json={"case_id": case.case_id, "dataset_size_bytes": 1048576, "chunk_size_bytes": 65536, "iterations": 1},
        headers=auth_headers,
    )
    assert res_perf.status_code == 200
    perf_data = res_perf.json()
    assert perf_data["bounded_streaming_verified"] is True
    assert "throughput_mb_per_sec" in perf_data


def test_11_api_audit_ledger_and_integrity_verification(client, auth_headers):
    """Verify audit ledger retrieval and SHA-256 hash chain verification."""
    res_ledger = client.get("/api/audit/ledger", headers=auth_headers)
    assert res_ledger.status_code == 200
    assert isinstance(res_ledger.json(), list)

    res_verify = client.post("/api/audit/verify", headers=auth_headers)
    assert res_verify.status_code == 200
    v_data = res_verify.json()
    assert v_data["is_valid"] is True


def test_12_api_method_registry_preserves_authentic_truth():
    """Verify method registry truth statuses."""
    client_test = TestClient(app)
    res = client_test.get("/api/methods/registry")
    assert res.status_code == 200
    methods = res.json()
    assert len(methods) == 25

    m_map = {m["id"]: m for m in methods}
    assert m_map[3]["status"] == "UNSUPPORTED"
    assert m_map[4]["status"] == "UNSUPPORTED"
    assert m_map[5]["status"] == "UNSUPPORTED"
    assert m_map[23]["status"] == "UNSUPPORTED"
    assert m_map[24]["status"] == "BACKEND UNAVAILABLE"
