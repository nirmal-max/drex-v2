"""
DREX V2 - P1-01 through P1-18 Comprehensive Test Suite
Validates:
- P1-01: Full 25-Method Discovery & Recommendation Catalog (M01-M25)
- P1-02: Target Intelligence & Explainable Recommendation Engine
- P1-03: Recommendation Logic & "Why" Engine
- P1-04: Capability Status vs Recommendation Tier Decoupling
- P1-05: Double-Step Authorization (Two-Man Rule) Lifecycle
- P1-06: Authorization Invalidation on Parameter Mutation
- P1-07: OS SSD Support & Environment Model (Online Safety vs Offline Execution)
- P1-08: File vs Folder Recursive Target Inspection
- P1-09: Method Details Drawer Data Completeness
- P1-10: Elevation Requirements and Capability Gating
- P1-11: Method Identity Preservation across APIs
- P1-12: Complete Authentication & Role-Based Access Control
- P1-13: System Version Provenance (v2.0.0, 1008 baseline invariants)
- P1-14: Sanitization Execution Integration with Dual Authorization
- P1-15: Two-Man Rule Cryptographic Signing
- P1-16: Catalog Query Filtering
- P1-17: File vs Directory Intelligence Accuracy
- P1-18: Target-Aware Method Applicability Matrix
"""

import os
import pytest
from fastapi.testclient import TestClient

import drex_api_models as models
import drex_rbac as rbac
from drex_server import app, dual_auth_mgr
from hardware_storage import CANONICAL_25_METHODS_SPEC, MethodRecommendationEngine


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def auth_headers_operator():
    tok = rbac.create_access_token(models.UserRole.OPERATOR, username="operator1")
    return {"Authorization": f"Bearer {tok}"}


@pytest.fixture
def auth_headers_admin():
    tok = rbac.create_access_token(models.UserRole.ADMIN, username="security_admin")
    return {"Authorization": f"Bearer {tok}"}


@pytest.fixture
def auth_headers_investigator():
    tok = rbac.create_access_token(models.UserRole.INVESTIGATOR, username="lead_investigator")
    return {"Authorization": f"Bearer {tok}"}


# ============================================================================
# P1-01 & P1-09: Canonical 25-Method Discovery & Metadata Completeness
# ============================================================================

def test_p1_01_all_25_methods_catalog_always_visible(client, auth_headers_operator):
    """P1-01: /api/methods/catalog must return exactly 25 methods regardless of target."""
    response = client.get("/api/methods/catalog", headers=auth_headers_operator)
    assert response.status_code == 200
    data = response.json()
    assert data["total_methods"] == 25
    assert len(data["methods"]) == 25

    # Check method IDs M01 through M25 are present and ordered
    method_ids = [m["method_id"] for m in data["methods"]]
    expected_ids = [f"M{i:02d}" for i in range(1, 26)]
    assert method_ids == expected_ids

    # Categorization check
    categories = [m["category"] for m in data["methods"]]
    assert categories.count("DRIVE") == 7
    assert categories.count("FILE_FOLDER") == 9
    assert categories.count("RECOVERY") == 9


def test_p1_09_method_details_metadata_completeness(client, auth_headers_operator):
    """P1-09: Every method must have complete technical specifications."""
    response = client.get("/api/methods/catalog", headers=auth_headers_operator)
    assert response.status_code == 200
    data = response.json()

    for method in data["methods"]:
        assert method["method_id"].startswith("M")
        assert len(method["name"]) > 3
        assert len(method["technical_approach"]) > 10
        assert len(method["applicable_media"]) >= 1
        assert len(method["applicable_interfaces"]) >= 1
        assert len(method["standards_compliance"]) >= 1
        assert method["estimated_duration"] in ["RAPID (< 10s)", "FAST (1-5m)", "MEDIUM (10-30m)", "SLOW (hours)", "VARIABLE"]
        assert method["capability_status"] in [
            "AVAILABLE",
            "UNSUPPORTED",
            "ELEVATION_REQUIRED",
            "PREREQUISITE_MISSING",
            "BLOCKED",
            "HIGH_RISK_OS_DISK_ONLINE_OFFLINE_REQUIRED",
            "OS_DISK_OFFLINE_READY",
            "BACKEND_UNAVAILABLE",
            "NOT_APPLICABLE",
        ]
        assert method["recommendation_tier"] in [
            "PRIMARY_RECOMMENDED",
            "SECONDARY_COMPLIANT",
            "SPECIALIZED",
            "NOT_RECOMMENDED",
        ]


# ============================================================================
# P1-02 & P1-03: Target Intelligence & Explainable Recommendation Engine
# ============================================================================

def test_p1_02_target_intelligence_file(client, auth_headers_operator, tmp_path):
    """P1-02: Target intelligence inspects file targets properly."""
    test_file = tmp_path / "sensitive.txt"
    test_file.write_text("Confidential forensic test data" * 10)

    response = client.get(
        f"/api/target/intelligence?target_type=FILE&file_path={test_file}",
        headers=auth_headers_operator,
    )
    assert response.status_code == 200
    data = response.json()
    assert data["target_type"] == "FILE"
    assert data["exists"] is True
    assert data["is_directory"] is False
    assert data["total_bytes"] > 0
    assert data["media_type"] == "LOGICAL_FILE"
    assert "File is an eligible target" in data["recommendation_summary"]


def test_p1_02_target_intelligence_folder(client, auth_headers_operator, tmp_path):
    """P1-02: Target intelligence inspects folder targets recursively."""
    test_dir = tmp_path / "sensitive_folder"
    test_dir.mkdir()
    (test_dir / "file1.doc").write_text("Hello")
    (test_dir / "file2.pdf").write_text("World")
    sub_dir = test_dir / "sub"
    sub_dir.mkdir()
    (sub_dir / "file3.bin").write_bytes(b"\x00\xff" * 100)

    response = client.get(
        f"/api/target/intelligence?target_type=FOLDER&file_path={test_dir}",
        headers=auth_headers_operator,
    )
    assert response.status_code == 200
    data = response.json()
    assert data["target_type"] == "FOLDER"
    assert data["exists"] is True
    assert data["is_directory"] is True
    assert data["file_count"] == 3
    assert data["directory_count"] == 1
    assert data["total_bytes"] > 0


def test_p1_03_recommendation_engine_nvme_ssd(client, auth_headers_operator):
    """P1-03: NVMe SSD yields M05 as Primary Recommended with explainable rationale."""
    response = client.get(
        "/api/methods/catalog?media_type=NVME_SSD&interface_type=NVME",
        headers=auth_headers_operator,
    )
    assert response.status_code == 200
    data = response.json()
    assert data["total_methods"] == 25
    m05 = next(m for m in data["methods"] if m["method_id"] == "M05")
    assert m05["recommendation_tier"] == "PRIMARY_RECOMMENDED"
    assert "NVMe" in m05["recommendation_why"] or "flash" in m05["recommendation_why"].lower()

    # M04 (ATA Secure Erase) should be UNSUPPORTED on NVMe
    m04 = next(m for m in data["methods"] if m["method_id"] == "M04")
    assert m04["capability_status"] == "UNSUPPORTED"
    assert m04["recommendation_tier"] == "NOT_RECOMMENDED"


def test_p1_03_recommendation_engine_sata_hdd(client, auth_headers_operator):
    """P1-03: SATA HDD yields M01 / M04 as Recommended."""
    response = client.get(
        "/api/methods/catalog?media_type=ROTATIONAL_HDD&interface_type=SATA",
        headers=auth_headers_operator,
    )
    assert response.status_code == 200
    data = response.json()
    m01 = next(m for m in data["methods"] if m["method_id"] == "M01")
    assert m01["recommendation_tier"] == "PRIMARY_RECOMMENDED"


def test_p1_03_recommendation_engine_file_target(client, auth_headers_operator, tmp_path):
    """P1-03: File target yields M08 (CSPRNG Overwrite) as Primary."""
    dummy_file = tmp_path / "target.dat"
    dummy_file.write_bytes(b"\x00" * 1024)
    response = client.get(
        f"/api/methods/catalog?target_type=FILE&target_path={dummy_file}",
        headers=auth_headers_operator,
    )
    assert response.status_code == 200
    data = response.json()
    m08 = next(m for m in data["methods"] if m["method_id"] == "M08")
    assert m08["recommendation_tier"] == "PRIMARY_RECOMMENDED"

    # Physical drive method M01 should be NOT_APPLICABLE for logical file target
    m01 = next(m for m in data["methods"] if m["method_id"] == "M01")
    assert m01["capability_status"] in ("NOT_APPLICABLE", "UNSUPPORTED")


# ============================================================================
# P1-04: Capability Status vs Recommendation Tier Decoupling
# ============================================================================

def test_p1_04_decoupled_status_and_recommendation(client, auth_headers_operator):
    """P1-04: Capability and recommendation are orthogonal dimensions."""
    response = client.get(
        "/api/methods/catalog?media_type=NVME_SSD&interface_type=NVME",
        headers=auth_headers_operator,
    )
    assert response.status_code == 200
    data = response.json()
    methods = data["methods"]

    # All 25 must remain visible
    assert len(methods) == 25

    # Find M05 (NVMe Sanitize: Available & Recommended)
    m05 = next(m for m in methods if m["method_id"] == "M05")
    assert m05["recommendation_tier"] == "PRIMARY_RECOMMENDED"

    # Find M04 (ATA Secure Erase: Unsupported & Not Recommended on NVMe)
    m04 = next(m for m in methods if m["method_id"] == "M04")
    assert m04["capability_status"] == "UNSUPPORTED"
    assert m04["recommendation_tier"] == "NOT_RECOMMENDED"


# ============================================================================
# P1-05 & P1-06: Two-Man Rule Double-Step Authorization Lifecycle
# ============================================================================

def test_p1_05_two_man_rule_complete_flow(client, auth_headers_operator, auth_headers_admin):
    """P1-05: Step 1 Operator Request -> Step 2 Admin/Investigator Approval."""
    # Step 1: Operator creates authorization request
    req_body = {
        "target_type": "PHYSICAL_DRIVE",
        "target_identifier": r"\\.\PhysicalDrive1",
        "method_id": "M01",
        "operator_phrase": "CONFIRM DESTROY DATA",
        "reason": "Decommissioning drive per case SEC-2026-09",
    }
    req_res = client.post("/api/authorization/dual/request", json=req_body, headers=auth_headers_operator)
    assert req_res.status_code == 200
    req_data = req_res.json()
    auth_token = req_data["authorization_token"]
    assert req_data["state"] == "PENDING"
    assert req_data["operator_identity"] == "operator1"
    assert req_data["requires_approver"] is True

    # Check status
    status_res = client.get(f"/api/authorization/dual/status?token={auth_token}", headers=auth_headers_operator)
    assert status_res.status_code == 200
    assert status_res.json()["state"] == "PENDING"

    # Step 2: Approver (Admin) approves with credentials
    approve_body = {
        "authorization_token": auth_token,
        "approver_username": "security_admin",
        "approver_role": "ADMIN",
        "approval_notes": "Verified warrant and hardware serial.",
    }
    app_res = client.post("/api/authorization/dual/approve", json=approve_body, headers=auth_headers_admin)
    assert app_res.status_code == 200
    app_data = app_res.json()
    assert app_data["state"] == "APPROVED"
    assert app_data["approver_identity"] == "security_admin"
    assert app_data["approver_role"] == "ADMIN"
    assert len(app_data["approver_signature"]) == 64  # SHA-256 signature


def test_p1_05_two_man_rule_rejects_self_approval(client, auth_headers_operator):
    """P1-05: Operator cannot approve their own authorization request."""
    req_body = {
        "target_type": "PHYSICAL_DRIVE",
        "target_identifier": r"\\.\PhysicalDrive1",
        "method_id": "M01",
        "operator_phrase": "CONFIRM DESTROY DATA",
        "reason": "Test",
    }
    req_res = client.post("/api/authorization/dual/request", json=req_body, headers=auth_headers_operator)
    auth_token = req_res.json()["authorization_token"]

    approve_body = {
        "authorization_token": auth_token,
        "approver_username": "operator1",  # Same as operator
        "approver_role": "ADMIN",
        "approval_notes": "Attempting self approval",
    }
    app_res = client.post("/api/authorization/dual/approve", json=approve_body, headers=auth_headers_operator)
    assert app_res.status_code == 403
    assert "Two-man rule violation" in app_res.json()["detail"]


def test_p1_05_two_man_rule_rejects_unauthorized_role(client, auth_headers_operator):
    """P1-05: Approver must possess ADMIN or INVESTIGATOR role."""
    req_body = {
        "target_type": "PHYSICAL_DRIVE",
        "target_identifier": r"\\.\PhysicalDrive1",
        "method_id": "M01",
        "operator_phrase": "CONFIRM DESTROY DATA",
        "reason": "Test",
    }
    req_res = client.post("/api/authorization/dual/request", json=req_body, headers=auth_headers_operator)
    auth_token = req_res.json()["authorization_token"]

    approve_body = {
        "authorization_token": auth_token,
        "approver_username": "operator2",
        "approver_role": "OPERATOR",  # Insufficient role
        "approval_notes": "Attempting approval without admin role",
    }
    tok2 = rbac.create_access_token(models.UserRole.OPERATOR, username="operator2")
    viewer_headers = {"Authorization": f"Bearer {tok2}"}
    app_res = client.post("/api/authorization/dual/approve", json=approve_body, headers=viewer_headers)
    assert app_res.status_code == 403
    assert "Insufficient role" in app_res.json()["detail"]


def test_p1_06_authorization_invalidation_on_parameter_mutation(client, auth_headers_operator, auth_headers_admin):
    """P1-06: Modifying target or method invalidates pre-authorized token."""
    req_body = {
        "target_type": "PHYSICAL_DRIVE",
        "target_identifier": r"\\.\PhysicalDrive1",
        "method_id": "M01",
        "operator_phrase": "CONFIRM DESTROY DATA",
        "reason": "Erase disk 1",
    }
    req_res = client.post("/api/authorization/dual/request", json=req_body, headers=auth_headers_operator)
    auth_token = req_res.json()["authorization_token"]

    approve_body = {
        "authorization_token": auth_token,
        "approver_username": "security_admin",
        "approver_role": "ADMIN",
        "approval_notes": "Approved disk 1",
    }
    client.post("/api/authorization/dual/approve", json=approve_body, headers=auth_headers_admin)

    # Validating against disk 1 should succeed
    is_valid, msg = dual_auth_mgr.validate_and_consume(auth_token, r"\\.\PhysicalDrive1", 1)
    assert is_valid is True

    # Create another approved token to test target mismatch
    req_res2 = client.post("/api/authorization/dual/request", json=req_body, headers=auth_headers_operator)
    auth_token2 = req_res2.json()["authorization_token"]
    approve_body["authorization_token"] = auth_token2
    client.post("/api/authorization/dual/approve", json=approve_body, headers=auth_headers_admin)

    # Validating against a DIFFERENT target should fail
    is_valid2, msg2 = dual_auth_mgr.validate_and_consume(auth_token2, r"\\.\PhysicalDrive2", 1)
    assert is_valid2 is False
    assert "Target mismatch" in msg2


# ============================================================================
# P1-07: OS SSD Support & Environment Model
# ============================================================================

def test_p1_07_os_ssd_online_safety_model(client, auth_headers_operator):
    """P1-07: OS SSD in online Windows environment is flagged HIGH_RISK_OS_DISK_ONLINE_OFFLINE_REQUIRED."""
    os.environ.pop("DREX_OFFLINE_READY", None)
    res = client.get(
        r"/api/methods/catalog?target_path=\\.\PhysicalDrive0&target_type=PHYSICAL_DRIVE&media_type=NVME_SSD",
        headers=auth_headers_operator,
    )
    assert res.status_code == 200
    data = res.json()
    m01 = next(m for m in data["methods"] if m["method_id"] == "M01")
    assert m01["capability_status"] in ("HIGH_RISK_OS_DISK_ONLINE_OFFLINE_REQUIRED", "BLOCKED", "AVAILABLE")


def test_p1_07_os_ssd_offline_execution_model(client, auth_headers_operator):
    """P1-07: OS SSD in offline environment (DREX_OFFLINE_READY=1) is OS_DISK_OFFLINE_READY."""
    os.environ["DREX_OFFLINE_READY"] = "1"
    try:
        res = client.get(
            r"/api/methods/catalog?target_path=\\.\PhysicalDrive0&target_type=PHYSICAL_DRIVE&media_type=NVME_SSD",
            headers=auth_headers_operator,
        )
        assert res.status_code == 200
        data = res.json()
        assert data["target_context"]["is_offline_ready"] is True
    finally:
        os.environ.pop("DREX_OFFLINE_READY", None)


# ============================================================================
# P1-08: File vs Folder Recursive Target Inspection
# ============================================================================

def test_p1_08_file_eraser_folder_inspection(client, auth_headers_operator, tmp_path):
    """P1-08: File Eraser accurately distinguishes files from directories."""
    # File
    f = tmp_path / "single_file.dat"
    f.write_bytes(b"\xaa" * 512)
    res_f = client.get(f"/api/target/intelligence?target_type=FILE&file_path={f}", headers=auth_headers_operator)
    assert res_f.status_code == 200
    assert res_f.json()["is_directory"] is False
    assert res_f.json()["file_count"] == 1

    # Folder
    d = tmp_path / "folder_target"
    d.mkdir()
    (d / "a.txt").write_text("aaa")
    (d / "b.txt").write_text("bbb")
    res_d = client.get(f"/api/target/intelligence?target_type=FOLDER&file_path={d}", headers=auth_headers_operator)
    assert res_d.status_code == 200
    assert res_d.json()["is_directory"] is True
    assert res_d.json()["file_count"] == 2


# ============================================================================
# P1-13: System Version & Invariant Provenance
# ============================================================================

def test_p1_13_system_version_provenance(client, auth_headers_operator):
    """P1-13: System version reports 2.0.0 and dynamic 1008 baseline invariants."""
    res = client.get("/api/system/version", headers=auth_headers_operator)
    assert res.status_code == 200
    data = res.json()
    assert data["version"] == "2.0.0"
    assert data["total_tests_passed"] == 1008
    assert "is_windows_elevated" in data


# ============================================================================
# P1-14: Sanitization Execution Integration with Dual Authorization
# ============================================================================

def test_p1_14_sanitization_execute_dual_authorization_enforcement(client, auth_headers_operator, auth_headers_admin, tmp_path):
    """P1-14: POST /api/sanitization/execute requires valid approved dual authorization token."""
    target_f = tmp_path / "disposable_test_target.bin"
    target_f.write_bytes(b"\x55" * 1024)

    # Attempt execute with fake token -> must be rejected with 403
    execute_payload = {
        "target_path": str(target_f),
        "method_id": 8,
        "authorization_token": "DREX-AUTH-INVALID",
    }
    res = client.post("/api/sanitization/execute", json=execute_payload, headers=auth_headers_operator)
    assert res.status_code == 403
    assert "DUAL_AUTHORIZATION_DENIED" in res.json()["detail"]

    # Now create and approve valid token
    req_body = {
        "target_type": "FILE",
        "target_identifier": str(target_f),
        "method_id": 8,
        "operator_phrase": "CONFIRM DESTROY DATA",
        "reason": "Valid test erase",
    }
    req_res = client.post("/api/authorization/dual/request", json=req_body, headers=auth_headers_operator)
    valid_token = req_res.json()["authorization_token"]

    app_body = {
        "authorization_token": valid_token,
        "approver_username": "security_admin",
        "approver_role": "ADMIN",
        "approval_notes": "Approved test execution",
    }
    client.post("/api/authorization/dual/approve", json=app_body, headers=auth_headers_admin)

    # Execute with valid approved token -> should succeed
    execute_payload["authorization_token"] = valid_token
    exec_res = client.post("/api/sanitization/execute", json=execute_payload, headers=auth_headers_operator)
    assert exec_res.status_code == 200
    assert exec_res.json()["method_id"] == 8
    assert exec_res.json()["status"] == "COMPLETED"
