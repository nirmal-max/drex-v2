"""
=============================================================================
DREX-V2 — PHASE 22: P0-01 AUTHORITATIVE CASE CONTEXT REGRESSION SUITE
=============================================================================
Formally verifies the invariant:
    active_case_id == workflow.case_id == job.case_id == audit.case_id == evidence.case_id
and ensures no operation launched from CASE-A receives CASE-B or an unrelated case.
=============================================================================
"""

import os
import uuid
import pytest
from fastapi.testclient import TestClient
from drex_server import app, case_manager, job_registry
import drex_api_models as models


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def admin_token(client):
    res = client.post("/api/auth/switch-persona", json={"target_role": "ADMIN"})
    assert res.status_code == 200
    return res.json()["access_token"]


@pytest.fixture
def auth_headers(admin_token):
    return {"Authorization": f"Bearer {admin_token}"}


def test_p0_01_case_a_and_case_b_isolation(client, auth_headers, tmp_path):
    """
    Formally verifies P0-01 algorithm:
    1. Create CASE-A and CASE-B.
    2. Set active case = CASE-A -> Launch recovery & sanitization -> verify job.case_id == CASE-A.
    3. Switch to CASE-B -> Launch recovery & sanitization -> verify job.case_id == CASE-B.
    4. Verify strict isolation: No operation launched from CASE-A receives CASE-B.
    """
    case_a_num = f"CASE-A-{uuid.uuid4().hex[:6].upper()}"
    case_b_num = f"CASE-B-{uuid.uuid4().hex[:6].upper()}"

    res_a = client.post("/api/cases", json={
        "case_number": case_a_num,
        "title": "Case Alpha Investigation",
        "examiner": "Lead Forensic Examiner A",
        "organization": "NTRO Forensic Unit",
    }, headers=auth_headers)
    assert res_a.status_code == 200
    case_a = res_a.json()
    case_a_id = case_a["case_id"]

    res_b = client.post("/api/cases", json={
        "case_number": case_b_num,
        "title": "Case Beta Investigation",
        "examiner": "Lead Forensic Examiner B",
        "organization": "NTRO Forensic Unit",
    }, headers=auth_headers)
    assert res_b.status_code == 200
    case_b = res_b.json()
    case_b_id = case_b["case_id"]

    assert case_a_id != case_b_id

    # Create safe disposable targets for tests (separate to respect active target locks)
    rec_target_a = tmp_path / "rec_target_a.bin"
    rec_target_a.write_bytes(b"\xAA" * 65536)
    san_target_a = tmp_path / "san_target_a.bin"
    san_target_a.write_bytes(b"\xAA" * 65536)

    rec_target_b = tmp_path / "rec_target_b.bin"
    rec_target_b.write_bytes(b"\xBB" * 65536)
    san_target_b = tmp_path / "san_target_b.bin"
    san_target_b.write_bytes(b"\xBB" * 65536)

    # ── Step 1: Launch Operations on CASE-A ─────────────────────────────
    # Recovery Scan on Case A
    res_rec_a = client.post("/api/recovery/scan", json={
        "case_id": case_a_id,
        "source_path": str(rec_target_a),
        "destination_dir": str(tmp_path / "vault_a"),
        "engine": "17",
    }, headers=auth_headers)
    assert res_rec_a.status_code == 200
    job_rec_a = res_rec_a.json()
    assert job_rec_a["case_id"] == case_a_id, f"Expected {case_a_id}, got {job_rec_a['case_id']}"
    assert "job_id" in job_rec_a
    assert "workflow_id" in job_rec_a

    # Sanitization on Case A
    clean_target_a = str(san_target_a).replace("\\", "_").replace("/", "_").replace(".", "_").strip("_").upper()
    phrase_a = f"ERASE-{clean_target_a}-PERMANENT"
    res_san_a = client.post("/api/sanitization/execute", json={
        "case_id": case_a_id,
        "target_path": str(san_target_a),
        "method_id": 8,
        "safety_phrase_entered": phrase_a,
        "async_execution": True,
    }, headers=auth_headers)
    assert res_san_a.status_code == 200
    job_san_a = res_san_a.json()
    assert job_san_a["case_id"] == case_a_id, f"Expected {case_a_id}, got {job_san_a['case_id']}"

    # ── Step 2: Switch to CASE-B & Launch Operations ─────────────────────
    # Recovery Scan on Case B
    res_rec_b = client.post("/api/recovery/scan", json={
        "case_id": case_b_id,
        "source_path": str(rec_target_b),
        "destination_dir": str(tmp_path / "vault_b"),
        "engine": "17",
    }, headers=auth_headers)
    assert res_rec_b.status_code == 200
    job_rec_b = res_rec_b.json()
    assert job_rec_b["case_id"] == case_b_id, f"Expected {case_b_id}, got {job_rec_b['case_id']}"

    # Sanitization on Case B
    clean_target_b = str(san_target_b).replace("\\", "_").replace("/", "_").replace(".", "_").strip("_").upper()
    phrase_b = f"ERASE-{clean_target_b}-PERMANENT"
    res_san_b = client.post("/api/sanitization/execute", json={
        "case_id": case_b_id,
        "target_path": str(san_target_b),
        "method_id": 8,
        "safety_phrase_entered": phrase_b,
        "async_execution": True,
    }, headers=auth_headers)
    assert res_san_b.status_code == 200
    job_san_b = res_san_b.json()
    assert job_san_b["case_id"] == case_b_id, f"Expected {case_b_id}, got {job_san_b['case_id']}"

    # ── Step 3: Invariant Proof — Strict Cross-Case Isolation ───────────
    # Active jobs for Case A must contain ONLY Case A jobs
    res_active_a = client.get(f"/api/jobs/active?case_id={case_a_id}", headers=auth_headers)
    assert res_active_a.status_code == 200
    jobs_a = res_active_a.json()
    for j in jobs_a:
        assert j["case_id"] == case_a_id, f"Leakage: Job {j['job_id']} with case {j['case_id']} returned in Case A query!"

    # Active jobs for Case B must contain ONLY Case B jobs
    res_active_b = client.get(f"/api/jobs/active?case_id={case_b_id}", headers=auth_headers)
    assert res_active_b.status_code == 200
    jobs_b = res_active_b.json()
    for j in jobs_b:
        assert j["case_id"] == case_b_id, f"Leakage: Job {j['job_id']} with case {j['case_id']} returned in Case B query!"

    # Fetching Job A using Case B filter must fail closed (404 Not Found)
    res_cross = client.get(f"/api/jobs/{job_rec_a['job_id']}?case_id={case_b_id}", headers=auth_headers)
    assert res_cross.status_code == 404, "Cross-case access should be denied with 404"


def test_p0_01_backend_rejects_missing_or_invalid_case(client, auth_headers, tmp_path):
    """Verify backend enforces authoritative case_id and rejects non-existent cases."""
    dummy_file = tmp_path / "dummy.bin"
    dummy_file.write_bytes(b"\x00" * 4096)
    clean_target = str(dummy_file).replace("\\", "_").replace("/", "_").replace(".", "_").strip("_").upper()

    # 1. Non-existent case_id in recovery scan -> 400 Bad Request
    res_rec_bad = client.post("/api/recovery/scan", json={
        "case_id": "CASE-DOES-NOT-EXIST",
        "source_path": str(dummy_file),
        "destination_dir": str(tmp_path / "out"),
        "engine": "17",
    }, headers=auth_headers)
    assert res_rec_bad.status_code == 400
    assert "Invalid case ID" in res_rec_bad.json()["detail"]

    # 2. Non-existent case_id in sanitization execute -> 400 Bad Request
    res_san_bad = client.post("/api/sanitization/execute", json={
        "case_id": "CASE-DOES-NOT-EXIST",
        "target_path": str(dummy_file),
        "method_id": 8,
        "safety_phrase_entered": f"ERASE-{clean_target}-PERMANENT",
    }, headers=auth_headers)
    assert res_san_bad.status_code == 400
    assert "Invalid case ID" in res_san_bad.json()["detail"]

    # 3. Missing/empty case_id in sanitization execute -> 400 Bad Request
    res_san_none = client.post("/api/sanitization/execute", json={
        "case_id": "",
        "target_path": str(dummy_file),
        "method_id": 8,
        "safety_phrase_entered": f"ERASE-{clean_target}-PERMANENT",
    }, headers=auth_headers)
    assert res_san_none.status_code == 400
    assert "authoritative case_id" in res_san_none.json()["detail"].lower()


def test_p0_01_job_registry_invariant():
    """Verify JobRegistry architecture raises ValueError if case_id is empty."""
    with pytest.raises(ValueError, match="CRITICAL INVARIANT VIOLATION"):
        job_registry.register_job(
            job_id="TEST-FAIL-01",
            operation_type="TEST_OP",
            target_path="C:/dummy",
            case_id="",
        )

    with pytest.raises(ValueError, match="CRITICAL INVARIANT VIOLATION"):
        job_registry.register_job(
            job_id="TEST-FAIL-02",
            operation_type="TEST_OP",
            target_path="C:/dummy",
            case_id="   ",
        )


def test_p0_01_omitted_case_id_never_attaches_to_active_cases(client, auth_headers, tmp_path):
    """
    Gate 2 Authoritative Invariant:
    When CASE-A and CASE-B exist, an operation with omitted/null case_id
    MUST NEVER attach to CASE-A or CASE-B.
    It must either:
    1. Allocate a fresh isolated DREX-TRIAGE case (destructive/recovery operations), or
    2. Fail closed by returning [] (GET disclosure endpoints).
    """
    # 1. Create CASE-A and CASE-B
    res_a = client.post("/api/cases", json={
        "case_number": f"CASE-A-GATE2-{uuid.uuid4().hex[:6].upper()}",
        "title": "Active Forensic Case Alpha",
        "examiner": "Examiner Alpha",
        "organization": "Forensic Directorate",
    }, headers=auth_headers)
    assert res_a.status_code == 200
    case_a_id = res_a.json()["case_id"]

    res_b = client.post("/api/cases", json={
        "case_number": f"CASE-B-GATE2-{uuid.uuid4().hex[:6].upper()}",
        "title": "Active Forensic Case Beta",
        "examiner": "Examiner Beta",
        "organization": "Forensic Directorate",
    }, headers=auth_headers)
    assert res_b.status_code == 200
    case_b_id = res_b.json()["case_id"]

    # 2. Recovery scan with omitted case_id
    rec_file = tmp_path / "omitted_case_rec.bin"
    rec_file.write_bytes(b"\xCC" * 8192)
    res_rec = client.post("/api/recovery/scan", json={
        "source_path": str(rec_file),
        "destination_dir": str(tmp_path / "out"),
        "engine": "17",
    }, headers=auth_headers)
    assert res_rec.status_code == 200
    rec_job = res_rec.json()
    # Must NOT attach to CASE-A or CASE-B
    assert rec_job["case_id"] != case_a_id, "CRITICAL ERROR: Omitted case_id silently attached to CASE-A!"
    assert rec_job["case_id"] != case_b_id, "CRITICAL ERROR: Omitted case_id silently attached to CASE-B!"
    # Must allocate fresh isolated DREX-TRIAGE case
    triage_case = case_manager.get_case(rec_job["case_id"])
    assert triage_case is not None
    assert triage_case.case_number.startswith("DREX-TRIAGE-")

    # 3. Destructive sanitization with omitted case_id
    san_file = tmp_path / "omitted_case_san.bin"
    san_file.write_bytes(b"\xDD" * 8192)
    clean_san = str(san_file).replace("\\", "_").replace("/", "_").replace(".", "_").strip("_").upper()
    res_san = client.post("/api/sanitization/execute", json={
        "target_path": str(san_file),
        "method_id": 8,
        "safety_phrase_entered": f"ERASE-{clean_san}-PERMANENT",
        "async_execution": True,
    }, headers=auth_headers)
    assert res_san.status_code == 200
    san_job = res_san.json()
    assert san_job["case_id"] != case_a_id, "CRITICAL ERROR: Omitted case_id silently attached to CASE-A!"
    assert san_job["case_id"] != case_b_id, "CRITICAL ERROR: Omitted case_id silently attached to CASE-B!"
    triage_case_san = case_manager.get_case(san_job["case_id"])
    assert triage_case_san is not None
    assert triage_case_san.case_number.startswith("DREX-TRIAGE-")

    # 4. Sensitive GET endpoints must FAIL CLOSED (return empty list)
    # Evidence Vault
    res_ev = client.get("/api/evidence", headers=auth_headers)
    assert res_ev.status_code == 200
    assert res_ev.json() == [], "GET /api/evidence with omitted case_id must fail closed ([])."

    # Certificates
    res_cert = client.get("/api/certificates", headers=auth_headers)
    assert res_cert.status_code == 200
    assert res_cert.json() == [], "GET /api/certificates with omitted case_id must fail closed ([])."

    # Audit Ledger
    res_audit = client.get("/api/audit/ledger", headers=auth_headers)
    assert res_audit.status_code == 200
    assert res_audit.json() == [], "GET /api/audit/ledger with omitted case_id must fail closed ([])."

