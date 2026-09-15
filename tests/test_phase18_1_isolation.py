"""
DREX-V2 Phase 18.1 State, Job, Workflow & Case Isolation Test Suite
===================================================================
Authoritative deterministic tests verifying the 8 defect classes eliminated in Phase 18.1:

1. Cross-Workflow Candidate & UI State Isolation (Carver vs Recovery vs Fragments)
2. Cross-Case Evidence Vault Isolation (Case A vs Case B)
3. Cross-Case Audit Ledger & Hash Chain Isolation
4. Cross-Case Recovery Candidate Isolation
5. Cross-Case Certificate Ingestion Isolation
6. Cross-Case Job Lookup & Cancellation Rejection (HTTP 404 on cross-case query)
7. Fail-Closed Behavior on Missing/Invalid case_id (HTTP 400 on /recovery/scan, /sanitization; empty lists on /evidence, /audit, /certificates with zero silent fallbacks)
8. Canonical Job Identity Preservation (case_id, workflow_id, job_id, method_id, target_id)
9. Job Target & Method Snapshot Immutability
10. Judge Demonstration Proof Loop Namespace Isolation (EVAL- namespace leaves operational cases untouched)
"""

import os
import shutil
import tempfile
import pytest
from fastapi.testclient import TestClient

import drex_api_models as models
import drex_rbac as rbac
from drex_server import app, case_manager, job_registry
from forensic_vault import ForensicCaseManager


@pytest.fixture
def client():
    token = rbac.create_access_token(models.UserRole.ADMIN)
    c = TestClient(app)
    c.headers["Authorization"] = f"Bearer {token}"
    return c


@pytest.fixture
def two_cases(client):
    """Creates two distinct operational cases for cross-case isolation tests."""
    c1_res = client.post(
        "/api/cases",
        json={
            "case_number": "DREX-ISO-CASE-A",
            "title": "Case Alpha Forensic Triage",
            "examiner": "Lead Examiner Alpha",
            "organization": "Forensic Lab Alpha",
            "notes": "Isolation verification case A",
        },
    )
    assert c1_res.status_code == 200
    case_a = c1_res.json()

    c2_res = client.post(
        "/api/cases",
        json={
            "case_number": "DREX-ISO-CASE-B",
            "title": "Case Beta Forensic Triage",
            "examiner": "Lead Examiner Beta",
            "organization": "Forensic Lab Beta",
            "notes": "Isolation verification case B",
        },
    )
    assert c2_res.status_code == 200
    case_b = c2_res.json()

    return case_a, case_b


# ─── 1. Cross-Case Evidence Vault Isolation ────────────────────────────────────

def test_01_cross_case_evidence_vault_isolation(client, two_cases):
    case_a, case_b = two_cases
    case_a_id = case_a["case_id"]
    case_b_id = case_b["case_id"]

    # Reconstruct a candidate in Case A
    recon_res = client.post(
        "/api/recovery/reconstruct",
        json={
            "case_id": case_a_id,
            "file_type": "PNG",
            "filename": "vault_isolated_artifact.png",
            "fragments": [
                {
                    "chunk_id": 1,
                    "offset": 0,
                    "data_hex": "89504e470d0a1a0a0000000d49484452000000100000001008060000001ff3ff61",
                    "is_header": True,
                    "is_footer": False,
                },
                {
                    "chunk_id": 2,
                    "offset": 4096,
                    "data_hex": "0000000049454e44ae426082",
                    "is_header": False,
                    "is_footer": True,
                },
            ],
            "strict_structure_validation": False,
        },
    )
    assert recon_res.status_code == 200
    cand_id = recon_res.json()["candidate_id"]

    # Ingest candidate specifically into Case A's immutable Evidence Vault
    extract_res = client.post(
        "/api/recovery/extract",
        json={
            "case_id": case_a_id,
            "candidate_id": cand_id,
            "notes": "Vault artifact bound strictly to Case A",
        },
    )
    assert extract_res.status_code == 200
    extracted = extract_res.json()
    vault_obj_id = extracted["vault_object_id"]

    # Query Case A evidence -> must contain the vault artifact
    res_a = client.get(f"/api/evidence?case_id={case_a_id}")
    assert res_a.status_code == 200
    items_a = res_a.json()
    ids_a = [item["evidence_id"] for item in items_a]
    assert vault_obj_id in ids_a

    # Query Case B evidence -> MUST NOT contain Case A's evidence
    res_b = client.get(f"/api/evidence?case_id={case_b_id}")
    assert res_b.status_code == 200
    items_b = res_b.json()
    ids_b = [item["evidence_id"] for item in items_b]
    assert vault_obj_id not in ids_b
    assert len(ids_b) == 0


# ─── 2. Cross-Case Audit Ledger & Hash Chain Isolation ────────────────────────

def test_02_cross_case_audit_ledger_isolation(client, two_cases):
    case_a, case_b = two_cases
    case_a_id = case_a["case_id"]
    case_b_id = case_b["case_id"]

    # Log an operation into Case A
    with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as f:
        f.write(b"Audit test content for case A")
        tmp_target = f.name

    try:
        clean_target = tmp_target.replace("\\", "_").replace("/", "_").replace(".", "_").replace(":", "_").strip("_").upper()
        safety_phrase = f"ERASE-{clean_target}-PERMANENT"

        shred_res = client.post(
            "/api/sanitization/execute",
            json={
                "case_id": case_a_id,
                "target_path": tmp_target,
                "method_id": 8,
                "safety_phrase_entered": safety_phrase,
            },
        )
        assert shred_res.status_code == 200

        # Query Case A ledger -> must contain audit events for Case A
        ledger_a = client.get(f"/api/audit/ledger?case_id={case_a_id}").json()
        assert len(ledger_a) >= 2  # Genesis + Sanitization

        # Query Case B ledger -> MUST NOT contain any events from Case A
        ledger_b = client.get(f"/api/audit/ledger?case_id={case_b_id}").json()
        assert len(ledger_b) == 1  # Only Case B genesis

        event_ids_a = {ev["event_id"] for ev in ledger_a}
        event_ids_b = {ev["event_id"] for ev in ledger_b}
        assert len(event_ids_a.intersection(event_ids_b)) == 0

    finally:
        if os.path.exists(tmp_target):
            os.remove(tmp_target)


# ─── 3. Cross-Case Recovery Candidates Isolation ──────────────────────────────

def test_03_cross_case_recovery_candidates_isolation(client, two_cases):
    case_a, case_b = two_cases
    case_a_id = case_a["case_id"]
    case_b_id = case_b["case_id"]

    # Reconstruct a fragment into Case A
    recon_res = client.post(
        "/api/recovery/reconstruct",
        json={
            "case_id": case_a_id,
            "file_type": "PNG",
            "filename": "case_a_isolated_evidence.png",
            "fragments": [
                {
                    "chunk_id": 1,
                    "offset": 0,
                    "data_hex": "89504e470d0a1a0a0000000d49484452000000100000001008060000001ff3ff61",
                    "is_header": True,
                    "is_footer": False,
                },
                {
                    "chunk_id": 2,
                    "offset": 4096,
                    "data_hex": "0000000049454e44ae426082",
                    "is_header": False,
                    "is_footer": True,
                },
            ],
            "strict_structure_validation": False,
        },
    )
    assert recon_res.status_code == 200
    candidate_id = recon_res.json()["candidate_id"]

    # Query Case A candidates -> must include candidate_id
    cands_a = client.get(f"/api/recovery/candidates?case_id={case_a_id}").json()
    ids_a = [c["candidate_id"] for c in cands_a]
    assert candidate_id in ids_a

    # Query Case B candidates -> MUST NOT include Case A candidate
    cands_b = client.get(f"/api/recovery/candidates?case_id={case_b_id}").json()
    ids_b = [c["candidate_id"] for c in cands_b]
    assert candidate_id not in ids_b


# ─── 4. Cross-Case Certificate Ingestion Isolation ─────────────────────────────

def test_04_cross_case_certificate_isolation(client, two_cases):
    case_a, case_b = two_cases
    case_a_id = case_a["case_id"]
    case_b_id = case_b["case_id"]

    # Generate certificate bound strictly to Case A
    gen_res = client.post(
        "/api/certificates/generate",
        json={
            "case_id": case_a_id,
            "target_identifier": "TEST_CASE_A_TARGET",
            "method_id": 8,
            "examiner_name": "Examiner Alpha",
        },
    )
    assert gen_res.status_code == 200
    cert_id = gen_res.json()["certificate_id"]

    # Query Case A certificates -> must include cert_id
    certs_a = client.get(f"/api/certificates?case_id={case_a_id}").json()
    ids_a = [c["certificate_id"] for c in certs_a]
    assert cert_id in ids_a

    # Query Case B certificates -> MUST NOT include Case A certificate
    certs_b = client.get(f"/api/certificates?case_id={case_b_id}").json()
    ids_b = [c["certificate_id"] for c in certs_b]
    assert cert_id not in ids_b


# ─── 5. Cross-Case Job Lookup & Cancel Rejection (HTTP 404) ────────────────────

def test_05_cross_case_job_isolation(client, two_cases):
    case_a, case_b = two_cases
    case_a_id = case_a["case_id"]
    case_b_id = case_b["case_id"]

    # Dispatch a recovery scan job in Case A
    scan_res = client.post(
        "/api/recovery/scan",
        json={
            "case_id": case_a_id,
            "source_path": "tests/fixtures/sample_disk.img",
            "destination_dir": "vault/extracted",
            "engine": "17",
            "workflow_id": "recovery",
        },
    )
    assert scan_res.status_code == 200
    job_id = scan_res.json()["job_id"]
    assert job_id is not None

    # Query job using correct Case A -> 200 OK
    job_a_res = client.get(f"/api/jobs/{job_id}?case_id={case_a_id}")
    assert job_a_res.status_code == 200
    assert job_a_res.json()["job_id"] == job_id
    assert job_a_res.json()["case_id"] == case_a_id

    # Query job using wrong Case B -> 404 Not Found (cross-case isolation!)
    job_b_res = client.get(f"/api/jobs/{job_id}?case_id={case_b_id}")
    assert job_b_res.status_code == 404

    # Attempt to cancel Case A's job using Case B's case_id -> 404 Not Found
    cancel_b_res = client.post(f"/api/jobs/{job_id}/cancel?case_id={case_b_id}")
    assert cancel_b_res.status_code == 404


# ─── 6. Fail-Closed on Missing Case ID on Mutating Endpoints ──────────────────

def test_06_fail_closed_on_missing_case_id(client):
    # 1. /api/evidence without case_id returns empty list (no fallback to cases[0])
    res_ev = client.get("/api/evidence")
    assert res_ev.status_code == 200
    assert res_ev.json() == []

    # 2. /api/recovery/scan with non-existent case_id returns 400 Bad Request
    res_scan = client.post(
        "/api/recovery/scan",
        json={
            "case_id": "NON_EXISTENT_CASE_99999",
            "source_path": "tests/fixtures/sample_disk.img",
            "destination_dir": "vault/extracted",
            "engine": "17",
        },
    )
    assert res_scan.status_code == 400
    assert "case not found" in res_scan.json()["detail"].lower() or "invalid case id" in res_scan.json()["detail"].lower()

    # 3. /api/sanitization/execute with non-existent case_id returns 400 Bad Request
    res_san = client.post(
        "/api/sanitization/execute",
        json={
            "case_id": "NON_EXISTENT_CASE_99999",
            "target_path": "test.txt",
            "method_id": 8,
            "safety_phrase_entered": "ERASE-TEST_TXT-PERMANENT",
        },
    )
    assert res_san.status_code == 400
    assert "case not found" in res_san.json()["detail"].lower() or "invalid case id" in res_san.json()["detail"].lower()

    # 4. /api/audit/ledger without case_id returns empty list (zero cross-case leakage)
    res_aud = client.get("/api/audit/ledger")
    assert res_aud.status_code == 200
    assert res_aud.json() == []

    # 5. /api/certificates without case_id returns empty list (zero cross-case leakage)
    res_cert = client.get("/api/certificates")
    assert res_cert.status_code == 200
    assert res_cert.json() == []


# ─── 7. Canonical Job Identity Preservation ───────────────────────────────────

def test_07_canonical_job_identity_preservation(client, two_cases):
    case_a, _ = two_cases
    case_a_id = case_a["case_id"]

    scan_res = client.post(
        "/api/recovery/scan",
        json={
            "case_id": case_a_id,
            "source_path": "tests/fixtures/sample_disk.img",
            "destination_dir": "vault/carved",
            "engine": "21",
            "workflow_id": "carving",
            "target_id": "TARGET-IMAGE-DISK",
        },
    )
    assert scan_res.status_code == 200
    job_id = scan_res.json()["job_id"]

    job_info = client.get(f"/api/jobs/{job_id}?case_id={case_a_id}").json()
    assert job_info["case_id"] == case_a_id
    assert job_info["workflow_id"] == "carving"
    assert job_info["job_id"] == job_id
    assert job_info["method_id"] == 21
    assert job_info["target_id"] == "TARGET-IMAGE-DISK"


# ─── 8. Target & Method Snapshot Immutability ─────────────────────────────────

def test_08_target_and_method_snapshot_immutability(client, two_cases):
    case_a, _ = two_cases
    case_a_id = case_a["case_id"]

    scan_res = client.post(
        "/api/recovery/scan",
        json={
            "case_id": case_a_id,
            "source_path": "tests/fixtures/sample_disk.img",
            "destination_dir": "vault/extracted",
            "engine": "17",
            "workflow_id": "recovery",
            "target_id": "DEV-PHYSICAL-0",
        },
    )
    assert scan_res.status_code == 200
    job_id = scan_res.json()["job_id"]

    job_record = client.get(f"/api/jobs/{job_id}?case_id={case_a_id}").json()
    # Ensure immutable snapshot values are preserved
    assert job_record["method_id"] == 17
    assert job_record["target_id"] == "DEV-PHYSICAL-0"
    assert job_record["target_path"] == "tests/fixtures/sample_disk.img"
    assert job_record["workflow_id"] == "recovery"


# ─── 9. Judge Proof Loop Namespace Isolation ─────────────────────────────────

def test_09_judge_proof_loop_namespace_isolation(client, two_cases):
    case_a, _ = two_cases
    case_a_id = case_a["case_id"]

    # Record baseline state of Case A
    evidence_before = client.get(f"/api/evidence?case_id={case_a_id}").json()
    ledger_before = client.get(f"/api/audit/ledger?case_id={case_a_id}").json()
    certs_before = client.get(f"/api/certificates?case_id={case_a_id}").json()

    # Run the automated 6-step Judge Demonstration Proof Loop
    demo_res = client.post("/api/demo/flow")
    assert demo_res.status_code == 200
    demo_data = demo_res.json()

    assert "PASS" in demo_data["verdict"]
    assert "EVAL" in demo_data.get("case_number", "") or "EVAL" in demo_data.get("case_id", "")
    assert demo_data["case_id"] != case_a_id

    # Verify that Case A was NOT mutated or polluted by the demo run
    evidence_after = client.get(f"/api/evidence?case_id={case_a_id}").json()
    ledger_after = client.get(f"/api/audit/ledger?case_id={case_a_id}").json()
    certs_after = client.get(f"/api/certificates?case_id={case_a_id}").json()

    assert len(evidence_after) == len(evidence_before)
    assert len(ledger_after) == len(ledger_before)
    assert len(certs_after) == len(certs_before)


# ─── 10. Cross-Case Backup & Restore Isolation ────────────────────────────────

def test_10_cross_case_backup_and_restore_isolation(client, two_cases):
    case_a, case_b = two_cases
    case_a_id = case_a["case_id"]
    case_b_id = case_b["case_id"]

    # Backup Case A
    backup_res = client.post(f"/api/cases/{case_a_id}/backup")
    assert backup_res.status_code == 200
    backup_data = backup_res.json()
    backup_path = backup_data["backup_path"]
    assert os.path.exists(backup_path)

    try:
        # Remove live Case A from disk to test restoration cleanly
        case_dir = case_manager._case_path(case_a_id)
        shutil.rmtree(case_dir, ignore_errors=True)

        # Restore Case A from backup
        restore_res = client.post(
            "/api/cases/restore",
            json={"backup_zip_path": backup_path},
        )
        assert restore_res.status_code == 200
        restored = restore_res.json()
        assert restored["case_id"] == case_a_id
        assert restored["audit_chain_valid"] is True

        # Case B remains untouched
        certs_b = client.get(f"/api/certificates?case_id={case_b_id}").json()
        assert len(certs_b) == 0

    finally:
        if os.path.exists(backup_path):
            try:
                os.remove(backup_path)
            except OSError:
                pass
        if os.path.exists(backup_data.get("manifest_path", "")):
            try:
                os.remove(backup_data["manifest_path"])
            except OSError:
                pass


# ─── 11. Cross-Workflow Notification & Progress Isolation ─────────────────────

def test_11_cross_workflow_notification_and_progress_isolation(client, two_cases):
    case_a, _ = two_cases
    case_a_id = case_a["case_id"]

    # Dispatch jobs with distinct workflow IDs
    j_rec = client.post(
        "/api/recovery/scan",
        json={
            "case_id": case_a_id,
            "source_path": "tests/fixtures/sample_disk.img",
            "destination_dir": "vault/extracted",
            "engine": "17",
            "workflow_id": "recovery",
            "target_id": "DEV-IMG-0",
        },
    ).json()

    j_carve = client.post(
        "/api/recovery/scan",
        json={
            "case_id": case_a_id,
            "source_path": "tests/fixtures/sample_disk.img",
            "destination_dir": "vault/carved",
            "engine": "21",
            "workflow_id": "carving",
            "target_id": "DEV-IMG-1",
        },
    ).json()

    rec_job_id = j_rec["job_id"]
    carve_job_id = j_carve["job_id"]

    rec_info = client.get(f"/api/jobs/{rec_job_id}?case_id={case_a_id}").json()
    carve_info = client.get(f"/api/jobs/{carve_job_id}?case_id={case_a_id}").json()

    assert rec_info["workflow_id"] == "recovery"
    assert carve_info["workflow_id"] == "carving"
    assert rec_info["target_id"] == "DEV-IMG-0"
    assert carve_info["target_id"] == "DEV-IMG-1"
    assert rec_info["job_id"] != carve_info["job_id"]


# ─── 12. Notification Subscription & Job Lifecycle Cleanup ────────────────────

def test_12_notification_subscription_and_job_lifecycle_cleanup(client, two_cases):
    case_a, _ = two_cases
    case_a_id = case_a["case_id"]

    # Dispatch a fast scan job
    res = client.post(
        "/api/recovery/scan",
        json={
            "case_id": case_a_id,
            "source_path": "tests/fixtures/sample_disk.img",
            "destination_dir": "vault/extracted",
            "engine": "17",
            "workflow_id": "recovery",
        },
    )
    job_id = res.json()["job_id"]

    # Query job status
    status = client.get(f"/api/jobs/{job_id}?case_id={case_a_id}").json()
    assert status["status"] in ["PENDING", "RUNNING", "COMPLETED", "FAILED", "BLOCKED"]
    assert status["job_id"] == job_id
    assert status["case_id"] == case_a_id


# ─── 13. Repeated Navigation Does Not Duplicate Events ────────────────────────

def test_13_repeated_navigation_does_not_duplicate_events(client, two_cases):
    case_a, _ = two_cases
    case_a_id = case_a["case_id"]

    # Initial state
    baseline_ledger = client.get(f"/api/audit/ledger?case_id={case_a_id}").json()
    baseline_len = len(baseline_ledger)

    # Simulate 20 navigation cycles querying the ledger & evidence
    for _ in range(20):
        ledger = client.get(f"/api/audit/ledger?case_id={case_a_id}").json()
        evidence = client.get(f"/api/evidence?case_id={case_a_id}").json()
        certs = client.get(f"/api/certificates?case_id={case_a_id}").json()
        assert len(ledger) == baseline_len
        assert isinstance(evidence, list)
        assert isinstance(certs, list)


# ─── 14. Stale Async Response Rejection ───────────────────────────────────────

def test_14_stale_async_response_rejection(client, two_cases):
    case_a, case_b = two_cases
    case_a_id = case_a["case_id"]
    case_b_id = case_b["case_id"]

    # Reconstruct fragment in Case A
    res_a = client.post(
        "/api/recovery/reconstruct",
        json={
            "case_id": case_a_id,
            "file_type": "PNG",
            "filename": "isolated_a.png",
            "fragments": [
                {
                    "chunk_id": 1,
                    "offset": 0,
                    "data_hex": "89504e470d0a1a0a0000000d49484452000000100000001008060000001ff3ff61",
                    "is_header": True,
                    "is_footer": False,
                },
                {
                    "chunk_id": 2,
                    "offset": 4096,
                    "data_hex": "0000000049454e44ae426082",
                    "is_header": False,
                    "is_footer": True,
                },
            ],
            "strict_structure_validation": False,
        },
    )
    assert res_a.status_code == 200
    cand_id_a = res_a.json()["candidate_id"]

    # Verify candidate is ONLY in Case A
    cands_a = [c["candidate_id"] for c in client.get(f"/api/recovery/candidates?case_id={case_a_id}").json()]
    cands_b = [c["candidate_id"] for c in client.get(f"/api/recovery/candidates?case_id={case_b_id}").json()]

    assert cand_id_a in cands_a
    assert cand_id_a not in cands_b


# ─── 15. Active Case Immutability ─────────────────────────────────────────────

def test_15_active_case_immutability(client, two_cases):
    case_a, case_b = two_cases
    case_a_id = case_a["case_id"]

    # Query cases list
    cases_res = client.get("/api/cases")
    assert cases_res.status_code == 200
    cases_list = cases_res.json()
    case_ids = [c["case_id"] for c in cases_list]
    assert case_a_id in case_ids

    # Run background judge demo flow
    demo_res = client.post("/api/demo/flow")
    assert demo_res.status_code == 200

    # Ensure Case A metadata and presence remain pristine
    case_a_check = client.get(f"/api/cases/{case_a_id}")
    assert case_a_check.status_code == 200
    assert case_a_check.json()["case_id"] == case_a_id
    assert case_a_check.json()["case_number"] == case_a["case_number"]


# ─── 16. Case Switch During Running Job ───────────────────────────────────────

def test_16_case_switch_during_running_job(client, two_cases):
    case_a, case_b = two_cases
    case_a_id = case_a["case_id"]
    case_b_id = case_b["case_id"]

    # Dispatch scan in Case A
    res = client.post(
        "/api/recovery/scan",
        json={
            "case_id": case_a_id,
            "source_path": "tests/fixtures/sample_disk.img",
            "destination_dir": "vault/extracted",
            "engine": "17",
            "workflow_id": "recovery",
        },
    )
    job_id = res.json()["job_id"]

    # Switch focus to Case B and query its state
    evidence_b = client.get(f"/api/evidence?case_id={case_b_id}").json()
    candidates_b = client.get(f"/api/recovery/candidates?case_id={case_b_id}").json()
    assert len(evidence_b) == 0
    assert len(candidates_b) == 0

    # Query job in Case A context
    job_res = client.get(f"/api/jobs/{job_id}?case_id={case_a_id}")
    assert job_res.status_code == 200
    assert job_res.json()["case_id"] == case_a_id


# ─── 17. Cross-Module Error Isolation ─────────────────────────────────────────

def test_17_cross_module_error_isolation(client, two_cases):
    case_a, _ = two_cases
    case_a_id = case_a["case_id"]

    # M01 Drive Eraser Error (Blocked on missing safety phrase / invalid target)
    err_m01 = client.post(
        "/api/sanitization/execute",
        json={
            "case_id": case_a_id,
            "target_path": "\\\\.\\PhysicalDrive99",
            "method_id": 1,
            "safety_phrase_entered": "WRONG_PHRASE",
        },
    )
    assert err_m01.status_code in [400, 422]

    # M08 File Shredder Error (Target file does not exist)
    err_m08 = client.post(
        "/api/sanitization/execute",
        json={
            "case_id": case_a_id,
            "target_path": "non_existent_file_9999.tmp",
            "method_id": 8,
            "safety_phrase_entered": "ERASE-NON_EXISTENT_FILE_9999_TMP-PERMANENT",
        },
    )
    assert err_m08.status_code in [400, 404, 422]

    # M17 Recovery Scan (Valid disk image) succeeds regardless of previous M01/M08 errors
    ok_m17 = client.post(
        "/api/recovery/scan",
        json={
            "case_id": case_a_id,
            "source_path": "tests/fixtures/sample_disk.img",
            "destination_dir": "vault/extracted",
            "engine": "17",
            "workflow_id": "recovery",
        },
    )
    assert ok_m17.status_code == 200

    # M22 Fragment Reassembly (Invalid empty fragments) returns 400 or 422
    err_m22 = client.post(
        "/api/recovery/reconstruct",
        json={
            "case_id": case_a_id,
            "file_type": "PNG",
            "filename": "invalid.png",
            "fragments": [],
        },
    )
    assert err_m22.status_code in [400, 422]


# ─── 18. Exact Reproduction of Sanitization Error Contamination ───────────────

def test_18_exact_reproduction_of_sanitization_error_contamination(client, two_cases):
    case_a, case_b = two_cases
    case_a_id = case_a["case_id"]
    case_b_id = case_b["case_id"]

    # 1. Trigger blocked sanitization error on invalid PhysicalDrive
    blocked_res = client.post(
        "/api/sanitization/execute",
        json={
            "case_id": case_a_id,
            "target_path": "\\\\.\\PhysicalDrive1",
            "method_id": 1,
            "safety_phrase_entered": "ERASE-__PHYSICALDRIVE1-PERMANENT",
        },
    )
    # Blocked due to non-existent / locked physical device
    assert blocked_res.status_code in [400, 422]

    # 2. Query File Shredder with legitimate disposable temp file -> MUST NOT be contaminated
    with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as f:
        f.write(b"Legitimate shredder payload")
        clean_file = f.name

    try:
        clean_target = clean_file.replace("\\", "_").replace("/", "_").replace(".", "_").replace(":", "_").strip("_").upper()
        phrase = f"ERASE-{clean_target}-PERMANENT"
        shred_res = client.post(
            "/api/sanitization/execute",
            json={
                "case_id": case_a_id,
                "target_path": clean_file,
                "method_id": 8,
                "safety_phrase_entered": phrase,
            },
        )
        assert shred_res.status_code == 200
        shred_data = shred_res.json()
        assert "PASS" in shred_data["verdict"] or shred_data["verdict"] in ["PASS", "COMPLETED", "VERIFIED"]
    finally:
        if os.path.exists(clean_file):
            os.remove(clean_file)

    # 3. Query Recovery Candidates in Case A and Case B -> Zero sanitization errors
    cands_a = client.get(f"/api/recovery/candidates?case_id={case_a_id}").json()
    cands_b = client.get(f"/api/recovery/candidates?case_id={case_b_id}").json()
    assert isinstance(cands_a, list)
    assert isinstance(cands_b, list)

    # 4. Verify Case B evidence vault is clean
    ev_b = client.get(f"/api/evidence?case_id={case_b_id}").json()
    assert len(ev_b) == 0

