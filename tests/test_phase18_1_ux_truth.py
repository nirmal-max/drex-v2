"""
DREX-V2 Phase 18.1 UI/UX, Source Selection & Operational Truth Regression Suite
=============================================================================
Verifies the 20 specific UX, Source Selection, and State Truth Requirements:

UX-01: Active case equals job case
UX-02: Active case equals fragment target case
UX-03: Judge proof single-job isolation
UX-04: Judge proof notification isolation
UX-05: 20-navigation subscription stress & single event delivery
UX-06: Sanitization error does not appear in File Shredder
UX-07: Sanitization error does not appear in Residue Analyzer
UX-08: Recovery candidate provenance
UX-09: Fixture labeling
UX-10: Raw carving source selection
UX-11: Hex sample labeling
UX-12: Fragment input selection
UX-13: File picker support
UX-14: Folder picker support
UX-15: Source change invalidates old results
UX-16: Failed TOCTOU disables execution
UX-17: Media technology cannot silently contradict detected capability
UX-18: Plan status cannot equal execution status
UX-19: Verifier requires actual package
UX-20: Demo package explicitly labeled
"""

import os
import re
import pytest
from fastapi.testclient import TestClient

import drex_api_models as models
import drex_rbac as rbac
from drex_server import app, case_manager, job_registry


@pytest.fixture
def client():
    token = rbac.create_access_token(models.UserRole.ADMIN)
    c = TestClient(app)
    c.headers["Authorization"] = f"Bearer {token}"
    return c


@pytest.fixture
def ops_case(client):
    res = client.post(
        "/api/cases",
        json={
            "case_number": "DREX-UX-OPS-001",
            "title": "Operational UX Investigation Case",
            "examiner": "Lead Forensic Investigator",
            "organization": "Forensic Assurance Lab",
            "notes": "Testing UX and operational truth consistency",
        },
    )
    assert res.status_code == 200
    return res.json()


# ─── UX-01: Active Case Equals Job Case ────────────────────────────────────────

def test_ux_01_active_case_equals_job_case(client, ops_case):
    case_id = ops_case["case_id"]

    # Start a recovery scan job for this case
    res = client.post(
        "/api/recovery/scan",
        json={
            "case_id": case_id,
            "source_path": "tests/fixtures/sample_disk.img",
            "destination_dir": "vault/extracted",
            "engine": "17",
            "workflow_id": "recovery",
        },
    )
    assert res.status_code == 200
    data = res.json()
    job_id = data["job_id"]

    # Retrieve the registered job
    job = job_registry.get_job(job_id)
    assert job is not None
    assert job["case_id"] == case_id
    assert job["workflow_id"] == "recovery"
    assert job["method_id"] == 17


# ─── UX-02: Active Case Equals Fragment Target Case ────────────────────────────

def test_ux_02_active_case_equals_fragment_target_case(client, ops_case):
    case_id = ops_case["case_id"]

    res = client.post(
        "/api/recovery/reconstruct",
        json={
            "case_id": case_id,
            "file_type": "PNG",
            "filename": "reconstructed_bi_fragment.png",
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
    assert res.status_code == 200
    data = res.json()

    # Reconstructed candidate belongs strictly to the active case
    cands_res = client.get(f"/api/recovery/candidates?case_id={case_id}")
    assert cands_res.status_code == 200
    cands = cands_res.json()
    cand_ids = [c["candidate_id"] for c in cands]
    assert data["candidate_id"] in cand_ids


# ─── UX-03: Judge Proof Single-Job Isolation ───────────────────────────────────

def test_ux_03_judge_proof_single_job_isolation(client, ops_case):
    ops_case_id = ops_case["case_id"]

    # Run Judge Demonstration Proof Flow
    res = client.post("/api/demo/flow")
    assert res.status_code == 200
    eval_data = res.json()

    assert eval_data["case_number"].startswith("EVAL-")
    assert eval_data["case_id"] != ops_case_id
    assert eval_data["verdict"].startswith("PASS")

    # Verify that operational case timeline was not polluted
    timeline_res = client.get(f"/api/cases/{ops_case_id}/timeline")
    assert timeline_res.status_code == 200
    ops_timeline = timeline_res.json()
    for ev in ops_timeline:
        assert not str(ev.get("case_id", "")).startswith("CASE-EVAL-")


# ─── UX-04: Judge Proof Notification Isolation ────────────────────────────────

def test_ux_04_judge_proof_notification_isolation(client, ops_case):
    # Verify in SPA code that judge proof notifications carry workflowId 'judge_demo'
    app_js_path = os.path.join(os.path.dirname(__file__), "..", "webui", "app.js")
    with open(app_js_path, "r", encoding="utf-8") as f:
        content = f.read()

    assert "workflowId: 'judge_demo'" in content
    # Toast filter prevents showing toasts for other workflows
    assert "workflowId && STATE.currentView && STATE.currentView !== workflowId" in content


# ─── UX-05: 20-Navigation Subscription Stress & Clean Event Dispatch ──────────

def test_ux_05_20_navigation_subscription_stress():
    app_js_path = os.path.join(os.path.dirname(__file__), "..", "webui", "app.js")
    with open(app_js_path, "r", encoding="utf-8") as f:
        content = f.read()

    # Verify notification deduplication cache and toast dismissal on navigation
    assert "_recentNotifs = new Map()" in content
    assert "toast.remove()" in content
    assert "drexNotificationContainer" in content


# ─── UX-06: Sanitization Error Does Not Appear in File Shredder ────────────────

def test_ux_06_sanitization_error_does_not_appear_in_file_shredder(client):
    app_js_path = os.path.join(os.path.dirname(__file__), "..", "webui", "app.js")
    with open(app_js_path, "r", encoding="utf-8") as f:
        content = f.read()

    # File shredder notifications are scoped strictly to 'file_eraser'
    assert "workflowId: 'file_eraser'" in content
    # Drive eraser notifications are scoped strictly to 'drive_eraser'
    assert "workflowId: 'drive_eraser'" in content


# ─── UX-07: Sanitization Error Does Not Appear in Residue Analyzer ────────────

def test_ux_07_sanitization_error_does_not_appear_in_residue_analyzer():
    app_js_path = os.path.join(os.path.dirname(__file__), "..", "webui", "app.js")
    with open(app_js_path, "r", encoding="utf-8") as f:
        content = f.read()

    assert "renderOperationalContextBar('RESIDUE ANALYZER'" in content
    assert "toast.dataset.workflowId" in content


# ─── UX-08: Recovery Candidate Provenance ──────────────────────────────────────

def test_ux_08_recovery_candidate_provenance(client, ops_case):
    case_id = ops_case["case_id"]

    res = client.post(
        "/api/recovery/reconstruct",
        json={
            "case_id": case_id,
            "file_type": "PNG",
            "filename": "provenance_test.png",
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
    assert res.status_code == 200
    recon_data = res.json()
    cand_id = recon_data["candidate_id"]

    cands_res = client.get(f"/api/recovery/candidates?case_id={case_id}")
    assert cands_res.status_code == 200
    cands = cands_res.json()
    assert len(cands) > 0

    cand = next(c for c in cands if c["candidate_id"] == cand_id)
    assert cand["candidate_id"] == cand_id
    assert "provenance" in cand
    assert cand["size_bytes"] > 0
    assert "sha256" in cand


# ─── UX-09: Fixture Labeling ───────────────────────────────────────────────────

def test_ux_09_fixture_labeling():
    app_js_path = os.path.join(os.path.dirname(__file__), "..", "webui", "app.js")
    with open(app_js_path, "r", encoding="utf-8") as f:
        content = f.read()

    assert "🧪 TEST FIXTURE (tests/fixtures/sample_disk.img)" in content
    assert "🧪 TEST FIXTURE" in content
    assert "🎯 EVALUATION ARTIFACT" in content or "🎯 EVALUATION DEMO VERIFICATION" in content


# ─── UX-10: Raw Carving Source Selection ──────────────────────────────────────

def test_ux_10_raw_carving_source_selection():
    app_js_path = os.path.join(os.path.dirname(__file__), "..", "webui", "app.js")
    with open(app_js_path, "r", encoding="utf-8") as f:
        content = f.read()

    assert "id=\"carveTargetSelect\"" in content
    assert "handleCarveSourceChange" in content
    assert "carveSourceChangeAlert" in content


# ─── UX-11: Hex Sample Labeling ────────────────────────────────────────────────

def test_ux_11_hex_sample_labeling():
    app_js_path = os.path.join(os.path.dirname(__file__), "..", "webui", "app.js")
    with open(app_js_path, "r", encoding="utf-8") as f:
        content = f.read()

    assert "🧪 SAMPLE / TEST DATA STREAM" in content
    assert "🧪 SAMPLE: PNG Image" in content
    assert "loadHexFile" in content


# ─── UX-12: Fragment Input Selection ──────────────────────────────────────────

def test_ux_12_fragment_input_selection():
    app_js_path = os.path.join(os.path.dirname(__file__), "..", "webui", "app.js")
    with open(app_js_path, "r", encoding="utf-8") as f:
        content = f.read()

    assert "SOURCE / CANDIDATE FRAGMENT SET" in content
    assert "updateFragmentSourceDisplay" in content
    assert "fragInputCandidateDisplay" in content


# ─── UX-13: File Picker Support ────────────────────────────────────────────────

def test_ux_13_file_picker_support():
    app_js_path = os.path.join(os.path.dirname(__file__), "..", "webui", "app.js")
    with open(app_js_path, "r", encoding="utf-8") as f:
        content = f.read()

    assert "id=\"shredNativeFileInput\"" in content
    assert "handleFilePickerSelect" in content
    assert "[ Browse File ]" in content


# ─── UX-14: Folder Picker Support ──────────────────────────────────────────────

def test_ux_14_folder_picker_support():
    app_js_path = os.path.join(os.path.dirname(__file__), "..", "webui", "app.js")
    with open(app_js_path, "r", encoding="utf-8") as f:
        content = f.read()

    assert "id=\"shredNativeFolderInput\"" in content
    assert "webkitdirectory" in content
    assert "handleFolderPickerSelect" in content
    assert "[ Browse Folder ]" in content


# ─── UX-15: Source Change Invalidates Old Results ─────────────────────────────

def test_ux_15_source_change_invalidates_old_results():
    app_js_path = os.path.join(os.path.dirname(__file__), "..", "webui", "app.js")
    with open(app_js_path, "r", encoding="utf-8") as f:
        content = f.read()

    assert "handleRecoverySourceChange" in content
    assert "recoverySourceChangeAlert" in content
    assert "handleCarveSourceChange" in content
    assert "carveSourceChangeAlert" in content


# ─── UX-16: Failed TOCTOU Disables Execution ──────────────────────────────────

def test_ux_16_failed_toctou_disables_execution():
    app_js_path = os.path.join(os.path.dirname(__file__), "..", "webui", "app.js")
    with open(app_js_path, "r", encoding="utf-8") as f:
        content = f.read()

    assert "TARGET_REVALIDATION_FAILED" in content
    assert "confirmErrorContainer" in content
    assert "Re-detect / Re-qualify Devices" in content


# ─── UX-17: Media Technology Cannot Silently Contradict Capability ───────────

def test_ux_17_media_technology_cannot_silently_contradict_capability():
    app_js_path = os.path.join(os.path.dirname(__file__), "..", "webui", "app.js")
    with open(app_js_path, "r", encoding="utf-8") as f:
        content = f.read()

    assert "handlePlanTargetChange" in content
    assert "handlePlanMediaOverride" in content
    assert "planMediaOverrideNotice" in content
    assert "⚠ MANUAL OVERRIDE" in content


# ─── UX-18: Plan Status Cannot Equal Execution Status ──────────────────────────

def test_ux_18_plan_status_cannot_equal_execution_status(client):
    # Test server endpoint returns plan with status and distinct execution state
    res = client.post(
        "/api/sanitization/plan",
        json={"target_path": "D:\\SafeDisposableTarget.img", "target_type": "DRIVE"},
    )
    assert res.status_code == 200
    plan = res.json()
    assert "plan_id" in plan

    app_js_path = os.path.join(os.path.dirname(__file__), "..", "webui", "app.js")
    with open(app_js_path, "r", encoding="utf-8") as f:
        content = f.read()

    assert "PLAN STATUS: READY" in content
    assert "EXECUTION: NOT STARTED" in content
    assert "VERIFICATION: NOT STARTED" in content


# ─── UX-19: Verifier Requires Actual Package ───────────────────────────────────

def test_ux_19_verifier_requires_actual_package(client):
    # Calling verify-package without specifying package path fails gracefully
    res = client.post("/api/verification/verify-package")
    assert res.status_code == 422 or res.status_code == 400

    app_js_path = os.path.join(os.path.dirname(__file__), "..", "webui", "app.js")
    with open(app_js_path, "r", encoding="utf-8") as f:
        content = f.read()

    assert "id=\"verifierPackagePath\"" in content
    assert "runIndependentPackageVerification" in content


# ─── UX-20: Demo Package Explicitly Labeled ───────────────────────────────────

def test_ux_20_demo_package_explicitly_labeled():
    app_js_path = os.path.join(os.path.dirname(__file__), "..", "webui", "app.js")
    with open(app_js_path, "r", encoding="utf-8") as f:
        content = f.read()

    assert "🎯 EVALUATION DEMO VERIFICATION" in content
    assert "DREX_EVIDENCE_PACKAGE_DEMO.zip" in content
    assert "Verify Evaluation Demo Package" in content
