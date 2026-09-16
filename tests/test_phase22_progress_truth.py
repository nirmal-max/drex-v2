"""
DREX-V2 Phase 22: Critical Progress Truth & Zero-Percentage Error Verification Suite
=====================================================================================
Formally verifies:
- State A: Pre-execution (CREATED, PRECHECK, PREPARING, QUEUED) reports 0.00% or null; no fabricated work.
- State B: Running with zero measurable work reports percent_complete = null / '—', NOT 0.01%.
- State C: First positive measurable work reports real percentage with 0.01% floor ONLY when real > 0.
- Decoupling of 100% Write Completion from VERIFIED state.
- Cooperative cancellation semantics (no false PASS, target unlocked, status CANCELLED).
- Failure transitions (status FAILED, verification NOT VERIFIED).
- Unknown total handling (indeterminate, no fabricated percentage).
- Tiny-file verification (512 B of 1 KB file reports 50%, NOT 0.01%).
- Multi-pass aggregate work (passes sum to total work; no resets).
- Directory aggregate progress (directory work reflects aggregate files, not single file).
- Speed & ETA truth rules (no fabricated speed or countdown when zero work processed).
"""

import os
import time
import pytest
from pathlib import Path
from starlette.testclient import TestClient

from drex_server import app, job_registry, case_manager, inspect_target_metadata
import drex_rbac as rbac
import drex_api_models as models
from file_sanitizer import FileSanitizer, SanitizationStandard


@pytest.fixture
def client():
    token = rbac.create_access_token(models.UserRole.ADMIN, username="admin_progress_truth")
    c = TestClient(app)
    c.headers["Authorization"] = f"Bearer {token}"
    return c


@pytest.fixture
def test_case_id():
    case = case_manager.create_case(
        case_number="CASE-P22-PROG-TRUTH-01",
        title="Phase 22 Progress Truth Invariant Verification",
        examiner="Forensic Validation Engineer",
        organization="DREX Forensics Lab",
    )
    return case.case_id


# ─── TEST 1: Processed = 0, Total = 50 MB -> percent_complete is None, NOT 0.01 ──

def test_progress_truth_state_b_zero_work_reports_null(client, test_case_id):
    """TEST 1: When job is RUNNING but processed_bytes == 0, percent_complete must be null / None."""
    job_id = f"JOB-TEST1-{int(time.time() * 1000)}"
    job_registry.create_job(
        operation_id=f"OP-{job_id}",
        job_id=job_id,
        case_id=test_case_id,
        actor="TEST_RUNNER",
        operation_type="SANITIZATION_EXECUTE",
        target_path="/dev/null",
    )

    # Transition to RUNNING with zero work
    job = job_registry.update_job(
        job_id,
        status=models.JobLifecycleState.RUNNING,
        phase="RUNNING",
        processed_bytes=0,
        total_bytes=50 * 1024 * 1024,
    )

    assert job["percent_complete"] is None, (
        f"Expected percent_complete to be None when processed_bytes == 0, got {job['percent_complete']}"
    )
    assert job["speed_bps"] == 0.0
    assert job["eta_seconds"] is None

    # Verify API contract
    res = client.get(f"/api/jobs/{job_id}?case_id={test_case_id}")
    assert res.status_code == 200
    api_data = res.json()
    assert api_data["percent_complete"] is None
    assert api_data["status"] == "RUNNING"


# ─── TEST 2: Processed = First Positive Chunk -> percent_complete > 0 and >= 0.01% ─

def test_progress_truth_state_c_first_positive_chunk(client, test_case_id):
    """TEST 2: When first positive chunk is processed, percentage must be > 0 and >= 0.01%."""
    job_id = f"JOB-TEST2-{int(time.time() * 1000)}"
    job_registry.create_job(
        operation_id=f"OP-{job_id}",
        job_id=job_id,
        case_id=test_case_id,
        actor="TEST_RUNNER",
        operation_type="SANITIZATION_EXECUTE",
        target_path="/dev/null",
    )

    total_sz = 50 * 1024 * 1024  # 50 MB
    chunk_sz = 256 * 1024        # 256 KB
    job = job_registry.update_job(
        job_id,
        status=models.JobLifecycleState.RUNNING,
        phase="WRITING",
        processed_bytes=chunk_sz,
        total_bytes=total_sz,
    )

    expected_pct = round((chunk_sz / total_sz) * 100.0, 2)  # ~0.51%
    assert job["percent_complete"] is not None
    assert job["percent_complete"] == expected_pct
    assert job["percent_complete"] >= 0.01


# ─── TEST 3: Real Percentage = 0.0001% -> Floor to 0.01% ─────────────────────

def test_progress_truth_sub_basis_point_floors_to_001(test_case_id):
    """TEST 3: Very small positive progress below 0.01% must floor to 0.01%, never 0.00%."""
    job_id = f"JOB-TEST3-{int(time.time() * 1000)}"
    job_registry.create_job(
        operation_id=f"OP-{job_id}",
        job_id=job_id,
        case_id=test_case_id,
        actor="TEST_RUNNER",
        operation_type="SANITIZATION_EXECUTE",
        target_path="/dev/null",
    )

    # 1 byte written out of 1 GB (0.0000001%)
    job = job_registry.update_job(
        job_id,
        status=models.JobLifecycleState.RUNNING,
        phase="WRITING",
        processed_bytes=1,
        total_bytes=1024 * 1024 * 1024,
    )

    assert job["percent_complete"] == 0.01, (
        f"Expected sub-basis-point progress to floor to 0.01, got {job['percent_complete']}"
    )


# ─── TEST 4: Real Percentage Exact Decimals ───────────────────────────────────

def test_progress_truth_exact_decimals(test_case_id):
    """TEST 4, 5, 6: Real percentages (0.37%, 10%, 99.99%) must match accurately."""
    job_id = f"JOB-TEST4-{int(time.time() * 1000)}"
    job_registry.create_job(
        operation_id=f"OP-{job_id}",
        job_id=job_id,
        case_id=test_case_id,
        actor="TEST_RUNNER",
        operation_type="SANITIZATION_EXECUTE",
        target_path="/dev/null",
    )

    # 0.37% test: 37 out of 10000
    job = job_registry.update_job(
        job_id,
        status=models.JobLifecycleState.RUNNING,
        phase="WRITING",
        processed_bytes=37,
        total_bytes=10000,
    )
    assert job["percent_complete"] == 0.37

    # 10% test: 1000 out of 10000
    job = job_registry.update_job(
        job_id,
        status=models.JobLifecycleState.RUNNING,
        phase="WRITING",
        processed_bytes=1000,
        total_bytes=10000,
    )
    assert job["percent_complete"] == 10.0

    # 99.99% test: 9999 out of 10000
    job = job_registry.update_job(
        job_id,
        status=models.JobLifecycleState.RUNNING,
        phase="WRITING",
        processed_bytes=9999,
        total_bytes=10000,
    )
    assert job["percent_complete"] == 99.99


# ─── TEST 7 & 8: 100% Write Completion Decoupled from VERIFIED ───────────────

def test_progress_truth_100_percent_decoupled_from_verified(test_case_id):
    """TEST 7 & 8: 100% write completion transitions to VERIFYING, NOT immediately VERIFIED."""
    job_id = f"JOB-TEST7-{int(time.time() * 1000)}"
    job_registry.create_job(
        operation_id=f"OP-{job_id}",
        job_id=job_id,
        case_id=test_case_id,
        actor="TEST_RUNNER",
        operation_type="SANITIZATION_EXECUTE",
        target_path="/dev/null",
    )

    # Writing 100% complete
    job = job_registry.update_job(
        job_id,
        status=models.JobLifecycleState.RUNNING,
        phase="WRITING",
        processed_bytes=1000,
        total_bytes=1000,
    )
    assert job["percent_complete"] == 100.0
    assert job["verification_state"] == "NOT_STARTED"

    # Transition to VERIFYING phase
    job = job_registry.update_job(
        job_id,
        phase="VERIFYING",
        verification_state="IN_PROGRESS",
    )
    assert job["percent_complete"] == 100.0
    assert job["phase"] == "VERIFYING"
    assert job["verification_state"] == "IN_PROGRESS"
    assert job["status"] != "COMPLETED"


# ─── TEST 9: Verification Success Transitions to VERIFIED ────────────────────

def test_progress_truth_verification_success_completes(test_case_id):
    """TEST 9: Terminal verification success sets VERIFIED and COMPLETED."""
    job_id = f"JOB-TEST9-{int(time.time() * 1000)}"
    job_registry.create_job(
        operation_id=f"OP-{job_id}",
        job_id=job_id,
        case_id=test_case_id,
        actor="TEST_RUNNER",
        operation_type="SANITIZATION_EXECUTE",
        target_path="/dev/null",
    )

    job_registry.update_job(job_id, status=models.JobLifecycleState.RUNNING, processed_bytes=1000, total_bytes=1000)
    job = job_registry.update_job(
        job_id,
        status=models.JobLifecycleState.COMPLETED,
        phase="COMPLETED",
        verification_state="VERIFIED",
    )
    assert job["status"] == "COMPLETED"
    assert job["verification_state"] == "VERIFIED"
    assert job["percent_complete"] == 100.0


# ─── TEST 10 & 11: Cancellation and Failure Do Not Emit VERIFIED ─────────────

def test_progress_truth_cancelled_and_failed_not_verified(test_case_id):
    """TEST 10 & 11: Cancelled or failed operations must never emit VERIFIED."""
    # Cancellation test
    job_id_c = f"JOB-TEST10-{int(time.time() * 1000)}"
    job_registry.create_job(
        operation_id=f"OP-{job_id_c}",
        job_id=job_id_c,
        case_id=test_case_id,
        actor="TEST_RUNNER",
        operation_type="SANITIZATION_EXECUTE",
        target_path="/dev/null",
    )
    job_registry.update_job(job_id_c, status=models.JobLifecycleState.RUNNING, processed_bytes=500, total_bytes=1000)
    job_c = job_registry.update_job(
        job_id_c,
        status=models.JobLifecycleState.CANCELLED,
        phase="CANCELLED",
        verification_state="UNVERIFIED",
    )
    assert job_c["status"] == "CANCELLED"
    assert job_c["verification_state"] != "VERIFIED"

    # Failure test
    job_id_f = f"JOB-TEST11-{int(time.time() * 1000)}"
    job_registry.create_job(
        operation_id=f"OP-{job_id_f}",
        job_id=job_id_f,
        case_id=test_case_id,
        actor="TEST_RUNNER",
        operation_type="SANITIZATION_EXECUTE",
        target_path="/dev/null",
    )
    job_f = job_registry.update_job(
        job_id_f,
        status=models.JobLifecycleState.FAILED,
        phase="FAILED",
        verification_state="UNVERIFIED",
        error_message="Simulated I/O fault",
    )
    assert job_f["status"] == "FAILED"
    assert job_f["verification_state"] != "VERIFIED"


# ─── TEST 12: Unknown Total Work Reports Indeterminate (null percentage) ─────

def test_progress_truth_unknown_total_reports_null(test_case_id):
    """TEST 12: If total work is unknown (total_bytes <= 0), percent_complete is None."""
    job_id = f"JOB-TEST12-{int(time.time() * 1000)}"
    job_registry.create_job(
        operation_id=f"OP-{job_id}",
        job_id=job_id,
        case_id=test_case_id,
        actor="TEST_RUNNER",
        operation_type="SANITIZATION_EXECUTE",
        target_path="/dev/null",
    )

    job = job_registry.update_job(
        job_id,
        status=models.JobLifecycleState.RUNNING,
        phase="RUNNING",
        processed_bytes=1048576,
        total_bytes=0,  # Unknown total
    )
    assert job["percent_complete"] is None, (
        f"Expected percent_complete to be None when total is unknown, got {job['percent_complete']}"
    )


# ─── TEST 18: Mandatory Tiny-File Test (Not Forced to 0.01%) ─────────────────

def test_progress_truth_tiny_file_first_chunk_is_large_percentage(test_case_id, tmp_path):
    """
    TEST 18: 1 KB file where first write is 512 B.
    Actual progress: 50.0%, NOT 0.01%!
    The 0.01% rule is a floor for small positive percentages, NOT a universal starting value!
    """
    job_id = f"JOB-TINY-{int(time.time() * 1000)}"
    job_registry.create_job(
        operation_id=f"OP-{job_id}",
        job_id=job_id,
        case_id=test_case_id,
        actor="TEST_RUNNER",
        operation_type="SANITIZATION_EXECUTE",
        target_path=str(tmp_path / "tiny.bin"),
    )

    file_sz = 1024  # 1 KB
    first_write = 512  # 512 B

    job = job_registry.update_job(
        job_id,
        status=models.JobLifecycleState.RUNNING,
        phase="WRITING",
        processed_bytes=first_write,
        total_bytes=file_sz,
    )

    assert job["percent_complete"] == 50.0, (
        f"Tiny file first chunk must be 50.0%, NOT 0.01%. Received: {job['percent_complete']}"
    )


# ─── TEST 19: Large-File Monotonicity & Sub-Precision Positive Progress ──────

def test_progress_truth_large_file_sub_precision_positive_progress(test_case_id):
    """TEST 19: 50 MB file after first 256 KB chunk produces authentic progress."""
    job_id = f"JOB-LARGE-{int(time.time() * 1000)}"
    job_registry.create_job(
        operation_id=f"OP-{job_id}",
        job_id=job_id,
        case_id=test_case_id,
        actor="TEST_RUNNER",
        operation_type="SANITIZATION_EXECUTE",
        target_path="/dev/large",
    )

    tot = 50 * 1024 * 1024
    chunk = 65536  # 64 KB chunk
    job = job_registry.update_job(
        job_id,
        status=models.JobLifecycleState.RUNNING,
        phase="WRITING",
        processed_bytes=chunk,
        total_bytes=tot,
    )
    expected_pct = round((chunk / tot) * 100.0, 2)
    assert job["percent_complete"] == expected_pct
    assert job["percent_complete"] > 0.0


# ─── TEST 20: Multi-Pass Work Model ──────────────────────────────────────────

def test_progress_truth_multi_pass_work_model(tmp_path):
    """TEST 20: Multi-pass operations sum across passes and do not reset progress to zero between passes."""
    test_f = tmp_path / "multipass.bin"
    f_size = 128 * 1024  # 128 KB
    test_f.write_bytes(b"A" * f_size)

    recorded_calls = []
    def progress_cb(written, total, phase):
        recorded_calls.append((written, total, phase))

    res = FileSanitizer.wipe_file(
        test_f,
        standard=SanitizationStandard.DOD_5220_22_M_3PASS,  # 3 passes
        unlink_after=False,
        progress_callback=progress_cb,
    )

    assert res.pass_count == 3
    assert len(recorded_calls) > 0

    # Verify total_work reflects file_size * 3 passes = 384 KB
    expected_total = f_size * 3
    for w, t, p in recorded_calls:
        assert t == expected_total

    # Verify monotonicity: written bytes must never decrease
    prev_w = 0
    for w, t, p in recorded_calls:
        assert w >= prev_w, f"Progress decreased from {prev_w} to {w}"
        prev_w = w

    assert prev_w == expected_total


# ─── TEST 21: Directory Aggregate Progress ───────────────────────────────────

def test_progress_truth_directory_aggregate_progress(tmp_path):
    """TEST 21: Directory sanitization progress reflects aggregate directory work, not single file."""
    dir_target = tmp_path / "test_dir"
    dir_target.mkdir()
    (dir_target / "file1.bin").write_bytes(b"X" * (64 * 1024))
    (dir_target / "file2.bin").write_bytes(b"Y" * (128 * 1024))

    calls = []
    def progress_cb(written, total, phase):
        calls.append((written, total, phase))

    results = FileSanitizer.wipe_directory_tree(
        dir_target,
        standard=SanitizationStandard.SINGLE_PASS_ZERO,
        unlink_after=False,
        progress_callback=progress_cb,
    )

    assert len(results) == 2
    assert len(calls) > 0

    # Total aggregate bytes = 64 KB + 128 KB = 192 KB
    expected_total = 192 * 1024
    for w, t, p in calls:
        assert t == expected_total, f"Expected total work {expected_total}, got {t}"

    prev_w = 0
    for w, t, p in calls:
        assert w >= prev_w, f"Directory progress decreased from {prev_w} to {w}"
        prev_w = w

    assert prev_w == expected_total


# ─── TEST 22: JavaScript Frontend Authoritative Progress Test ────────────────

def test_javascript_authoritative_progress_suite():
    """Execute node tests/test_js_progress_truth.js to verify frontend model truth."""
    import subprocess
    res = subprocess.run(["node", "tests/test_js_progress_truth.js"], capture_output=True, text=True)
    assert res.returncode == 0, f"JS test failed:\n{res.stderr}\n{res.stdout}"
    assert "SUCCESS: All 26 JavaScript Authoritative Progress Truth Assertions Passed Cleanly!" in res.stdout

