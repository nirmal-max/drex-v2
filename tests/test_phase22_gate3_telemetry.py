import os
import time
import pytest
from pathlib import Path
from starlette.testclient import TestClient

from drex_server import app, job_registry, case_manager, inspect_target_metadata

import drex_rbac as rbac
import drex_api_models as models

@pytest.fixture
def client():
    token = rbac.create_access_token(models.UserRole.ADMIN, username="admin_phase22")
    c = TestClient(app)
    c.headers["Authorization"] = f"Bearer {token}"
    return c

@pytest.fixture
def test_case_id():
    case = case_manager.create_case(
        case_number="CASE-P22-TELEMETRY-01",
        title="Phase 22 Telemetry & Cancellation Verification",
        examiner="Lead Forensic Architect",
        organization="DREX Forensics Lab",
    )
    return case.case_id

def test_sanitization_async_execution_and_telemetry(client, test_case_id, tmp_path):
    target_file = tmp_path / "async_wipe_target.bin"
    target_file.write_bytes(os.urandom(1024 * 1024))  # 1 MB test file

    meta = inspect_target_metadata(str(target_file))
    pre_hash = meta["preflight_hash"]

    clean_target = str(target_file).replace("\\", "_").replace("/", "_").replace(".", "_").strip("_").upper()
    phrase = f"ERASE-{clean_target}-PERMANENT"

    # 1. Dispatch asynchronous sanitization execution
    res = client.post(
        "/api/sanitization/execute",
        json={
            "case_id": test_case_id,
            "target_path": str(target_file),
            "method_id": 8,  # CSPRNG
            "safety_phrase_entered": phrase,
            "preflight_identity": pre_hash,
            "async_execution": True,
        }
    )
    assert res.status_code == 200, res.text
    data = res.json()
    assert data["status"] == "QUEUED"
    assert data["phase"] == "QUEUED"
    assert data["async_execution"] is True
    job_id = data["job_id"]

    # 2. Poll job status until terminal state
    max_wait = 10.0
    start = time.time()
    terminal_reached = False
    observed_phases = set()

    while time.time() - start < max_wait:
        status_res = client.get(f"/api/jobs/{job_id}?case_id={test_case_id}")
        assert status_res.status_code == 200
        job_data = status_res.json()
        observed_phases.add(job_data.get("phase"))

        if job_data["status"] in ("COMPLETED", "FAILED", "CANCELLED"):
            terminal_reached = True
            break
        time.sleep(0.05)

    assert terminal_reached is True, f"Job did not terminate within {max_wait}s. Last state: {job_data}"
    assert job_data["status"] == "COMPLETED"
    assert job_data["phase"] == "VERIFIED"
    assert job_data["verification_state"] == "VERIFIED"
    assert job_data["processed_bytes"] == 1024 * 1024
    assert job_data["total_bytes"] == 1024 * 1024
    assert job_data["percent_complete"] == 100.0
    assert job_data["details"]["bytes_written"] == 1024 * 1024
    assert job_data["details"]["readback_mismatches"] == 0

    # Verify active jobs endpoint filters cleanly
    active_res = client.get(f"/api/jobs/active?case_id={test_case_id}")
    assert active_res.status_code == 200
    active_list = active_res.json()
    assert all(j["job_id"] != job_id for j in active_list), "Completed job should not remain in active jobs list"


def test_sanitization_cooperative_cancellation(client, test_case_id, tmp_path):
    target_file = tmp_path / "cancel_target.bin"
    target_file.write_bytes(os.urandom(2 * 1024 * 1024))  # 2 MB test file

    meta = inspect_target_metadata(str(target_file))
    pre_hash = meta["preflight_hash"]

    clean_target = str(target_file).replace("\\", "_").replace("/", "_").replace(".", "_").strip("_").upper()
    phrase = f"ERASE-{clean_target}-PERMANENT"

    # Launch async execution
    res = client.post(
        "/api/sanitization/execute",
        json={
            "case_id": test_case_id,
            "target_path": str(target_file),
            "method_id": 8,
            "safety_phrase_entered": phrase,
            "preflight_identity": pre_hash,
            "async_execution": True,
        }
    )
    assert res.status_code == 200
    job_id = res.json()["job_id"]

    # Request cancellation immediately
    cancel_res = client.post(f"/api/jobs/{job_id}/cancel?case_id={test_case_id}")
    assert cancel_res.status_code == 200
    cancel_data = cancel_res.json()
    assert cancel_data["cancellation_requested"] is True

    # Wait for job to reflect cancellation
    max_wait = 5.0
    start = time.time()
    cancelled = False
    while time.time() - start < max_wait:
        status_res = client.get(f"/api/jobs/{job_id}?case_id={test_case_id}")
        assert status_res.status_code == 200
        job_data = status_res.json()
        if job_data["status"] == "CANCELLED":
            cancelled = True
            break
        time.sleep(0.05)

    assert cancelled is True, f"Job was not cancelled. Status: {job_data.get('status')}"
    assert job_data["verification_state"] == "UNVERIFIED"
    assert job_data["phase"] == "CANCELLED"
    # Verify target lock was released
    lock_released = False
    for _ in range(20):
        if not job_registry.is_target_locked(str(target_file)):
            lock_released = True
            break
        time.sleep(0.05)
    assert lock_released is True, "Target lock should be released after cancellation"
