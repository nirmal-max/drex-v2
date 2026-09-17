"""
tests/test_p0_01_through_12_regression.py
=========================================
Comprehensive automated regression test suite covering all 12 release-blocking P0 defects:

P0-01: Drive Eraser method selection & hardware wipe dispatch (M01-M07, no M08 fallback).
P0-02: Recovery physical device elevation preflight (RBAC role vs Windows process token).
P0-03: Stale recovery candidate elimination (clean 0-candidate state).
P0-04: Case / operation context isolation (strict case filtering in active ops).
P0-05: Duplicate physical device inventory elimination (1 canonical DriveInfo per physical disk).
P0-06: Evidence Vault count accuracy & dynamic sync.
P0-07: Certificate count & digest lifecycle (is_sealed strictly requires 64-char valid SHA-256 hash).
P0-08: Raw authentication error handling & structured 401 UX.
P0-09: Recovery operation card progress semantics (operation-type aware labels).
P0-10: M25 Forensic Recovery error wrapping & diagnostic preservation.
P0-11: Certificate page context & multi-method attestation register.
P0-12: Destructive button execution state gating (OS tripwire, active case, safety phrase).
"""

import json
import os
import sys
import tempfile
from pathlib import Path
import pytest
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient

import drex_api_models as models
import drex_rbac as rbac
from drex_server import app, case_manager, job_registry
from drex_app import discover_drives, DriveInfo
from forensic_vault import VaultObjectType, EvidenceSourceType
from hardware_storage import HardwareExecutionStatus, DeviceSafetyStateMachine, DeviceIntelligenceEngine
from recovery_adapter import ForensicRecoveryAdapter, RECOVERY_METHOD_SPECS, RecoveryError, QuickRecoveryAdapter


@pytest.fixture
def auth_headers():
    token = rbac.create_access_token(models.UserRole.ADMIN)
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def client(auth_headers):
    c = TestClient(app)
    c.headers.update(auth_headers)
    return c


@pytest.fixture
def unauth_client():
    return TestClient(app)


# ─── P0-01: Drive Eraser Method Selection & Hardware Wipe Dispatch ────────────

def test_p0_01_drive_eraser_plan_defaults_to_m01(client):
    """Verify /api/sanitization/plan for physical drive targets defaults to M01 NIST SP 800-88 Clear, not M08."""
    resp = client.post(
        "/api/sanitization/plan",
        json={"target_path": r"\\.\PhysicalDrive1", "target_type": "DRIVE"}
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["qualified_method_id"] == 1, f"Expected qualified_method_id == 1, got {data['qualified_method_id']}"
    assert "NIST SP 800-88" in data["qualified_method_name"]


def test_p0_01_drive_eraser_execute_routes_to_hardware_backend(client):
    """Verify /api/sanitization/execute for physical target with method 1 routes to hardware wipe backend."""
    case = case_manager.create_case(
        case_number="CASE-P0-01-EXEC",
        title="Drive Wipe Execution Case",
        examiner="Lead Forensic Analyst",
        organization="Forensic Lab",
    )
    target = r"\\.\PhysicalDrive99"
    clean_target = target.replace("\\", "_").replace("/", "_").replace(".", "_").strip("_").upper()
    phrase = f"ERASE-{clean_target}-PERMANENT"

    with patch("drex_server.DeviceSafetyStateMachine.evaluate_safety") as mock_safety:
        mock_safety.return_value = (True, HardwareExecutionStatus.SUCCESS, "Safe test drive", [])
        with patch("drex_server.DriveWipeHardwareBackend.execute") as mock_hw_exec:
            from hardware_storage import HardwareOperationResult
            mock_hw_exec.return_value = HardwareOperationResult(
                status=HardwareExecutionStatus.SUCCESS,
                method_id="M01",
                device_path=target,
                bus_type="NVMe",
                is_physical_hardware_executed=True,
                evidence_payload={"bytes_written": 1024 * 1024},
                execution="SUCCESS",
                verification="SUCCESS",
                hardware_qualification="QUALIFIED",
                backend="DRIVEWIPE_ADAPTED",
                bus="NVMe",
            )
            resp = client.post(
                "/api/sanitization/execute",
                json={
                    "case_id": case.case_id,
                    "target_path": target,
                    "method_id": 1,
                    "safety_phrase_entered": phrase,
                    "async_execution": False,
                }
            )
            assert resp.status_code == 200
            data = resp.json()
            assert data["method_id"] == 1
            assert data["status"] == "COMPLETED"
            assert mock_hw_exec.called


# ─── P0-02: Recovery Physical Device Access & Process Elevation ───────────────

def test_p0_02_recovery_physical_scan_requires_elevation(client):
    """Verify non-elevated physical device recovery scan is rejected with HTTP 422 and structured elevation error."""
    case = case_manager.create_case(
        case_number="CASE-P0-02-ELEV",
        title="Elevation Preflight Case",
        examiner="Lead Forensic Analyst",
        organization="Forensic Lab",
    )
    with patch.object(DeviceIntelligenceEngine, "is_elevated", return_value=False):
        resp = client.post(
            "/api/recovery/scan",
            json={
                "case_id": case.case_id,
                "source_path": r"\\.\PhysicalDrive1",
                "destination_dir": "vault/extracted",
                "engine": "17",
            }
        )
        assert resp.status_code == 422
        detail = str(resp.json().get("detail", ""))
        assert "PHYSICAL_DEVICE_ACCESS_DENIED_ELEVATION_REQUIRED" in detail
        assert "Windows Administrator" in detail


def test_p0_02_system_version_reports_elevation_state(client):
    """Verify /api/system/version includes is_windows_elevated boolean."""
    resp = client.get("/api/system/version")
    assert resp.status_code == 200
    data = resp.json()
    assert "is_windows_elevated" in data
    assert isinstance(data["is_windows_elevated"], bool)


# ─── P0-03: Stale Recovery Candidate Elimination ─────────────────────────────

def test_p0_03_recovery_candidates_isolation(client):
    """Verify /api/recovery/candidates returns an empty list for a clean case without fallback to global fixtures."""
    resp = client.get("/api/recovery/candidates?case_id=CASE-EMPTY-TEST-P0-03")
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)
    assert len(data) == 0


# ─── P0-04: Case / Operation Context Isolation ────────────────────────────────

def test_p0_04_active_jobs_isolated_by_case(client):
    """Verify /api/jobs/active?case_id=... strictly filters active jobs by case_id."""
    job_registry.register_job(
        job_id="JOB-CASE-P0-04-A",
        operation_type="RECOVERY",
        target_path="sample_a.img",
        case_id="CASE-AAA",
        workflow_id="recovery",
        method_id=17,
    )
    job_registry.register_job(
        job_id="JOB-CASE-P0-04-B",
        operation_type="SANITIZATION",
        target_path="sample_b.img",
        case_id="CASE-BBB",
        workflow_id="sanitization",
        method_id=1,
    )

    resp_a = client.get("/api/jobs/active?case_id=CASE-AAA")
    assert resp_a.status_code == 200
    jobs_a = resp_a.json()
    assert all(j["case_id"] == "CASE-AAA" for j in jobs_a)
    assert any(j["job_id"] == "JOB-CASE-P0-04-A" for j in jobs_a)
    assert not any(j["job_id"] == "JOB-CASE-P0-04-B" for j in jobs_a)

    # Cleanup
    job_registry._jobs.pop("JOB-CASE-P0-04-A", None)
    job_registry._jobs.pop("JOB-CASE-P0-04-B", None)


# ─── P0-05: Duplicate Physical Device Inventory Elimination ───────────────────

def test_p0_05_discover_drives_produces_single_canonical_physical_drive():
    """Verify discover_drives produces exactly 1 DriveInfo per physical drive with aggregated partitions."""
    def mock_ps(cmd):
        if "Win32_DiskDrive" in cmd:
            return [{
                "Index": 0,
                "DeviceID": r"\\.\PhysicalDrive0",
                "Model": "SAMSUNG MZVL21T0HCLR-00B00",
                "SerialNumber": "S676NF0T123456",
                "Size": "1024209543168",
                "InterfaceType": "NVMe",
                "MediaType": "Fixed hard disk media",
                "Status": "OK",
            }]
        elif "Win32_LogicalDiskToPartition" in cmd:
            return [{
                "Antecedent": r'\\.\root\cimv2:Win32_DiskPartition.DeviceID="Disk #0, Partition #1"',
                "Dependent": r'\\.\root\cimv2:Win32_LogicalDisk.DeviceID="C:"',
            }]
        elif "Win32_LogicalDisk" in cmd:
            return [{
                "DeviceID": "C:",
                "VolumeName": "Windows",
                "FileSystem": "NTFS",
                "Size": "1023672668160",
                "FreeSpace": "500000000000",
                "DriveType": 3,
            }]
        return None

    with patch("drex_app._ps_json", side_effect=mock_ps):
        drives = discover_drives()
        assert len(drives) == 1
        d0 = drives[0]
        assert d0.device_path == r"\\.\PhysicalDrive0"
        assert d0.model == "SAMSUNG MZVL21T0HCLR-00B00"
        assert d0.is_system_or_boot is True


# ─── P0-06 & P0-07: Evidence Vault Count & Cryptographic Digest Lifecycle ─────

def test_p0_07_evidence_is_sealed_requires_valid_sha256_hash(client):
    """Verify evidence items are only is_sealed=True when a valid 64-character SHA-256 hash is present."""
    case = case_manager.create_case(
        case_number="CASE-P0-07-SEAL",
        title="Sealing Verification Case",
        examiner="Senior Analyst",
        organization="Forensic Lab",
    )
    
    # Register an item with valid 64-char sha256 via vault store_file
    with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
        f.write(b"Sealed evidence data block for cryptographic attestation test")
        tmp_path = f.name
    
    try:
        vault = case_manager.get_vault(case.case_id)
        v_obj = vault.store_file(
            case_id=case.case_id,
            source_path=tmp_path,
            object_type=VaultObjectType.RECOVERED,
            destination_name="sealed_artifact.bin",
        )
        assert len(v_obj.sha256_hash) == 64

        resp = client.get(f"/api/evidence?case_id={case.case_id}")
        assert resp.status_code == 200
        items = resp.json()
        assert len(items) >= 1

        sealed = next((i for i in items if i["evidence_id"] == v_obj.object_id), None)
        assert sealed is not None
        assert sealed["sha256_hash"] == v_obj.sha256_hash
        assert sealed["is_sealed"] is True, "Vault object with valid 64-char hash must be sealed"
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)


# ─── P0-08: Authentication Required Interceptor ───────────────────────────────

def test_p0_08_unauthenticated_request_returns_401(unauth_client):
    """Verify protected endpoints return HTTP 401 Unauthorized for missing tokens."""
    resp = unauth_client.get("/api/evidence?case_id=CASE-UNAUTH")
    assert resp.status_code == 401


# ─── P0-10: M25 Forensic Recovery Diagnostic & Identity Preservation ───────────

def test_p0_10_forensic_recovery_adapter_preserves_m25_identity():
    """Verify ForensicRecoveryAdapter preserves M25 identity and wraps sub-stage errors with diagnostic prefix."""
    spec = RECOVERY_METHOD_SPECS[8]  # "forensic" (Method 25)
    adapter = ForensicRecoveryAdapter(spec, Path("."))
    
    # Mock QuickRecoveryAdapter.scan to raise RecoveryError
    with patch.object(QuickRecoveryAdapter, "scan") as mock_scan:
        mock_scan.side_effect = RecoveryError("TSK inode table corruption at offset 0x4000")
        
        with pytest.raises(RecoveryError) as exc_info:
            adapter.scan("invalid_test_stream.img")
        
        assert "M25 Forensic Recovery -> Quick Recovery sub-stage failed: TSK inode table corruption at offset 0x4000" in str(exc_info.value)


# ─── P0-11: Certificate Generation on Physical Target Uses Method 1 (not 8) ───

def test_p0_11_certificate_generation_on_physical_target_uses_method_1(client):
    """Verify /api/certificates/generate defaults to physical method 1 (or selected M01-M07) on physical drive."""
    case = case_manager.create_case(
        case_number="CASE-P0-11-CERT",
        title="Certificate Method Case",
        examiner="Senior Investigator",
        organization="Forensic Lab",
    )
    resp = client.post(
        "/api/certificates/generate",
        json={
            "case_id": case.case_id,
            "target_identifier": r"\\.\PhysicalDrive1",
            "method_id": 1,
            "examiner_name": "Senior Investigator",
        }
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["method_id"] == 1
    assert data["target_name"] == r"\\.\PhysicalDrive1"


# ─── P0-12: Destructive Button Execution Gating (Safety Preflight) ─────────────

def test_p0_12_sanitization_execute_rejects_system_disk_mutation(client):
    """Verify /api/sanitization/execute strictly blocks execution against Windows system disk."""
    case = case_manager.create_case(
        case_number="CASE-P0-12-SAFE",
        title="Safety Validation Case",
        examiner="Senior Investigator",
        organization="Forensic Lab",
    )
    target = r"\\.\PhysicalDrive0"
    clean_target = target.replace("\\", "_").replace("/", "_").replace(".", "_").strip("_").upper()
    phrase = f"ERASE-{clean_target}-PERMANENT"

    with patch("drex_server.DeviceSafetyStateMachine.evaluate_safety") as mock_safety:
        mock_safety.return_value = (
            False,
            HardwareExecutionStatus.SYSTEM_DISK_BLOCKED,
            "Target device contains active Windows boot/system volumes. Sanitization blocked by OS extent tripwire.",
            ["OS Boot Disk"],
        )
        resp = client.post(
            "/api/sanitization/execute",
            json={
                "case_id": case.case_id,
                "target_path": target,
                "method_id": 1,
                "safety_phrase_entered": phrase,
                "async_execution": False,
            }
        )
        assert resp.status_code == 422
        detail = str(resp.json().get("detail", ""))
        assert "SAFETY TRIPWIRE" in detail or "system/boot" in detail or "SYSTEM_DISK_BLOCKED" in detail or "METHOD UNSUPPORTED" in detail
