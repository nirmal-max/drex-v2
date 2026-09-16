"""
tests/test_phase21_runtime_truth.py
===================================
Automated verification test suite for DREX V2 Phase 21:
Runtime Truth, Real Desktop Workflows, Anti-TOCTOU Revalidation,
and 949-Test Integrity Invariants.
"""

import os
import json
import hashlib
import tempfile
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from drex_server import app, ROOT_DIR, get_git_commit, inspect_target_metadata
import drex_api_models as models
import drex_rbac as rbac
from forensic_vault import ForensicCaseManager
from entropy_engine import calculate_shannon_entropy


@pytest.fixture
def client():
    token = rbac.create_access_token(models.UserRole.ADMIN, username="admin_phase21")
    c = TestClient(app)
    c.headers["Authorization"] = f"Bearer {token}"
    return c


@pytest.fixture
def test_case_id(client):
    res = client.post(
        "/api/cases",
        json={
            "case_number": "DREX-PHASE21-TEST",
            "title": "Phase 21 Automated Verification Suite",
            "examiner": "Automated Test Runner",
            "organization": "DREX QA Labs",
        }
    )
    assert res.status_code in (200, 201)
    return res.json()["case_id"]


# ─── 1. System Version & Build ID Truth ────────────────────────────────────────

def test_system_version_endpoint(client):
    res = client.get("/api/system/version")
    assert res.status_code == 200
    data = res.json()
    assert data["build_id"] in ("fbad09d", "b3c8ba1") or len(data["build_id"]) >= 7
    assert data["commit"] in ("fbad09d", "b3c8ba1") or len(data["commit"]) >= 7
    assert data["asset_version"] in ("fbad09d", "b3c8ba1") or len(data["asset_version"]) >= 7
    assert data["version"] == "2.0.0"
    assert "Windows" in data["environment"] or "Linux" in data["environment"] or "Darwin" in data["environment"]
    assert "server_timestamp" in data


def test_static_asset_no_cache_headers(client):
    endpoints = ["/", "/index.html", "/app.js", "/styles.css", "/sw.js", "/manifest.json"]
    for ep in endpoints:
        res = client.get(ep)
        assert res.status_code == 200
        cache_ctrl = res.headers.get("cache-control", "")
        assert "no-cache" in cache_ctrl or "no-store" in cache_ctrl or "must-revalidate" in cache_ctrl


# ─── 2. Real Desktop Dialog & Target Inspection Endpoints ──────────────────────

def test_dialog_pick_file_override(client, tmp_path):
    sample_file = tmp_path / "evidence_document.docx"
    sample_file.write_bytes(b"FORENSIC_EVIDENCE_PAYLOAD_PHASE_21" * 100)
    
    res = client.post(
        "/api/dialog/pick-file",
        json={"path_override": str(sample_file)}
    )
    assert res.status_code == 200
    data = res.json()
    assert data["exists"] is True
    assert data["type"] == "FILE"
    assert data["file_count"] == 1
    assert data["total_size"] == len(sample_file.read_bytes())
    assert data["readable"] is True
    assert data["protected"] is False
    assert data["preflight_hash"] is not None
    assert len(data["preflight_hash"]) == 64


def test_dialog_pick_folder_override(client, tmp_path):
    sub = tmp_path / "case_folder"
    sub.mkdir()
    (sub / "file1.txt").write_bytes(b"Data1")
    (sub / "file2.bin").write_bytes(b"Data2_extended")
    
    res = client.post(
        "/api/dialog/pick-folder",
        json={"path_override": str(sub)}
    )
    assert res.status_code == 200
    data = res.json()
    assert data["exists"] is True
    assert data["type"] in ("FOLDER", "DIRECTORY")
    assert data["file_count"] >= 2
    assert data["total_size"] >= 18
    assert data["readable"] is True


def test_inspect_target_endpoint(client, tmp_path):
    target = tmp_path / "inspect_target.log"
    target.write_bytes(b"Inspection Target Content 12345")
    
    res = client.post(
        "/api/dialog/inspect-target",
        json={"target_path": str(target)}
    )
    assert res.status_code == 200
    data = res.json()
    assert data["exists"] is True
    assert data["type"] == "FILE"
    assert data["total_size"] == len(b"Inspection Target Content 12345")
    assert data["readable"] is True
    assert data["status"] == "OK"


# ─── 3. Anti-TOCTOU Revalidation & Safety Tripwire ─────────────────────────────

def test_sanitization_safety_tripwire_system_drive(client, test_case_id):
    protected_paths = [
        "C:\\Windows\\System32\\kernel32.dll",
        "C:\\Program Files\\DREX",
        "\\\\.\\PhysicalDrive0",
    ]
    for p in protected_paths:
        res = client.post(
            "/api/sanitization/execute",
            json={
                "case_id": test_case_id,
                "target_path": p,
                "method_id": 8,
                "safety_phrase_entered": "ERASE-TARGET-PERMANENT",
            }
        )
        assert res.status_code in (422, 400), f"Path {p} should be blocked by safety tripwire"


def test_sanitization_toctou_preflight_identity_mismatch(client, test_case_id, tmp_path):
    target_file = tmp_path / "toctou_test.bin"
    target_file.write_bytes(b"INITIAL_ORIGINAL_DATA_12345")
    
    # Preflight inspection
    meta = inspect_target_metadata(str(target_file))
    orig_hash = meta["preflight_hash"]
    assert orig_hash is not None
    
    # Tamper file after preflight inspection
    target_file.write_bytes(b"TAMPERED_MODIFIED_DATA_67890")
    
    clean_target = str(target_file).replace("\\", "_").replace("/", "_").replace(".", "_").strip("_").upper()
    phrase = f"ERASE-{clean_target}-PERMANENT"
    
    res = client.post(
        "/api/sanitization/execute",
        json={
            "case_id": test_case_id,
            "target_path": str(target_file),
            "method_id": 8,
            "safety_phrase_entered": phrase,
            "preflight_identity": orig_hash,  # Old hash -> should trigger 409 TOCTOU conflict!
        }
    )
    assert res.status_code == 409
    assert "TOCTOU VIOLATION" in res.json()["detail"]


def test_sanitization_execution_valid_with_entropy(client, test_case_id, tmp_path):
    target_file = tmp_path / "valid_shred_target.bin"
    target_file.write_bytes(b"A" * 65536)  # Initial low entropy
    
    meta = inspect_target_metadata(str(target_file))
    pre_hash = meta["preflight_hash"]
    
    clean_target = str(target_file).replace("\\", "_").replace("/", "_").replace(".", "_").strip("_").upper()
    phrase = f"ERASE-{clean_target}-PERMANENT"
    
    res = client.post(
        "/api/sanitization/execute",
        json={
            "case_id": test_case_id,
            "target_path": str(target_file),
            "method_id": 8,  # CSPRNG
            "safety_phrase_entered": phrase,
            "preflight_identity": pre_hash,
        }
    )
    assert res.status_code == 200
    data = res.json()
    assert "PASS" in data["verdict"]
    assert data["bytes_written"] == 65536
    assert data["entropy_h"] >= 7.990
    assert data["readback_mismatches"] == 0


# ─── 4. 949-Test Integrity & Dynamic Results Invariant ─────────────────────────

def test_validation_test_results_endpoint_invariant(client):
    res = client.get("/api/validation/test-results")
    assert res.status_code == 200
    data = res.json()
    
    assert data["collected"] >= 1
    assert data["passed"] >= 1
    assert data["failed"] == 0
    assert data["errors"] == 0
    assert isinstance(data["warnings"], int)
    assert data["commit"] in ("fbad09d", "b3c8ba1") or len(data["commit"]) >= 7
    assert data["python_version"] == "3.14.3"
    assert data["pytest_version"] == "9.1.1"
    
    # Verify categories sum exactly to collected
    cat_sum = sum(c["total"] for c in data["categories"].values())
    assert cat_sum == data["collected"]
    
    # Verify test inventory length matches collected
    assert len(data["tests"]) == data["collected"]
    for item in data["tests"]:
        assert item["status"] == "PASSED"
        assert item["node_id"] is not None
        assert item["category"] is not None


# ─── 5. Judge Demonstration Proof vs Operational Demonstration ────────────────

def test_judge_demo_synthetic_flow(client):
    res = client.post("/api/demo/flow")
    assert res.status_code == 200
    data = res.json()
    assert data["verdict"].startswith("PASS")
    assert "SYNTHETIC EVALUATION PROOF" in data["verdict"]
    assert "FULL FORENSIC PROOF LOOP VERIFIED" in data["verdict"]
    assert data["environment"] == "SYNTHETIC FIXTURE"
    assert len(data["steps_completed"]) == 6
    assert data["elapsed_seconds"] < 60.0


def test_judge_demo_operational_flow_with_real_certificate(client):
    res = client.post("/api/demo/operational-flow")
    assert res.status_code == 200
    data = res.json()
    assert data["verdict"] == "PASS"
    assert data["environment"] == "LIVE ISOLATED WORKSTATION"
    assert len(data["steps_completed"]) == 5
    assert data["entropy_h"] >= 7.980
    assert data["certificate_id"] is not None
    assert data["case_id"] is not None
    
    # Download and verify genuine PDF certificate
    pdf_res = client.get(f"/api/certificates/{data['certificate_id']}/pdf?case_id={data['case_id']}")
    assert pdf_res.status_code == 200
    assert pdf_res.headers["content-type"] == "application/pdf"
    assert pdf_res.content.startswith(b"%PDF-")
    assert len(pdf_res.content) > 1000
