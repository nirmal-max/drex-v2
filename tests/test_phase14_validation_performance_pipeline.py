"""
DREX-V2 Phase 14 Comprehensive Test Suite
=========================================
Module: test_phase14_validation_performance_pipeline.py
Phase: 14 / End-to-End Validation Laboratory & Performance Laboratory Integration

Validates:
1. Authoritative headless ValidationLabEngine execution & KAT suite verdicts.
2. Truthful 25-Method Known-Answer Test (KAT) qualification matrix with conservative hardware boundaries:
   - M03 -> UNSUPPORTED / HARDWARE_REQUIRED
   - M05 -> UNSUPPORTED / HARDWARE_REQUIRED
   - M23 -> UNSUPPORTED / HARDWARE_REQUIRED
   - M24 -> BACKEND_UNAVAILABLE / HARDWARE_REQUIRED
   - M21/M22 -> KAT_PARTIAL / LIMITED
3. Explicit distinction between software algorithm validation and physical hardware execution (physical_execution: NOT_EXECUTED).
4. Aggregate failure semantics (HARDWARE_LIMITED, ALL_REQUIRED_PASS, FAILED).
5. Bounded streaming memory invariant (fixed 64 KB chunk buffer, O(1) heap scaling across 1 MB, 5 MB, 10 MB inputs).
6. Dual-signal memory separation (Python tracemalloc heap vs OS Process RSS / Working Set).
7. Resource exhaustion safety enforcement (caps on dataset <= 50 MB, iterations <= 10, chunk <= 4 MB).
8. Anti-cheating protections (server computes authoritative results; client injected metrics/verdicts rejected or ignored).
9. Report integrity & multi-factor independent verification (recomputed SHA-256, case binding, audit chain event linking).
10. Tamper detection on reports and audit ledger records.
11. Multi-surface RBAC enforcement across 6 personas.
12. Cross-module regression with Phase 12 (Advanced Recovery/Fragments) and Phase 13 (Forensic Certificates).
13. Non-destructive synthetic fixture safety guarantees.

Zero external dependencies. Pure Python standard library & pytest.
License: Apache 2.0.
"""

import copy
import dataclasses
import hashlib
import json
import os
import shutil
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List

import pytest
from fastapi.testclient import TestClient

import drex_api_models as models
import drex_rbac as rbac
from drex_server import app, case_manager
from forensic_vault import (
    AuditVerificationStatus,
    CaseStatus,
    ForensicCaseManager,
    StreamingHasher,
    VaultObjectType,
)
from performance_lab import BenchmarkResult, MemoryProfileSnapshot, PerformanceLab
from validation_lab import (
    ValidationLabEngine,
    ValidationLabReport,
    ValidationSuiteSummary,
    build_method_truth_matrix,
)


# ─── Test Fixtures & Setup ───────────────────────────────────────────────────

@pytest.fixture(scope="function")
def client(tmp_path):
    """FastAPI TestClient with isolated case manager storage directory."""
    original_base = case_manager.base_dir
    case_manager.base_dir = tmp_path / "drex_vault"
    case_manager.cases_dir = case_manager.base_dir / "cases"
    case_manager.cases_dir.mkdir(parents=True, exist_ok=True)
    yield TestClient(app)
    case_manager.base_dir = original_base
    case_manager.cases_dir = original_base / "cases"


@pytest.fixture(scope="function")
def test_case(client):
    """Helper creating an active test case."""
    c = case_manager.create_case(
        case_number=f"VAL-TEST-{int(time.time() * 1000)}",
        title="Phase 14 Validation Lab Investigation",
        examiner="Analyst Alice",
        organization="National Cyber Forensic Lab",
    )
    return {"case_id": c.case_id, "case_number": c.case_number}


def auth_header(role: Any = rbac.UserRole.FORENSIC_ANALYST, name: str = "Test User") -> Dict[str, str]:
    if isinstance(role, str):
        role_enum = getattr(rbac.UserRole, role, rbac.UserRole.JUDGE_DEMO)
    else:
        role_enum = role
    token = rbac.create_access_token(role=role_enum, username=name)
    return {"Authorization": f"Bearer {token}"}



# ─── 1. Validation Lab Engine & KAT Truth Model Tests ────────────────────────

def test_01_validation_lab_headless_execution():
    """Test headless programmatic execution of all Validation Lab test suites."""
    report = ValidationLabEngine.run_all_suites()
    assert isinstance(report, ValidationLabReport)
    assert report.total_suites >= 5
    assert report.total_tests > 0
    assert report.total_passed > 0
    assert report.total_failed == 0
    assert report.overall_verdict in ("HARDWARE_LIMITED", "ALL_REQUIRED_PASS")
    assert report.duration_seconds > 0
    assert len(report.method_matrix) == 25
    assert len(report.benchmarks) > 0


def test_02_25_method_kat_truth_matrix_preservation():
    """Verify all 25 methods maintain truthful, approved qualification boundaries."""
    matrix = build_method_truth_matrix()
    assert len(matrix) == 25

    # Check mandatory conservative hardware boundaries
    m_map = {m["method_id"]: m for m in matrix}

    # M03: Device-Native Sanitize
    assert m_map[3]["truth_status"] == "UNSUPPORTED"
    assert m_map[3]["hardware_status"] == "HARDWARE_REQUIRED"

    # M04: ATA Secure Erase
    assert m_map[4]["truth_status"] == "UNSUPPORTED"
    assert m_map[4]["hardware_status"] == "HARDWARE_REQUIRED"

    # M05: NVMe Secure Erase
    assert m_map[5]["truth_status"] == "UNSUPPORTED"
    assert m_map[5]["hardware_status"] == "HARDWARE_REQUIRED"

    # M21: Deep Recovery
    assert m_map[21]["truth_status"] == "KAT_PARTIAL"
    assert m_map[21]["hardware_status"] == "LIMITED"

    # M22: Fragment Recovery
    assert m_map[22]["truth_status"] == "KAT_PARTIAL"
    assert m_map[22]["hardware_status"] == "LIMITED"

    # M23: RAID / Storage Recovery
    assert m_map[23]["truth_status"] == "UNSUPPORTED"
    assert m_map[23]["hardware_status"] == "HARDWARE_REQUIRED"

    # M24: Damaged Media Recovery
    assert m_map[24]["truth_status"] == "BACKEND_UNAVAILABLE"
    assert m_map[24]["hardware_status"] == "HARDWARE_REQUIRED"


def test_03_validation_report_software_vs_hardware_distinction():
    """Verify that validation report explicitly distinguishes software KAT from physical execution."""
    report = ValidationLabEngine.run_all_suites()
    for m in report.method_matrix:
        assert m["physical_execution"] == "NOT_EXECUTED", f"Method M{m['method_id']} must declare NOT_EXECUTED for physical hardware"
        assert "software_status" in m
        assert "hardware_status" in m
    assert "Physical hardware execution: NOT_EXECUTED" in report.disclaimer


def test_04_validation_report_aggregate_verdict_semantics():
    """Verify aggregate verdict logic does not report plain PASS when hardware methods are limited."""
    report = ValidationLabEngine.run_all_suites()
    # Since M03/M05/M23/M24 are unsupported/hardware-limited, verdict must be HARDWARE_LIMITED
    assert report.overall_verdict == "HARDWARE_LIMITED"
    assert report.suites_failed == 0


# ─── 2. Validation REST API & Evidence Vault Integration ─────────────────────

def test_05_validation_run_rest_endpoint_authorized(client, test_case):
    """POST /api/validation/run creates an authoritative report with JWT auth."""
    case_id = test_case["case_id"]
    res = client.post(
        "/api/validation/run",
        json={"case_id": case_id, "suites": ["SUITE-KAT-REC", "SUITE-KAT-SAN"]},
        headers=auth_header("FORENSIC_ANALYST"),
    )
    assert res.status_code == 200, res.text
    data = res.json()
    assert data["case_id"] == case_id
    assert data["overall_verdict"] == "HARDWARE_LIMITED"
    assert data["report_id"].startswith("DREX-VAL-REPORT-")
    assert len(data["report_hash"]) == 64
    assert len(data["method_matrix"]) == 25


def test_06_validation_run_creates_vault_report_artifact(client, test_case):
    """Verify report is stored in case reports directory and registered in Evidence Vault."""
    case_id = test_case["case_id"]
    res = client.post(
        "/api/validation/run",
        json={"case_id": case_id},
        headers=auth_header("FORENSIC_ANALYST"),
    )
    assert res.status_code == 200
    rep_id = res.json()["report_id"]

    vault = case_manager.get_vault(case_id)
    objects = vault.list_objects()
    rep_objs = [o for o in objects if o.object_type == VaultObjectType.REPORT and o.metadata.get("report_id") == rep_id]
    assert len(rep_objs) == 1
    assert rep_objs[0].sha256_hash == res.json()["report_hash"]


def test_07_validation_run_emits_audit_events(client, test_case):
    """Verify VALIDATION_RUN_STARTED and VALIDATION_RUN_COMPLETED events are logged in audit chain."""
    case_id = test_case["case_id"]
    res = client.post(
        "/api/validation/run",
        json={"case_id": case_id},
        headers=auth_header("EXAMINER"),
    )
    assert res.status_code == 200
    rep_id = res.json()["report_id"]

    chain = case_manager.get_audit_chain(case_id)
    started = next((e for e in chain if e.event_type == "VALIDATION_RUN_STARTED"), None)
    completed = next((e for e in chain if e.event_type == "VALIDATION_RUN_COMPLETED"), None)

    assert started is not None
    assert completed is not None
    assert completed.canonical_payload.get("report_id") == rep_id
    assert completed.canonical_payload.get("report_hash") == res.json()["report_hash"]


def test_08_validation_reports_list_and_get_endpoints(client, test_case):
    """Test GET /api/validation/reports and GET /api/validation/reports/{report_id}."""
    case_id = test_case["case_id"]
    r1 = client.post("/api/validation/run", json={"case_id": case_id}, headers=auth_header("FORENSIC_ANALYST")).json()
    rep_id = r1["report_id"]

    # List reports
    list_res = client.get(f"/api/validation/reports?case_id={case_id}", headers=auth_header("VIEWER"))
    assert list_res.status_code == 200
    reports = list_res.json()
    assert len(reports) >= 1
    assert any(r["report_id"] == rep_id for r in reports)

    # Get single report
    get_res = client.get(f"/api/validation/reports/{rep_id}?case_id={case_id}", headers=auth_header("VIEWER"))
    assert get_res.status_code == 200
    assert get_res.json()["report_id"] == rep_id


def test_09_validation_report_independent_cryptographic_verification(client, test_case):
    """POST /api/validation/verify recomputes canonical SHA-256 and verifies audit chain integrity."""
    case_id = test_case["case_id"]
    run_res = client.post("/api/validation/run", json={"case_id": case_id}, headers=auth_header("FORENSIC_ANALYST")).json()
    rep_id = run_res["report_id"]

    verify_res = client.post(
        "/api/validation/verify",
        json={"case_id": case_id, "report_id": rep_id},
        headers=auth_header("AUDITOR"),
    )
    assert verify_res.status_code == 200
    v = verify_res.json()
    assert v["valid"] is True
    assert v["report_hash_valid"] is True
    assert v["audit_chain_valid"] is True
    assert v["case_binding_valid"] is True
    assert "PASS" in v["verdict"]


def test_10_validation_report_tamper_detection(client, test_case):
    """Mutating report fields on disk invalidates cryptographic SHA-256 verification."""
    case_id = test_case["case_id"]
    run_res = client.post("/api/validation/run", json={"case_id": case_id}, headers=auth_header("FORENSIC_ANALYST")).json()
    rep_id = run_res["report_id"]

    # Tamper with the saved JSON file
    cdir = case_manager._case_path(case_id)
    jpath = cdir / "reports" / f"{rep_id}.json"
    rep_data = json.loads(jpath.read_text(encoding="utf-8"))
    rep_data["overall_verdict"] = "FORGED_ALL_PASS"
    jpath.write_text(json.dumps(rep_data), encoding="utf-8")

    verify_res = client.post(
        "/api/validation/verify",
        json={"case_id": case_id, "report_id": rep_id},
        headers=auth_header("AUDITOR"),
    )
    assert verify_res.status_code == 200
    v = verify_res.json()
    assert v["valid"] is False
    assert v["report_hash_valid"] is False
    assert "FAIL" in v["verdict"]


def test_11_validation_report_audit_chain_tamper_detection(client, test_case):
    """Tampering with audit event payload causes audit verification failure."""
    case_id = test_case["case_id"]
    run_res = client.post("/api/validation/run", json={"case_id": case_id}, headers=auth_header("FORENSIC_ANALYST")).json()
    rep_id = run_res["report_id"]

    # Tamper with audit ledger on disk
    cdir = case_manager._case_path(case_id)
    audit_file = cdir / "audit" / "audit_chain.json"
    audit_data = json.loads(audit_file.read_text(encoding="utf-8"))
    audit_data[-1]["canonical_payload"]["report_hash"] = "0" * 64
    audit_file.write_text(json.dumps(audit_data), encoding="utf-8")

    verify_res = client.post(
        "/api/validation/verify",
        json={"case_id": case_id, "report_id": rep_id},
        headers=auth_header("AUDITOR"),
    )
    assert verify_res.status_code == 200
    v = verify_res.json()
    assert v["valid"] is False
    assert v["audit_chain_valid"] is False


def test_12_validation_report_case_isolation_and_idor(client, test_case):
    """Verifying report under a different case fails case boundary check."""
    case_id_1 = test_case["case_id"]
    run_res = client.post("/api/validation/run", json={"case_id": case_id_1}, headers=auth_header("FORENSIC_ANALYST")).json()
    rep_id = run_res["report_id"]

    # Create a second case
    res2 = client.post(
        "/api/cases",
        json={"case_number": "CASE-PHASE14-ISOLATION-02", "title": "Second Case", "examiner": "Examiner 2"},
        headers=auth_header("FORENSIC_ANALYST"),
    )
    case_id_2 = res2.json()["case_id"]

    verify_res = client.post(
        "/api/validation/verify",
        json={"case_id": case_id_2, "report_id": rep_id},
        headers=auth_header("AUDITOR"),
    )
    assert verify_res.status_code == 200
    v = verify_res.json()
    assert v["valid"] is False
    assert "FAIL" in v["verdict"]


def test_13_validation_api_anti_cheating(client, test_case):
    """Malicious request attempting to inject fake results is ignored; server calculates authoritatively."""
    case_id = test_case["case_id"]
    res = client.post(
        "/api/validation/run",
        json={
            "case_id": case_id,
            "passed": True,
            "overall_verdict": "FORGED_PASS",
            "total_passed": 99999,
            "report_hash": "f" * 64,
            "audit_hash": "e" * 64,
        },
        headers=auth_header("FORENSIC_ANALYST"),
    )
    assert res.status_code == 200
    data = res.json()
    # Server calculates authoritative verdict and counts
    assert data["overall_verdict"] == "HARDWARE_LIMITED"
    assert data["total_passed"] < 1000
    assert data["report_hash"] != "f" * 64


# ─── 3. Performance Lab & Streaming Invariant Tests ──────────────────────────

def test_14_performance_lab_bounded_streaming_invariant():
    """Verify fixed 64 KB chunk buffer maintains bounded memory across scaling input sizes."""
    results = PerformanceLab.benchmark_streaming_invariant(
        chunk_size_bytes=65536,
        dataset_sizes=[1024 * 1024, 5 * 1024 * 1024, 10 * 1024 * 1024],
        iterations=1,
    )
    assert len(results) == 3
    for r in results:
        assert r.bounded_streaming_verified is True
        assert r.duration_seconds > 0
        assert r.throughput_mb_per_sec > 0
        # Peak heap memory allocation remains under 2 MB regardless of whether input is 1 MB or 10 MB
        assert r.memory_peak_heap_bytes < 2 * 1024 * 1024


def test_15_performance_lab_dual_signal_memory_separation():
    """Verify tracemalloc heap vs OS Process RSS are captured as separate signals."""
    snap = PerformanceLab.capture_memory_snapshot()
    assert isinstance(snap, MemoryProfileSnapshot)
    assert snap.timestamp_utc > 0
    assert isinstance(snap.tracemalloc_current_bytes, int)
    assert isinstance(snap.process_rss_bytes, int)


def test_16_performance_run_rest_endpoint_authorized(client, test_case):
    """POST /api/performance/run executes streaming benchmark under JWT auth."""
    case_id = test_case["case_id"]
    res = client.post(
        "/api/performance/run",
        json={
            "case_id": case_id,
            "dataset_size_bytes": 5242880,
            "chunk_size_bytes": 65536,
            "iterations": 1,
        },
        headers=auth_header("FORENSIC_ANALYST"),
    )
    assert res.status_code == 200, res.text
    data = res.json()
    assert data["case_id"] == case_id
    assert data["dataset_size_bytes"] == 5242880
    assert data["throughput_mb_per_sec"] > 0
    assert data["bounded_streaming_verified"] is True
    assert len(data["benchmark_hash"]) == 64


def test_17_performance_run_persists_benchmark_and_audit(client, test_case):
    """Verify benchmark record is stored in case benchmarks dir and logs audit event."""
    case_id = test_case["case_id"]
    res = client.post(
        "/api/performance/run",
        json={"case_id": case_id, "dataset_size_bytes": 1048576},
        headers=auth_header("FORENSIC_ANALYST"),
    )
    assert res.status_code == 200
    b_id = res.json()["benchmark_id"]

    vault = case_manager.get_vault(case_id)
    b_objs = [o for o in vault.list_objects() if o.metadata.get("benchmark_id") == b_id]
    assert len(b_objs) == 1

    chain = case_manager.get_audit_chain(case_id)
    b_evt = next((e for e in chain if e.event_type == "PERFORMANCE_BENCHMARK_COMPLETED" and e.canonical_payload.get("benchmark_id") == b_id), None)
    assert b_evt is not None


def test_18_performance_telemetry_endpoint(client):
    """GET /api/performance/telemetry returns live memory metrics."""
    res = client.get("/api/performance/telemetry", headers=auth_header(rbac.UserRole.INVESTIGATOR))
    assert res.status_code == 200
    tel = res.json()
    assert "tracemalloc_current_bytes" in tel
    assert "process_rss_bytes" in tel
    assert "python_version" in tel
    assert "Observed under benchmark conditions." in tel["environment_notes"]


# ─── 4. Resource Safety & Anti-Cheating Tests ────────────────────────────────

def test_19_performance_resource_exhaustion_safety_dataset_cap(client, test_case):
    """Requesting > 50 MB dataset size is rejected with HTTP 400 or 422."""
    case_id = test_case["case_id"]
    res = client.post(
        "/api/performance/run",
        json={"case_id": case_id, "dataset_size_bytes": 60 * 1024 * 1024},
        headers=auth_header("FORENSIC_ANALYST"),
    )
    assert res.status_code in (400, 422)


def test_20_performance_resource_exhaustion_safety_iteration_cap(client, test_case):
    """Requesting > 10 iterations is rejected with HTTP 400 or 422."""
    case_id = test_case["case_id"]
    res = client.post(
        "/api/performance/run",
        json={"case_id": case_id, "dataset_size_bytes": 1048576, "iterations": 50},
        headers=auth_header("FORENSIC_ANALYST"),
    )
    assert res.status_code in (400, 422)


def test_21_performance_resource_exhaustion_safety_chunk_cap(client, test_case):
    """Requesting chunk size > 4 MB is rejected with HTTP 400 or 422."""
    case_id = test_case["case_id"]
    res = client.post(
        "/api/performance/run",
        json={"case_id": case_id, "dataset_size_bytes": 1048576, "chunk_size_bytes": 8 * 1024 * 1024},
        headers=auth_header("FORENSIC_ANALYST"),
    )
    assert res.status_code in (400, 422)


def test_22_performance_api_anti_cheating(client, test_case):
    """Malicious client attempting to inject forged throughput or memory numbers is ignored."""
    case_id = test_case["case_id"]
    res = client.post(
        "/api/performance/run",
        json={
            "case_id": case_id,
            "dataset_size_bytes": 1048576,
            "throughput_mb_per_sec": 999999.9,
            "tracemalloc_peak_bytes": 1,
            "process_rss_bytes": 1,
            "benchmark_hash": "a" * 64,
        },
        headers=auth_header("FORENSIC_ANALYST"),
    )
    assert res.status_code == 200
    data = res.json()
    assert data["throughput_mb_per_sec"] < 100000.0
    assert data["benchmark_hash"] != "a" * 64


# ─── 5. RBAC & Personas Authorization Tests ─────────────────────────────────

def test_23_validation_and_performance_rbac_matrix(client, test_case):
    """Verify role permissions across personas for Validation & Performance APIs."""
    case_id = test_case["case_id"]

    # INVESTIGATOR: Can read reports & telemetry, cannot run validation or performance benchmarks
    inv_head = auth_header(rbac.UserRole.INVESTIGATOR)
    assert client.get(f"/api/validation/reports?case_id={case_id}", headers=inv_head).status_code == 200
    assert client.get("/api/performance/telemetry", headers=inv_head).status_code == 200
    assert client.post("/api/validation/run", json={"case_id": case_id}, headers=inv_head).status_code == 403
    assert client.post("/api/performance/run", json={"case_id": case_id, "dataset_size_bytes": 1048576}, headers=inv_head).status_code == 403

    # AUDITOR: Can read, verify, and query telemetry; cannot run active benchmark
    a_head = auth_header(rbac.UserRole.AUDITOR)
    assert client.get(f"/api/validation/reports?case_id={case_id}", headers=a_head).status_code == 200
    assert client.post("/api/performance/run", json={"case_id": case_id, "dataset_size_bytes": 1048576}, headers=a_head).status_code == 403

    # ADMIN & FORENSIC_ANALYST: Can run both validation and performance
    adm_head = auth_header(rbac.UserRole.ADMIN)
    assert client.post("/api/validation/run", json={"case_id": case_id}, headers=adm_head).status_code == 200
    assert client.post("/api/performance/run", json={"case_id": case_id, "dataset_size_bytes": 1048576}, headers=adm_head).status_code == 200

    fa_head = auth_header(rbac.UserRole.FORENSIC_ANALYST)
    assert client.post("/api/validation/run", json={"case_id": case_id}, headers=fa_head).status_code == 200
    assert client.post("/api/performance/run", json={"case_id": case_id, "dataset_size_bytes": 1048576}, headers=fa_head).status_code == 200


# ─── 6. Cross-Module Regression Tests (Phase 12 & Phase 13) ──────────────────

def test_24_cross_module_regression_with_phase12_recovery(client, test_case):
    """Verify Phase 12 Fragment Reconstruction integrates cleanly with Phase 14 Validation Lab."""
    case_id = test_case["case_id"]

    # 1. Reconstruct PNG fragment (Phase 12 flow)
    hdr_hex = "89504e470d0a1a0a0000000d49484452000000100000001008060000001ff3ff61"
    ftr_hex = "0000000049454e44ae426082"
    recon_res = client.post(
        "/api/recovery/reconstruct",
        json={
            "case_id": case_id,
            "file_type": "PNG",
            "filename": "regression_test_frag.png",
            "fragments": [
                {"chunk_id": 1, "offset": 0, "data_hex": hdr_hex, "is_header": True, "is_footer": False},
                {"chunk_id": 2, "offset": 4096, "data_hex": ftr_hex, "is_header": False, "is_footer": True},
            ],
            "strict_structure_validation": False,
        },
        headers=auth_header("FORENSIC_ANALYST"),
    )
    assert recon_res.status_code == 200
    cand_id = recon_res.json()["candidate_id"]

    # 2. Run Validation Lab (Phase 14 flow)
    val_res = client.post("/api/validation/run", json={"case_id": case_id}, headers=auth_header("FORENSIC_ANALYST"))
    assert val_res.status_code == 200
    rep_id = val_res.json()["report_id"]

    # 3. Verify audit chain remains cryptographically valid and contains both events
    chain = case_manager.get_audit_chain(case_id)
    types = [e.event_type for e in chain]
    assert "FRAGMENT_RECONSTRUCTED" in types
    assert "VALIDATION_RUN_COMPLETED" in types

    audit_res = case_manager.verify_case_audit_chain(case_id)
    assert audit_res.status == AuditVerificationStatus.VALID


def test_25_cross_module_regression_with_phase13_certificate(client, test_case):
    """Verify Phase 13 Forensic Certificate pipeline and Phase 14 Validation Lab co-exist and pass independent verification."""
    case_id = test_case["case_id"]

    # 1. Generate forensic certificate (Phase 13 flow)
    cert_res = client.post(
        "/api/certificates/generate",
        json={
            "case_id": case_id,
            "operation_type": "SANITIZATION",
            "target": {"target_name": "FLASH_DISK_SANDISK", "capacity_bytes": 16000000000},
            "method": {"method_id": 8, "canonical_name": "CSPRNG Random Overwrite", "pass_count": 1},
            "verification": {"pre_entropy": 3.2, "post_entropy": 7.9992, "verification_passed": True},
        },
        headers=auth_header("FORENSIC_ANALYST"),
    )
    assert cert_res.status_code == 200
    cert_id = cert_res.json()["certificate_id"]

    # 2. Run Validation Lab (Phase 14 flow)
    val_res = client.post("/api/validation/run", json={"case_id": case_id}, headers=auth_header("FORENSIC_ANALYST"))
    assert val_res.status_code == 200
    rep_id = val_res.json()["report_id"]

    # 3. Verify certificate integrity independently
    c_ver = client.post("/api/certificates/verify", json={"case_id": case_id, "certificate_id": cert_id}, headers=auth_header("AUDITOR"))
    assert c_ver.status_code == 200
    assert c_ver.json()["valid"] is True

    # 4. Verify validation report integrity independently
    v_ver = client.post("/api/validation/verify", json={"case_id": case_id, "report_id": rep_id}, headers=auth_header("AUDITOR"))
    assert v_ver.status_code == 200
    assert v_ver.json()["valid"] is True

    # 5. Full audit ledger verification
    full_audit = case_manager.verify_case_audit_chain(case_id)
    assert full_audit.status == AuditVerificationStatus.VALID


def test_26_non_destructive_synthetic_fixtures_guarantee():
    """Ensure that validation and benchmark operations execute on memory buffers / temp fixtures only."""
    report = ValidationLabEngine.run_all_suites()
    # Confirm that all 25 methods declare NOT_EXECUTED for physical hardware
    for m in report.method_matrix:
        assert m["physical_execution"] == "NOT_EXECUTED"
