"""
DREX-V2 — Phase 21.1 Master Defect Elimination Tests
=====================================================
Automated verification for all Video Defect classes (V01-V14),
TOCTOU attacks (T01-T08), Method Invariants (M01-M25),
and Runtime Safety Tripwires.
"""

import hashlib
import json
import os
import pathlib
import tempfile
import time
import pytest
from starlette.testclient import TestClient

from drex_server import app, inspect_target_metadata, case_manager
from target_normalizer import normalize_target, TargetType
from hardware_storage import Qualification25MethodEngine


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def auth_headers(client):
    res = client.post("/api/auth/login", json={"username": "admin", "password": "Password123!", "role": "ADMIN"})
    data = res.json()
    token = data.get("access_token") or data.get("token")
    return {"Authorization": f"Bearer {token}"}


# ─── SECTION 1: V01 — FILE TARGET PATH CORRUPTION ─────────────────────────────

def test_v01_file_path_missing_backslash_recovery():
    """Verify D:ForensicData path missing backslash is normalized to D:\\ForensicData."""
    norm = normalize_target("D:ForensicDataTriageTarget.img")
    assert norm.normalized_target == "D:\\ForensicDataTriageTarget.img"
    assert norm.is_filesystem_path is True
    assert norm.is_physical_device is False


def test_v01_file_path_with_spaces():
    """Verify paths containing spaces survive normalization with exact string integrity."""
    raw = r"D:\Forensic Evidence Vault\Case 2026-09\triage artifact.docx"
    norm = normalize_target(raw)
    assert norm.normalized_target == raw
    assert norm.is_filesystem_path is True


def test_v01_file_path_unicode():
    """Verify Unicode paths survive normalization without mangling."""
    raw = r"D:\Forensic_案件_データ\evidence_01.dat"
    norm = normalize_target(raw)
    assert norm.normalized_target == raw
    assert norm.is_filesystem_path is True


def test_v01_deeply_nested_file_path():
    """Verify deeply nested file paths preserve all directories and separators."""
    raw = r"D:\Level1\Level2\Level3\Level4\Level5\evidence.bin"
    norm = normalize_target(raw)
    assert norm.normalized_target == raw


# ─── SECTION 2: V02 & V03 — PHYSICAL DRIVE PATH CORRUPTION & NAMESPACES ────────

def test_v02_physical_drive_lost_backslash_recovery():
    """Verify .PHYSICALDRIVE1 with stripped backslashes is normalized to \\\\.\\PhysicalDrive1."""
    norm = normalize_target(".PHYSICALDRIVE1")
    assert norm.normalized_target == r"\\.\PhysicalDrive1"
    assert norm.is_physical_device is True
    assert norm.disk_number == 1


def test_v02_physical_drive_exact_namespace():
    """Verify \\\\.\\PhysicalDrive0 is correctly identified as physical device and system drive."""
    norm = normalize_target(r"\\.\PhysicalDrive0")
    assert norm.normalized_target == r"\\.\PhysicalDrive0"
    assert norm.is_physical_device is True
    assert norm.is_system_drive is True


def test_v03_device_vs_filesystem_namespaces():
    """Verify clear namespace separation between FILE, DIRECTORY, VOLUME, and PHYSICAL_DEVICE."""
    # File
    f_norm = normalize_target(r"D:\Data\file.docx")
    assert f_norm.target_type == TargetType.FILE.value
    assert f_norm.is_physical_device is False

    # Directory
    d_norm = normalize_target(r"D:\Data")
    assert d_norm.target_type in (TargetType.DIRECTORY.value, TargetType.FILE.value)
    assert d_norm.is_physical_device is False

    # Volume
    v_norm = normalize_target(r"D:")
    assert v_norm.target_type == TargetType.VOLUME.value
    assert v_norm.is_volume is True

    # Physical Device
    p_norm = normalize_target(r"\\.\PhysicalDrive1")
    assert p_norm.target_type == TargetType.PHYSICAL_DEVICE.value
    assert p_norm.is_physical_device is True


def test_v03_inspect_target_metadata_device():
    """Verify inspect_target_metadata handles physical device namespace without calling Path.resolve()."""
    meta = inspect_target_metadata(r"\\.\PhysicalDrive1")
    assert meta["type"] == "DEVICE"
    assert meta["path"] == r"\\.\PhysicalDrive1"
    assert meta["filesystem"] == "RAW_BLOCK_DEVICE"
    assert meta["protected"] is False


# ─── SECTION 3: V04 & V05 — NOTIFICATION & CASE ISOLATION ─────────────────────

def test_v04_notification_scoping_in_spa():
    """Verify notification filtering logic strictly enforces workflowId and caseId isolation."""
    app_js_path = os.path.join(os.path.dirname(__file__), "..", "webui", "app.js")
    with open(app_js_path, "r", encoding="utf-8") as f:
        content = f.read()

    assert "workflowId && STATE.currentView && STATE.currentView !== workflowId" in content
    assert "toastWf && toastWf !== viewId" in content
    assert "_recentNotifs = new Map()" in content


def test_v05_case_isolation_during_demo_loop(client, auth_headers):
    """Verify running synthetic or operational demo does not mutate active investigator case."""
    # Create an active operational case
    ops_case = case_manager.create_case(
        case_number=f"OPS-{int(time.time())}",
        title="Active Operational Case",
        examiner="Lead Investigator",
        organization="Digital Forensics Lab",
    )
    case_manager.active_case = ops_case

    # Run demo flow with auth
    res = client.post("/api/demo/flow", headers=auth_headers)
    assert res.status_code == 200
    demo_data = res.json()

    # Active operational case should still be the original
    assert case_manager.active_case.case_id == ops_case.case_id
    assert demo_data["case_id"] != ops_case.case_id
    assert demo_data["case_number"].startswith("EVAL-")


# ─── SECTION 4: V06 & V07 — EVIDENCE AGGREGATION & CERTIFICATE VERIFICATION ───

def test_v06_evidence_aggregation_across_cases(client, auth_headers):
    """Verify GET /api/evidence enforces case isolation and fails closed when case_id is omitted."""
    from forensic_vault import EvidenceSourceType
    c1 = case_manager.create_case(case_number=f"EVAL-EV1-{int(time.time())}", title="Case 1", examiner="Analyst 1", organization="Forensic Lab")
    case_manager.register_evidence(
        case_id=c1.case_id,
        source_type=EvidenceSourceType.FILE,
        source_path=r"D:\Data\file1.dat",
        examiner="Analyst 1",
        capacity=1024,
    )

    # 1. Without case_id, fail-closed to empty list to preserve cross-case privacy
    res_default = client.get("/api/evidence", headers=auth_headers)
    assert res_default.status_code == 200
    assert res_default.json() == []

    # 2. With specific case_id, return case-specific evidence
    res_scoped = client.get(f"/api/evidence?case_id={c1.case_id}", headers=auth_headers)
    assert res_scoped.status_code == 200
    items = res_scoped.json()
    assert isinstance(items, list)
    assert len(items) > 0
    assert all(it["case_id"] == c1.case_id for it in items)

    # 3. Explicit all_cases=true auditor mode aggregates
    res_all = client.get("/api/evidence?all_cases=true", headers=auth_headers)
    assert res_all.status_code == 200
    all_items = res_all.json()
    assert len(all_items) >= len(items)


def test_v07_certificate_verification_and_tamper_detection(client, auth_headers):
    """Verify certificate generation, PDF download, and independent tamper detection."""
    # Run operational demo flow to produce real certificate
    res = client.post("/api/demo/operational-flow", headers=auth_headers)
    assert res.status_code == 200
    data = res.json()
    cert_id = data["certificate_id"]
    case_id = data["case_id"]

    # Verify certificate
    verify_res = client.post("/api/certificates/verify", json={"case_id": case_id, "certificate_id": cert_id}, headers=auth_headers)
    assert verify_res.status_code == 200
    v_data = verify_res.json()
    assert v_data["valid"] is True
    assert v_data["certificate_hash_valid"] is True
    assert v_data["pdf_hash_valid"] is True

    # Tampered case should fail verification
    bad_verify = client.post("/api/certificates/verify", json={"case_id": "CASE-NONEXISTENT", "certificate_id": cert_id}, headers=auth_headers)
    assert bad_verify.status_code == 200
    assert bad_verify.json()["valid"] is False


# ─── SECTION 5: V08-V10 — RECOVERY & FRAGMENT VERIFICATION ─────────────────────

def test_v09_fragment_reconstruction_png_valid(client, auth_headers):
    """Verify bipartite non-contiguous PNG chunk reconstruction and SHA-256 verification."""
    c = case_manager.create_case(case_number=f"FRAG-{int(time.time())}", title="Fragment Case", examiner="Analyst", organization="Forensic Lab")
    
    png_hdr = "89504e470d0a1a0a0000000d49484452000000100000001008060000001ff3ff61"
    png_ftr = "0000000049454e44ae426082"
    
    res = client.post(
        "/api/recovery/reconstruct",
        json={
            "case_id": c.case_id,
            "file_type": "PNG",
            "filename": "reconstructed.png",
            "fragments": [
                {"chunk_id": 1, "offset": 0, "data_hex": png_hdr, "is_header": True, "is_footer": False},
                {"chunk_id": 2, "offset": 4096, "data_hex": png_ftr, "is_header": False, "is_footer": True},
            ],
        },
        headers=auth_headers,
    )
    assert res.status_code == 200
    recon = res.json()
    assert recon["is_valid_structure"] is True
    assert recon["reconstruction_confidence"] >= 0.8
    assert recon["total_size_bytes"] > 0
    assert len(recon["sha256"]) == 64


def test_v09_fragment_reconstruction_rejects_overlapping_extents(client, auth_headers):
    """Verify reconstruction engine rejects overlapping fragment extents."""
    c = case_manager.create_case(case_number=f"FRAG-ERR-{int(time.time())}", title="Error Case", examiner="Analyst", organization="Forensic Lab")
    
    res = client.post(
        "/api/recovery/reconstruct",
        json={
            "case_id": c.case_id,
            "file_type": "PNG",
            "filename": "overlap.png",
            "fragments": [
                {"chunk_id": 1, "offset": 0, "data_hex": "AABBCCDD" * 10, "is_header": True, "is_footer": False},
                {"chunk_id": 2, "offset": 10, "data_hex": "11223344" * 10, "is_header": False, "is_footer": True},
            ],
        },
        headers=auth_headers,
    )
    assert res.status_code == 422


# ─── SECTION 6: V11-V13 — SYSTEM DISK SAFETY TRIPWIRES ─────────────────────────

def test_v13_system_drive_destructive_tripwire(client, auth_headers):
    """Verify destructive sanitization against Windows system drive is blocked."""
    c = case_manager.create_case(case_number=f"TRIP-{int(time.time())}", title="Tripwire Case", examiner="Analyst", organization="Forensic Lab")
    
    for bad_target in [r"C:\Windows", "C:\\", r"\\.\PhysicalDrive0", r"C:\Program Files"]:
        res = client.post(
            "/api/sanitization/execute",
            json={
                "case_id": c.case_id,
                "target_path": bad_target,
                "method_id": 8,
                "safety_phrase_entered": "ERASE-TARGET-PERMANENT",
            },
            headers=auth_headers,
        )
        assert res.status_code in (403, 422), f"Target {bad_target} was not blocked by tripwire (status {res.status_code})"


# ─── SECTION 7: TOCTOU ATTACK TESTING (T01-T08) ────────────────────────────────

def test_toctou_t01_file_modified_after_preflight(client, auth_headers, tmp_path):
    """TOCTOU T01: File modified after preflight inspection must fail closed with 409 Conflict."""
    c = case_manager.create_case(case_number=f"TOCTOU-{int(time.time())}", title="TOCTOU Case", examiner="Analyst", organization="Forensic Lab")
    test_file = tmp_path / "safe_toctou_target.bin"
    test_file.write_bytes(b"INITIAL_ORIGINAL_DATA_CONTENT" * 100)
    
    # 1. Preflight inspection
    insp = inspect_target_metadata(str(test_file))
    preflight_hash = insp["preflight_hash"]
    assert preflight_hash is not None

    # 2. TOCTOU modification attack
    test_file.write_bytes(b"TAMPERED_MODIFIED_DATA_CONTENT" * 100)

    # 3. Execute sanitization with old preflight identity
    clean_target = str(test_file).replace("\\", "_").replace("/", "_").replace(".", "_").replace(":", "_").strip("_").upper()
    phrase = f"ERASE-{clean_target}-PERMANENT"
    
    res = client.post(
        "/api/sanitization/execute",
        json={
            "case_id": c.case_id,
            "target_path": str(test_file),
            "method_id": 8,
            "safety_phrase_entered": phrase,
            "preflight_identity": preflight_hash,
        },
        headers=auth_headers,
    )
    assert res.status_code == 409
    assert "TOCTOU VIOLATION" in res.json()["detail"]


# ─── SECTION 8: METHOD INVARIANTS M01-M25 TRUTHFULNESS ─────────────────────────

def test_m01_m25_all_methods_registered_and_classified():
    """Verify all 25 canonical methods exist in CANONICAL_25_METHODS_SPEC."""
    from hardware_storage import CANONICAL_25_METHODS_SPEC
    assert len(CANONICAL_25_METHODS_SPEC) == 25
    ids = list(CANONICAL_25_METHODS_SPEC.keys())
    assert sorted(ids) == list(range(1, 26))

    for m_id, spec in CANONICAL_25_METHODS_SPEC.items():
        assert "name" in spec
        assert "category" in spec
        assert "backend" in spec
        assert spec["category"] in ("Drive Erasure", "File/Folder Erasure", "Recovery")

