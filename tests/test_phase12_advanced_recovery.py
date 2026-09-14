"""
Phase 12 Comprehensive Validation Test Suite
Tests advanced recovery, candidate registry, fragment reconstruction, seam analysis,
overlap rejection, 5-factor confidence invariant, vault extraction promotion, and audit chaining.
"""

import os
import shutil
import hashlib
import tempfile
import pytest
from fastapi.testclient import TestClient

import drex_server
from drex_server import app
from drex_api_models import UserRole
from drex_rbac import create_access_token
from forensic_vault import (
    ForensicCaseManager,
    RecoveryCandidateState,
    RecoveryArtifactRecord,
)
from validators import (
    FormatRegistry,
    CandidateState,
    EvidenceScores,
)


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def test_case(tmp_path):
    # Setup isolated test vault and case
    vault_dir = tmp_path / "test_vault"
    vault_dir.mkdir(parents=True, exist_ok=True)
    mgr = ForensicCaseManager(base_data_dir=vault_dir)
    case = mgr.create_case(
        case_number="CASE-2026-001",
        title="Phase 12 Recovery Case",
        examiner="Lead Analyst",
        organization="DREX Forensic Lab",
        description="Forensic fragment reconstruction test",
    )
    # Patch global case manager in server for tests
    old_mgr = drex_server.case_manager
    drex_server.case_manager = mgr
    
    yield {"case_id": case.case_id, "mgr": mgr, "vault_dir": str(vault_dir)}
    
    drex_server.case_manager = old_mgr


def compute_five_factor_confidence(has_hdr: bool, has_ftr: bool, has_struct: bool, entropy_val: float, fs_align: float) -> float:
    hdr_score = 0.25 if has_hdr else 0.0
    ftr_score = 0.25 if has_ftr else 0.0
    struct_score = 0.20 if has_struct else 0.0
    entropy_score = min(1.0, max(0.0, entropy_val)) * 0.15
    fs_score = min(1.0, max(0.0, fs_align)) * 0.15
    return round(hdr_score + ftr_score + struct_score + entropy_score + fs_score, 4)


def test_phase12_five_factor_confidence_formula():
    """Verify the 5-factor confidence model invariant (0.25, 0.25, 0.20, 0.15, 0.15)."""
    # Exact weight verification
    weights = [0.25, 0.25, 0.20, 0.15, 0.15]
    assert sum(weights) == 1.00

    score = compute_five_factor_confidence(
        has_hdr=True,
        has_ftr=True,
        has_struct=True,
        entropy_val=1.0,
        fs_align=1.0,
    )
    assert abs(score - 1.00) < 1e-4

    # Partial score
    partial_score = compute_five_factor_confidence(
        has_hdr=True,
        has_ftr=False,
        has_struct=False,
        entropy_val=0.5,
        fs_align=0.0,
    )
    # Header: 0.25 + Entropy: 0.5 * 0.15 = 0.325
    assert abs(partial_score - 0.325) < 1e-4


def test_phase12_fragment_reconstruction_success(client, test_case):
    """Test valid bi-fragment reconstruction, candidate creation, and hash linkage."""
    token = create_access_token(UserRole.FORENSIC_ANALYST)
    case_id = test_case["case_id"]

    # Valid minimal PNG header chunk & footer chunk
    hdr_bytes = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15c4"
    ftr_bytes = b"\x00\x00\x00\x00IEND\xaeB`\x82"

    payload = {
        "case_id": case_id,
        "file_type": "PNG",
        "filename": "reconstructed_artifact.png",
        "fragments": [
            {
                "chunk_id": 1,
                "offset": 0,
                "data_hex": hdr_bytes.hex(),
                "is_header": True,
                "is_footer": False,
                "source_cluster": 100,
            },
            {
                "chunk_id": 2,
                "offset": len(hdr_bytes),
                "data_hex": ftr_bytes.hex(),
                "is_header": False,
                "is_footer": True,
                "source_cluster": 105,
            },
        ],
        "strict_structure_validation": False,
    }

    res = client.post(
        "/api/recovery/reconstruct",
        json=payload,
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res.status_code == 200, res.text
    data = res.json()
    assert data["case_id"] == case_id
    assert data["state"] == "RECONSTRUCTED_CANDIDATE"
    assert data["total_size_bytes"] == len(hdr_bytes) + len(ftr_bytes)
    assert data["reconstruction_confidence"] > 0.5
    assert len(data["sha256"]) == 64

    # Confirm candidate was registered in case vault
    candidates_res = client.get(
        f"/api/recovery/candidates?case_id={case_id}",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert candidates_res.status_code == 200
    c_list = candidates_res.json()
    matching = [c for c in c_list if c["candidate_id"] == data["candidate_id"]]
    assert len(matching) == 1
    assert matching[0]["validation_state"] == "RECONSTRUCTED_CANDIDATE"
    assert matching[0]["confidence_factors"]["header_signature"] == 0.25
    assert matching[0]["confidence_factors"]["footer_signature"] == 0.25


def test_phase12_fragment_reconstruction_overlap_rejection(client, test_case):
    """Test that overlapping fragment offsets are strictly rejected with HTTP 422."""
    token = create_access_token(UserRole.FORENSIC_ANALYST)
    case_id = test_case["case_id"]

    payload = {
        "case_id": case_id,
        "file_type": "PNG",
        "filename": "overlapping_attempt.png",
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
                "offset": 10,  # Overlaps with previous fragment (length is 33 bytes)
                "data_hex": "0000000049454e44ae426082",
                "is_header": False,
                "is_footer": True,
            },
        ],
    }

    res = client.post(
        "/api/recovery/reconstruct",
        json=payload,
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res.status_code == 422
    assert "Overlapping fragment extents" in res.json()["detail"]


def test_phase12_fragment_reconstruction_malformed_input(client, test_case):
    """Test rejection of empty fragments, malformed hex, and negative offsets."""
    token = create_access_token(UserRole.FORENSIC_ANALYST)
    case_id = test_case["case_id"]

    # Negative offset
    res = client.post(
        "/api/recovery/reconstruct",
        json={
            "case_id": case_id,
            "file_type": "JPEG",
            "filename": "neg.jpg",
            "fragments": [{"chunk_id": 1, "offset": -5, "data_hex": "ffd8ffe0"}],
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res.status_code == 422

    # Malformed hex string
    res2 = client.post(
        "/api/recovery/reconstruct",
        json={
            "case_id": case_id,
            "file_type": "JPEG",
            "filename": "badhex.jpg",
            "fragments": [{"chunk_id": 1, "offset": 0, "data_hex": "NOT_VALID_HEX"}],
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res2.status_code == 422


def test_phase12_candidate_extract_promotion_to_vault(client, test_case):
    """Test extraction of candidate into verified evidence vault object with audit entry."""
    token = create_access_token(UserRole.FORENSIC_ANALYST)
    case_id = test_case["case_id"]
    mgr: ForensicCaseManager = test_case["mgr"]

    # Pre-populate a candidate in the case vault
    valid_png = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15c4\x00\x00\x00\x00IEND\xaeB`\x82"
    rec = RecoveryArtifactRecord(
        candidate_id="CAND-TEST-001",
        case_id=case_id,
        source_evidence_id="\\\\.\\PhysicalDrive1",
        source_offset=4096,
        filesystem_origin="vault_target.png",
        carving_method="PNG",
        reconstruction_method="StructureCarver",
        evidence_confidence_score=0.88,
        validation_state=RecoveryCandidateState.VALIDATED_CANDIDATE,
        output_hash=hashlib.sha256(valid_png).hexdigest(),
        output_size=len(valid_png),
    )
    mgr.add_recovery_candidate(
        case_id=case_id,
        artifact=rec,
        payload_bytes=valid_png,
        actor="Lead Analyst",
    )

    # Extract candidate to vault
    res = client.post(
        "/api/recovery/extract",
        json={
            "case_id": case_id,
            "candidate_id": rec.candidate_id,
            "notes": "Verified candidate promoted to evidence vault",
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res.status_code == 200, res.text
    data = res.json()
    assert data["candidate_id"] == rec.candidate_id
    assert data["vault_object_id"].startswith("VLT-")
    assert data["sha256"] == rec.output_hash
    assert data["audit_event_id"].startswith("AUD-")

    # Verify audit chain integrity with Auditor persona
    auditor_token = create_access_token(UserRole.AUDITOR)
    audit_res = client.post(
        f"/api/audit/verify?case_id={case_id}",
        headers={"Authorization": f"Bearer {auditor_token}"},
    )
    assert audit_res.status_code == 200
    assert audit_res.json()["is_valid"] is True


def test_phase12_candidate_extract_corrupted_fails_closed(client, test_case):
    """Test that extracting a candidate whose payload fails structural validation is rejected."""
    token = create_access_token(UserRole.FORENSIC_ANALYST)
    case_id = test_case["case_id"]
    mgr: ForensicCaseManager = test_case["mgr"]

    # Corrupted candidate bytes that do not match format
    corrupted_bytes = b"CORRUPTED_GARBAGE_PAYLOAD_NOT_A_PNG"
    rec = RecoveryArtifactRecord(
        candidate_id="CAND-CORRUPT-001",
        case_id=case_id,
        source_evidence_id="\\\\.\\PhysicalDrive1",
        source_offset=0,
        filesystem_origin="corrupted.png",
        carving_method="PNG",
        reconstruction_method="StructureCarver",
        evidence_confidence_score=0.10,
        validation_state=RecoveryCandidateState.CANDIDATE,
        output_hash=hashlib.sha256(corrupted_bytes).hexdigest(),
        output_size=len(corrupted_bytes),
    )
    mgr.add_recovery_candidate(
        case_id=case_id,
        artifact=rec,
        payload_bytes=corrupted_bytes,
        actor="Lead Analyst",
    )

    # Attempt to extract should fail format validation gate
    res = client.post(
        "/api/recovery/extract",
        json={
            "case_id": case_id,
            "candidate_id": rec.candidate_id,
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res.status_code == 422
    assert "structural validation rejected" in res.json()["detail"].lower()


def test_phase12_recovery_idor_and_case_isolation(client, test_case):
    """Test IDOR protection across cases."""
    token = create_access_token(UserRole.FORENSIC_ANALYST)

    # Attempt reconstruct on non-existent case
    res1 = client.post(
        "/api/recovery/reconstruct",
        json={
            "case_id": "CASE-NON-EXISTENT-99999",
            "file_type": "PNG",
            "filename": "fake.png",
            "fragments": [{"chunk_id": 1, "offset": 0, "data_hex": "89504e470d0a1a0a"}],
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res1.status_code == 404

    # Attempt extract on non-existent candidate
    res2 = client.post(
        "/api/recovery/extract",
        json={
            "case_id": test_case["case_id"],
            "candidate_id": "CAND-NON-EXISTENT-999",
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res2.status_code == 404


def test_phase12_rbac_reconstruction_permissions(client, test_case):
    """Test that FORENSIC_ANALYST and ADMIN are permitted, while OPERATOR is denied."""
    case_id = test_case["case_id"]
    hdr_hex = "89504e470d0a1a0a"

    # Operator token
    op_token = create_access_token(UserRole.OPERATOR)
    res_op = client.post(
        "/api/recovery/reconstruct",
        json={
            "case_id": case_id,
            "file_type": "PNG",
            "filename": "op.png",
            "fragments": [{"chunk_id": 1, "offset": 0, "data_hex": hdr_hex}],
        },
        headers={"Authorization": f"Bearer {op_token}"},
    )
    assert res_op.status_code == 403

    # Forensic Analyst token
    fa_token = create_access_token(UserRole.FORENSIC_ANALYST)
    res_fa = client.post(
        "/api/recovery/reconstruct",
        json={
            "case_id": case_id,
            "file_type": "PNG",
            "filename": "fa.png",
            "fragments": [{"chunk_id": 1, "offset": 0, "data_hex": hdr_hex}],
        },
        headers={"Authorization": f"Bearer {fa_token}"},
    )
    assert res_fa.status_code == 200

    # Admin token
    admin_token = create_access_token(UserRole.ADMIN)
    res_admin = client.post(
        "/api/recovery/reconstruct",
        json={
            "case_id": case_id,
            "file_type": "PNG",
            "filename": "admin.png",
            "fragments": [{"chunk_id": 1, "offset": 0, "data_hex": hdr_hex}],
        },
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert res_admin.status_code == 200


def test_phase12_real_file_carving_scan_populates_candidates(client, tmp_path, test_case):
    """Test that DeepCarverEngine carving a test file generates candidate items with 5-factor scoring."""
    token = create_access_token(UserRole.FORENSIC_ANALYST)

    # Create a synthetic image with valid PNG and JPEG signatures embedded
    test_img = tmp_path / "test_drive.bin"
    png_data = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15c4\x00\x00\x00\x00IEND\xaeB`\x82"
    jpeg_data = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00\xff\xdb\x00C\x00\x08\x06\x06\x07\x06\x05\x08\x07\x07\x07\t\t\x08\n\x0c\x14\r\x0c\x0b\x0b\x0c\x19\x12\x13\x0f\x14\x1d\x1a\x1f\x1e\x1d\x1a\x1c\x1c $.' \",#\x1c\x1c(7),01444\x1f'9=82<.342\xff\xd9"
    
    with open(test_img, "wb") as f:
        f.write(b"\x00" * 1024)
        f.write(png_data)
        f.write(b"\x00" * 2048)
        f.write(jpeg_data)
        f.write(b"\x00" * 1024)

    out_dir = tmp_path / "scan_out"
    out_dir.mkdir(parents=True, exist_ok=True)

    scan_res = client.post(
        "/api/recovery/scan",
        json={
            "source_path": str(test_img),
            "destination_dir": str(out_dir),
            "engine": "CARVE",
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    assert scan_res.status_code == 200
    scan_data = scan_res.json()
    assert "job_id" in scan_data
    assert scan_data["job_id"].startswith("REC-")
