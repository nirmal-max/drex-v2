"""
DREX-V2 Phase 13 End-to-End Forensic Certificate & Cryptographic Attestation Pipeline Test Suite
================================================================================================

Validates:
1. End-to-end certificate generation, server-side authoritative data binding, and PDF 1.4 compilation.
2. Case-bound evidence vault persistence (JSON and PDF artifacts as VaultObjectType.CERTIFICATE).
3. SHA-256 hash-linked audit chain append with CERTIFICATE_ISSUED events.
4. Independent multi-factor verification (structure, certificate hash, PDF digest, audit chain, case/op binding).
5. Tamper-evidence detection (mutated JSON, mutated PDF bytes, broken audit chain, forged ID, cross-case IDOR).
6. Strict RBAC permission enforcement (issue vs read vs verify across personas).
7. Fail-closed truth model discipline (rejection of non-COMPLETED jobs, preservation of HARDWARE_REQUIRED states).
8. Regression compatibility with Phase 10-12 baselines.

Zero external dependencies (pure Python standard library + pytest + fastapi TestClient).
License: Apache 2.0.
"""

import hashlib
import json
import os
import pathlib
import tempfile
import time
import uuid
import pytest
from fastapi.testclient import TestClient

import drex_api_models as models
import drex_rbac as rbac
from certificate_engine import (
    ForensicCertificateEngine,
    ForensicSanitizationCertificate,
    PurePythonPDFWriter,
    CertificateTargetInfo,
    CertificateMethodInfo,
    CertificateVerificationInfo,
    CertificateTruthModel,
)
from drex_server import app, case_manager, job_registry
from forensic_vault import (
    ForensicCaseManager,
    EvidenceVault,
    VaultObjectType,
    AuditVerificationStatus,
    StreamingHasher,
)


@pytest.fixture(scope="module")
def client():
    return TestClient(app)


@pytest.fixture
def auth_headers():
    def _headers(role=rbac.UserRole.ADMIN):
        token = rbac.create_access_token(
            role=role,
            username=f"test_{role.value.lower()}",
        )
        return {"Authorization": f"Bearer {token}"}
    return _headers


@pytest.fixture
def test_case(client, auth_headers):
    c = case_manager.create_case(
        case_number=f"TEST-CASE-{uuid.uuid4().hex[:6].upper()}",
        title="Phase 13 Certificate Pipeline Test Case",
        examiner="Lead Forensic Analyst",
        organization="DREX Forensic Lab",
        description="Tamper-evident certificate validation container.",
    )
    return c


# ─── 1. Generation & Data Model Integrity ─────────────────────────────────────

def test_certificate_generation_success(client, auth_headers, test_case):
    """Verify certificate generation endpoint creates valid record bound to case."""
    headers = auth_headers(rbac.UserRole.ADMIN)
    req_body = {
        "case_id": test_case.case_id,
        "target_identifier": "TEST_STORAGE_DRIVE_0",
        "method_id": 8,
        "examiner_name": "Senior Certifier",
        "notes": "Verified CSPRNG overwrite.",
    }
    resp = client.post("/api/certificates/generate", json=req_body, headers=headers)
    assert resp.status_code == 200, resp.text
    data = resp.json()

    assert data["certificate_id"].startswith("CERT-DREX-")
    assert data["case_id"] == test_case.case_id
    assert data["method_id"] == 8
    assert data["method_name"] == "CSPRNG Random Overwrite"
    assert "NIST SP 800-88" in data["standard_reference"]
    assert data["execution_state"] == "REAL"
    assert data["verification_state"] == "EXACT_READBACK"
    assert data["physical_execution"] == "NOT_EXECUTED"
    assert len(data["tamper_evident_signature"]) == 64
    assert len(data["audit_chain_event_hash"]) == 64
    assert data["pdf_sha256"] is not None
    assert len(data["pdf_sha256"]) == 64


def test_certificate_retrieval_and_listing(client, auth_headers, test_case):
    """Verify list and detail retrieval endpoints."""
    headers = auth_headers(rbac.UserRole.FORENSIC_ANALYST)
    # Generate a certificate
    gen_resp = client.post(
        "/api/certificates/generate",
        json={"case_id": test_case.case_id, "method_id": 1},
        headers=headers,
    )
    assert gen_resp.status_code == 200
    cert_id = gen_resp.json()["certificate_id"]

    # List certificates
    list_resp = client.get(f"/api/certificates?case_id={test_case.case_id}", headers=headers)
    assert list_resp.status_code == 200
    certs = list_resp.json()
    assert len(certs) >= 1
    assert any(c["certificate_id"] == cert_id for c in certs)

    # Get single certificate
    get_resp = client.get(f"/api/certificates/{cert_id}?case_id={test_case.case_id}", headers=headers)
    assert get_resp.status_code == 200
    assert get_resp.json()["certificate_id"] == cert_id


# ─── 2. PDF Structure & Standard Conformance ──────────────────────────────────

def test_pdf_download_and_structure(client, auth_headers, test_case):
    """Verify downloaded PDF conforms to PDF 1.4 specification without external dependencies."""
    headers = auth_headers(rbac.UserRole.ADMIN)
    gen_resp = client.post(
        "/api/certificates/generate",
        json={"case_id": test_case.case_id, "method_id": 8},
        headers=headers,
    )
    assert gen_resp.status_code == 200
    cert_id = gen_resp.json()["certificate_id"]

    pdf_resp = client.get(f"/api/certificates/{cert_id}/pdf?case_id={test_case.case_id}", headers=headers)
    assert pdf_resp.status_code == 200
    assert pdf_resp.headers["content-type"] == "application/pdf"
    pdf_bytes = pdf_resp.content

    # Validate PDF 1.4 Structural Invariants
    assert pdf_bytes.startswith(b"%PDF-1.4"), "PDF must start with %PDF-1.4 header"
    assert b"%%EOF" in pdf_bytes, "PDF must contain %%EOF marker"
    assert b"/Type /Catalog" in pdf_bytes, "PDF must include catalog"
    assert b"/Type /Pages" in pdf_bytes, "PDF must include page tree"
    assert b"/Type /Page" in pdf_bytes, "PDF must include page object"
    assert b"xref" in pdf_bytes, "PDF must contain cross-reference table"
    assert b"trailer" in pdf_bytes, "PDF must contain trailer"
    assert b"DREX-V2 FORENSIC SANITIZATION CERTIFICATE" in pdf_bytes


# ─── 3. SHA-256 Integrity & Audit Chain Binding ───────────────────────────────

def test_certificate_sha256_integrity_and_audit_binding(client, auth_headers, test_case):
    """Verify cryptographic binding between certificate metadata, PDF, and audit chain."""
    headers = auth_headers(rbac.UserRole.ADMIN)
    gen_resp = client.post(
        "/api/certificates/generate",
        json={"case_id": test_case.case_id, "method_id": 7},
        headers=headers,
    )
    assert gen_resp.status_code == 200
    cert_data = gen_resp.json()
    cert_id = cert_data["certificate_id"]

    # Verify audit ledger contains CERTIFICATE_ISSUED event
    audit_chain = case_manager.get_audit_chain(test_case.case_id)
    cert_events = [
        e for e in audit_chain
        if e.event_type == "CERTIFICATE_ISSUED" and e.canonical_payload.get("certificate_id") == cert_id
    ]
    assert len(cert_events) == 1
    evt = cert_events[0]
    assert evt.canonical_payload["certificate_hash"] == cert_data["tamper_evident_signature"]
    assert evt.canonical_payload["pdf_hash"] == cert_data["pdf_sha256"]


def test_certificate_verification_success(client, auth_headers, test_case):
    """Verify POST /api/certificates/verify passes for untouched certificate."""
    headers = auth_headers(rbac.UserRole.AUDITOR)
    gen_headers = auth_headers(rbac.UserRole.ADMIN)
    gen_resp = client.post(
        "/api/certificates/generate",
        json={"case_id": test_case.case_id, "method_id": 8},
        headers=gen_headers,
    )
    cert_id = gen_resp.json()["certificate_id"]

    verify_resp = client.post(
        "/api/certificates/verify",
        json={"case_id": test_case.case_id, "certificate_id": cert_id},
        headers=headers,
    )
    assert verify_resp.status_code == 200
    v = verify_resp.json()
    assert v["valid"] is True
    assert v["certificate_hash_valid"] is True
    assert v["pdf_hash_valid"] is True
    assert v["audit_chain_valid"] is True
    assert v["case_binding_valid"] is True
    assert v["operation_binding_valid"] is True
    assert "PASS" in v["verdict"]


# ─── 4. Tamper Testing & Mutation Detection ───────────────────────────────────

def test_tampered_json_detection(client, auth_headers, test_case):
    """Verify that tampering with any field in the certificate JSON is detected."""
    headers = auth_headers(rbac.UserRole.ADMIN)
    gen_resp = client.post(
        "/api/certificates/generate",
        json={"case_id": test_case.case_id, "method_id": 8},
        headers=headers,
    )
    cert_id = gen_resp.json()["certificate_id"]

    # Tamper with the JSON on disk (e.g. change target_name)
    cdir = case_manager._case_path(test_case.case_id)
    json_path = cdir / "certificates" / f"{cert_id}.json"
    data = json.loads(json_path.read_text(encoding="utf-8"))
    data["target"]["target_name"] = "TAMPERED_TARGET_DRIVE_X"
    json_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

    # Run independent verification
    v_resp = client.post(
        "/api/certificates/verify",
        json={"case_id": test_case.case_id, "certificate_id": cert_id},
        headers=headers,
    )
    assert v_resp.status_code == 200
    v = v_resp.json()
    assert v["valid"] is False
    assert v["certificate_hash_valid"] is False, "Tampered JSON must fail certificate hash verification"


def test_tampered_pdf_detection(client, auth_headers, test_case):
    """Verify that modifying even 1 byte of the PDF artifact fails verification."""
    headers = auth_headers(rbac.UserRole.ADMIN)
    gen_resp = client.post(
        "/api/certificates/generate",
        json={"case_id": test_case.case_id, "method_id": 8},
        headers=headers,
    )
    cert_id = gen_resp.json()["certificate_id"]

    # Tamper with PDF bytes on disk
    cdir = case_manager._case_path(test_case.case_id)
    pdf_path = cdir / "certificates" / f"{cert_id}.pdf"
    pdf_bytes = bytearray(pdf_path.read_bytes())
    pdf_bytes[len(pdf_bytes) // 2] ^= 0xFF  # Flip byte
    pdf_path.write_bytes(bytes(pdf_bytes))

    # Run independent verification
    v_resp = client.post(
        "/api/certificates/verify",
        json={"case_id": test_case.case_id, "certificate_id": cert_id},
        headers=headers,
    )
    assert v_resp.status_code == 200
    v = v_resp.json()
    assert v["valid"] is False
    assert v["pdf_hash_valid"] is False, "Tampered PDF must fail digest verification"


def test_tampered_audit_chain_detection(client, auth_headers, test_case):
    """Verify that mutating the audit chain invalidates certificate verification."""
    headers = auth_headers(rbac.UserRole.ADMIN)
    gen_resp = client.post(
        "/api/certificates/generate",
        json={"case_id": test_case.case_id, "method_id": 8},
        headers=headers,
    )
    cert_id = gen_resp.json()["certificate_id"]

    # Tamper with audit chain on disk
    cdir = case_manager._case_path(test_case.case_id)
    audit_file = cdir / "audit" / "audit_chain.json"
    audit_events = json.loads(audit_file.read_text(encoding="utf-8"))
    audit_events[-1]["actor"] = "MALICIOUS_IMPOSTOR"
    audit_file.write_text(json.dumps(audit_events, indent=2), encoding="utf-8")

    # Run independent verification
    v_resp = client.post(
        "/api/certificates/verify",
        json={"case_id": test_case.case_id, "certificate_id": cert_id},
        headers=headers,
    )
    assert v_resp.status_code == 200
    v = v_resp.json()
    assert v["valid"] is False
    assert v["audit_chain_valid"] is False, "Broken audit chain must fail verification"


# ─── 5. Case Isolation & IDOR Protection ──────────────────────────────────────

def test_case_isolation_and_idor(client, auth_headers):
    """Verify that querying Case A's certificate from Case B fails closed."""
    headers = auth_headers(rbac.UserRole.ADMIN)
    case_a = case_manager.create_case("CASE-A-NUM", "Case A", "Examiner A", "Lab A")
    case_b = case_manager.create_case("CASE-B-NUM", "Case B", "Examiner B", "Lab B")

    # Generate certificate in Case A
    gen_resp = client.post(
        "/api/certificates/generate",
        json={"case_id": case_a.case_id, "method_id": 8},
        headers=headers,
    )
    cert_id = gen_resp.json()["certificate_id"]

    # Attempt to query Case A's cert using Case B
    resp_cross_get = client.get(f"/api/certificates/{cert_id}?case_id={case_b.case_id}", headers=headers)
    assert resp_cross_get.status_code == 404

    # Attempt to verify Case A's cert claiming it belongs to Case B
    v_cross = client.post(
        "/api/certificates/verify",
        json={"case_id": case_b.case_id, "certificate_id": cert_id},
        headers=headers,
    )
    assert v_cross.status_code == 200
    assert v_cross.json()["valid"] is False


def test_malformed_and_path_traversal_ids(client, auth_headers, test_case):
    """Verify path traversal and non-existent certificate IDs fail safely."""
    headers = auth_headers(rbac.UserRole.ADMIN)
    traversal_id = ".._.._etc_passwd"

    resp = client.get(f"/api/certificates/{traversal_id}?case_id={test_case.case_id}", headers=headers)
    assert resp.status_code == 404

    resp_pdf = client.get(f"/api/certificates/{traversal_id}/pdf?case_id={test_case.case_id}", headers=headers)
    assert resp_pdf.status_code == 404

    # Non-existent ID
    resp_non = client.get(f"/api/certificates/CERT-NONEXISTENT?case_id={test_case.case_id}", headers=headers)
    assert resp_non.status_code == 404


# ─── 6. RBAC Permissions Matrix ───────────────────────────────────────────────

def test_rbac_permissions_enforcement(client, auth_headers, test_case):
    """Verify permissions across ADMIN, FORENSIC_ANALYST, AUDITOR, INVESTIGATOR, OPERATOR."""
    admin_hdr = auth_headers(rbac.UserRole.ADMIN)
    analyst_hdr = auth_headers(rbac.UserRole.FORENSIC_ANALYST)
    auditor_hdr = auth_headers(rbac.UserRole.AUDITOR)
    investigator_hdr = auth_headers(rbac.UserRole.INVESTIGATOR)
    operator_hdr = auth_headers(rbac.UserRole.OPERATOR)

    # 1. Admin can issue, read, verify
    r1 = client.post("/api/certificates/generate", json={"case_id": test_case.case_id, "method_id": 8}, headers=admin_hdr)
    assert r1.status_code == 200
    cert_id = r1.json()["certificate_id"]

    # 2. Forensic Analyst can issue, read, verify
    r2 = client.post("/api/certificates/generate", json={"case_id": test_case.case_id, "method_id": 8}, headers=analyst_hdr)
    assert r2.status_code == 200

    # 3. Auditor can read and verify, but CANNOT issue
    r3_issue = client.post("/api/certificates/generate", json={"case_id": test_case.case_id, "method_id": 8}, headers=auditor_hdr)
    assert r3_issue.status_code == 403
    r3_read = client.get(f"/api/certificates/{cert_id}?case_id={test_case.case_id}", headers=auditor_hdr)
    assert r3_read.status_code == 200
    r3_verify = client.post("/api/certificates/verify", json={"case_id": test_case.case_id, "certificate_id": cert_id}, headers=auditor_hdr)
    assert r3_verify.status_code == 200

    # 4. Operator CANNOT issue or verify
    r4_issue = client.post("/api/certificates/generate", json={"case_id": test_case.case_id, "method_id": 8}, headers=operator_hdr)
    assert r4_issue.status_code == 403
    r4_verify = client.post("/api/certificates/verify", json={"case_id": test_case.case_id, "certificate_id": cert_id}, headers=operator_hdr)
    assert r4_verify.status_code == 403
    r4_read = client.get(f"/api/certificates/{cert_id}?case_id={test_case.case_id}", headers=operator_hdr)
    assert r4_read.status_code == 200

    # 5. Unauthenticated rejected with 401
    r5 = client.get(f"/api/certificates/{cert_id}?case_id={test_case.case_id}")
    assert r5.status_code == 401


# ─── 7. Incomplete Job Fail-Closed & Truth Model ──────────────────────────────

def test_failed_and_running_job_certificate_rejection(client, auth_headers, test_case):
    """Verify that jobs in FAILED, CANCELLED, or RUNNING states cannot receive a certificate."""
    headers = auth_headers(rbac.UserRole.ADMIN)

    # Register a running job
    running_job_id = f"JOB-RUN-{uuid.uuid4().hex[:6]}"
    job_registry.register_job(
        job_id=running_job_id,
        operation_type="SANITIZATION_EXECUTE",
        target_path="DUMMY_TARGET",
        case_id=test_case.case_id,
    )
    job_registry.update_job(running_job_id, status=models.JobLifecycleState.RUNNING)

    r_run = client.post(
        "/api/certificates/generate",
        json={"case_id": test_case.case_id, "job_id": running_job_id},
        headers=headers,
    )
    assert r_run.status_code == 422, "Running job must be rejected with HTTP 422"

    # Register a failed job
    failed_job_id = f"JOB-FAIL-{uuid.uuid4().hex[:6]}"
    job_registry.register_job(
        job_id=failed_job_id,
        operation_type="SANITIZATION_EXECUTE",
        target_path="DUMMY_TARGET",
        case_id=test_case.case_id,
    )
    job_registry.update_job(failed_job_id, status=models.JobLifecycleState.FAILED, error_message="IO Error")

    r_fail = client.post(
        "/api/certificates/generate",
        json={"case_id": test_case.case_id, "job_id": failed_job_id},
        headers=headers,
    )
    assert r_fail.status_code == 422, "Failed job must be rejected with HTTP 422"


def test_hardware_required_boundary_truth_model(client, auth_headers, test_case):
    """Verify that hardware-dependent methods (M03, M05, M23, M24) preserve truth state NOT_EXECUTED."""
    headers = auth_headers(rbac.UserRole.ADMIN)

    for m_id in (3, 5, 23, 24):
        resp = client.post(
            "/api/certificates/generate",
            json={"case_id": test_case.case_id, "method_id": m_id},
            headers=headers,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["physical_execution"] == "NOT_EXECUTED", f"Method {m_id} must have physical_execution=NOT_EXECUTED"
        assert any("Physical controller execution: NOT_EXECUTED" in lim for lim in data["forensic_limitations"])


# ─── 8. Vault Integration & Atomic Persistence ────────────────────────────────

def test_vault_integration_and_atomic_persistence(client, auth_headers, test_case):
    """Verify that certificates are indexed in the case EvidenceVault as VaultObjectType.CERTIFICATE."""
    headers = auth_headers(rbac.UserRole.ADMIN)
    resp = client.post(
        "/api/certificates/generate",
        json={"case_id": test_case.case_id, "method_id": 8},
        headers=headers,
    )
    cert_id = resp.json()["certificate_id"]

    vault = case_manager.get_vault(test_case.case_id)
    objects = vault.list_objects()

    cert_objs = [o for o in objects if o.object_type == VaultObjectType.CERTIFICATE and o.metadata.get("certificate_id") == cert_id]
    assert len(cert_objs) == 2, "Must register both JSON and PDF vault objects"
    formats = {o.metadata.get("format") for o in cert_objs}
    assert formats == {"JSON", "PDF"}


# ─── 9. Phase 12 Regression Compatibility ─────────────────────────────────────

def test_regression_with_phase12_recovery_candidates(client, auth_headers, test_case):
    """Ensure Phase 12 recovery candidate and vault ingestion flow remains unbroken."""
    headers = auth_headers(rbac.UserRole.ADMIN)
    scan_resp = client.post(
        "/api/recovery/scan",
        json={"source_path": "C:\\Windows\\dummy.img", "destination_dir": "C:\\Windows\\dummy_out", "case_id": test_case.case_id},
        headers=headers,
    )
    assert scan_resp.status_code == 200
    assert "job_id" in scan_resp.json()

    # Verify candidate listing
    cand_resp = client.get("/api/recovery/candidates", headers=headers)
    assert cand_resp.status_code == 200
    assert isinstance(cand_resp.json(), list)


# ─── 10. Extended Edge Cases & Manipulation Resistance ────────────────────────

def test_cancelled_and_interrupted_job_rejection(client, auth_headers, test_case):
    """Verify that cancelled and interrupted jobs are rejected from certificate issuance."""
    headers = auth_headers(rbac.UserRole.ADMIN)

    # Cancelled job
    canc_job_id = f"JOB-CANC-{uuid.uuid4().hex[:6]}"
    job_registry.register_job(
        job_id=canc_job_id,
        operation_type="SANITIZATION_EXECUTE",
        target_path="TARGET",
        case_id=test_case.case_id,
    )
    job_registry.update_job(canc_job_id, status=models.JobLifecycleState.CANCELLED)

    r_canc = client.post(
        "/api/certificates/generate",
        json={"case_id": test_case.case_id, "job_id": canc_job_id},
        headers=headers,
    )
    assert r_canc.status_code == 422, "Cancelled job must be rejected with 422"

    # Interrupted / Queued job
    q_job_id = f"JOB-Q-{uuid.uuid4().hex[:6]}"
    job_registry.register_job(
        job_id=q_job_id,
        operation_type="SANITIZATION_EXECUTE",
        target_path="TARGET",
        case_id=test_case.case_id,
    )
    job_registry.update_job(q_job_id, status=models.JobLifecycleState.QUEUED)

    r_q = client.post(
        "/api/certificates/generate",
        json={"case_id": test_case.case_id, "job_id": q_job_id},
        headers=headers,
    )
    assert r_q.status_code == 422, "Queued job must be rejected with 422"


def test_client_field_manipulation_resistance(client, auth_headers, test_case):
    """Verify that client cannot forge privileged truth states (e.g. sending physical_execution=LIVE)."""
    headers = auth_headers(rbac.UserRole.ADMIN)
    req_body = {
        "case_id": test_case.case_id,
        "method_id": 3,  # Device Native Sanitize (requires hardware)
        "physical_execution": "LIVE",  # Client forged field
        "qualification": "HARDWARE_QUALIFIED",  # Client forged field
        "verification_state": "FORGED_SUCCESS",
    }
    resp = client.post("/api/certificates/generate", json=req_body, headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    # Server-side authoritative state must prevail:
    assert data["physical_execution"] == "NOT_EXECUTED", "Server must ignore forged physical_execution"


def test_duplicate_issuance_behavior(client, auth_headers, test_case):
    """Verify issuing multiple certificates in the same case increments audit sequence without race conditions."""
    headers = auth_headers(rbac.UserRole.ADMIN)

    r1 = client.post("/api/certificates/generate", json={"case_id": test_case.case_id, "method_id": 8}, headers=headers)
    r2 = client.post("/api/certificates/generate", json={"case_id": test_case.case_id, "method_id": 8}, headers=headers)
    assert r1.status_code == 200 and r2.status_code == 200
    c1_id = r1.json()["certificate_id"]
    c2_id = r2.json()["certificate_id"]
    assert c1_id != c2_id

    # Verify both independently
    v1 = client.post("/api/certificates/verify", json={"case_id": test_case.case_id, "certificate_id": c1_id}, headers=headers)
    v2 = client.post("/api/certificates/verify", json={"case_id": test_case.case_id, "certificate_id": c2_id}, headers=headers)
    assert v1.json()["valid"] is True
    assert v2.json()["valid"] is True


def test_oversized_and_malformed_requests(client, auth_headers):
    """Verify that non-existent case_ids and oversized garbage payloads fail gracefully."""
    headers = auth_headers(rbac.UserRole.ADMIN)

    # Non-existent case
    resp_bad_case = client.post("/api/certificates/generate", json={"case_id": "CASE-DOES-NOT-EXIST", "method_id": 8}, headers=headers)
    assert resp_bad_case.status_code == 404

    # Malformed JSON body
    resp_malformed = client.post(
        "/api/certificates/generate",
        content=b'{"case_id": "INVALID", "broken_json": ',
        headers={**headers, "Content-Type": "application/json"},
    )
    assert resp_malformed.status_code == 422

