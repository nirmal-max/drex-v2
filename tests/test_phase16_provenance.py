"""DREX-V2 Phase 16 Evidence Provenance & Fusion Test Suite
=========================================================
Tests multi-source candidate corroboration, metadata source tracking,
candidate lifecycle state progression, Evidence Vault promotion,
hash-chained audit verification, and certificate attestation binding.
"""

import hashlib
import json
import tempfile
from pathlib import Path
import pytest

from certificate_engine import (
    CertificateMethodInfo,
    CertificateTargetInfo,
    CertificateTruthModel,
    CertificateVerificationInfo,
    ForensicSanitizationCertificate,
)
from forensic_vault import (
    AuditEvent,
    AuditVerificationStatus,
    CaseStatus,
    EvidenceSource,
    EvidenceSourceType,
    EvidenceVault,
    ForensicCase,
    IndependentAuditVerifier,
    RecoveryArtifactRecord,
    RecoveryCandidateState,
    StreamingHasher,
    VaultObjectType,
)
from fragment_engine import CandidateFusionEngine, FusedCandidateRecord
from fs_base import FilesystemKind, FsCandidateRecord, MetadataSource
from validators import CandidateState, EvidenceScores


# ─── 1. Candidate Fusion & Multi-Source Corroboration ──────────────────────────

def test_01_candidate_fusion_identical_sha256_grouping():
    """Verify CandidateFusionEngine groups carver and fs candidates with identical hashes."""
    dummy_payload = b"FORENSIC_EVIDENCE_PAYLOAD_2026"
    cand_hash = hashlib.sha256(dummy_payload).hexdigest()
    
    # Candidate 1 from DeepCarver
    class MockCarvedArtifact:
        def __init__(self):
            self.artifact_id = "CARVE-PDF-001"
            self.file_type = "PDF"
            self.sha256 = cand_hash
            self.data = dummy_payload
            self.confidence = 0.75
            self.state = CandidateState.STRUCTURALLY_VALID
            self.discovery_sources = ["CARVER"]
            self.limitations = []

    # Candidate 2 from Filesystem Recovery
    class MockFsCandidate:
        def __init__(self):
            self.candidate_id = "FS-CAND-002"
            self.filesystem = FilesystemKind.NTFS
            self.output_hash = cand_hash
            self.data = dummy_payload
            self.evidence_confidence_score = 0.85
            self.state = RecoveryCandidateState.VALIDATED_CANDIDATE
            self.limitations = []

    c1 = MockCarvedArtifact()
    c2 = MockFsCandidate()
    
    fused_records = CandidateFusionEngine.fuse_candidates([c1, c2], case_id="CASE_PROV_01")
    assert len(fused_records) == 1
    fused = fused_records[0]
    
    assert fused.sha256 == cand_hash
    assert "CARVER" in fused.discovery_sources
    assert "FILESYSTEM_NTFS" in fused.discovery_sources
    # Corroboration bonus applied: base max (0.85) + 0.05
    assert fused.confidence_score >= 0.90
    assert fused.confidence_factors["source_count"] == 2


def test_02_candidate_fusion_preserves_single_source_without_bonus():
    """Verify single source candidate does not receive unearned corroboration bonus."""
    dummy_payload = b"ISOLATED_CARVED_FRAGMENT"
    cand_hash = hashlib.sha256(dummy_payload).hexdigest()
    
    class MockCarvedArtifact:
        def __init__(self):
            self.artifact_id = "CARVE-JPG-999"
            self.file_type = "JPEG"
            self.sha256 = cand_hash
            self.data = dummy_payload
            self.confidence = 0.70
            self.state = CandidateState.CANDIDATE
            self.discovery_sources = ["CARVER"]
            self.limitations = ["Missing EOI marker"]

    fused_records = CandidateFusionEngine.fuse_candidates([MockCarvedArtifact()])
    assert len(fused_records) == 1
    fused = fused_records[0]
    assert fused.confidence_score == 0.70
    assert fused.confidence_factors["multi_source_corroboration"] == 0.0


# ─── 2. Metadata Source Tracking & Inferred Provenance ────────────────────────

def test_03_metadata_source_provenance_tagging():
    """Verify FsCandidateRecord correctly models metadata provenance sources."""
    rec_ntfs = FsCandidateRecord("c_ntfs", FilesystemKind.NTFS, "file.docx", metadata_source=MetadataSource.NTFS_MFT)
    rec_fat = FsCandidateRecord("c_fat", FilesystemKind.FAT32, "data.csv", metadata_source=MetadataSource.FAT_DIRECTORY_ENTRY)
    rec_ext = FsCandidateRecord("c_ext", FilesystemKind.EXT4, "log.txt", metadata_source=MetadataSource.EXT_INODE)
    rec_inferred = FsCandidateRecord("c_inf", FilesystemKind.FAT32, "orphaned.bin", metadata_source=MetadataSource.INFERRED, is_metadata_inferred=True)
    
    assert rec_ntfs.metadata_source == MetadataSource.NTFS_MFT
    assert rec_ntfs.is_metadata_inferred is False
    assert rec_fat.metadata_source == MetadataSource.FAT_DIRECTORY_ENTRY
    assert rec_ext.metadata_source == MetadataSource.EXT_INODE
    assert rec_inferred.metadata_source == MetadataSource.INFERRED
    assert rec_inferred.is_metadata_inferred is True


# ─── 3. Candidate Lifecycle Progression ───────────────────────────────────────

def test_04_recovery_candidate_lifecycle_states():
    """Verify strict progression across RecoveryCandidateState enum."""
    states = [s.value for s in RecoveryCandidateState]
    assert states == ["CANDIDATE", "VALIDATED_CANDIDATE", "RECONSTRUCTED_CANDIDATE", "RECOVERED_ARTIFACT"]
    
    record = RecoveryArtifactRecord(
        candidate_id="REC-001",
        case_id="CASE-1",
        source_evidence_id="EVID-1",
        source_offset=1024,
        filesystem_origin="NTFS",
        carving_method="STRUCTURE_AWARE",
        reconstruction_method="CONTIGUOUS",
        evidence_confidence_score=0.95,
        validation_state=RecoveryCandidateState.RECOVERED_ARTIFACT,
        output_hash=hashlib.sha256(b"content").hexdigest(),
        output_size=7,
    )
    assert record.validation_state == RecoveryCandidateState.RECOVERED_ARTIFACT
    d = record.to_dict()
    assert d["validation_state"] == "RECOVERED_ARTIFACT"


# ─── 4. Evidence Vault Storage & Categorization ───────────────────────────────

def test_05_evidence_vault_categorized_storage(tmp_path):
    """Verify EvidenceVault segregates objects into SOURCE, DERIVED, RECOVERED, and REPORT dirs."""
    vault = EvidenceVault(tmp_path / "case_vault")
    
    src_file = tmp_path / "recovered_artifact.bin"
    src_file.write_bytes(b"RECOVERED_FORENSIC_DATA")
    
    v_obj = vault.store_file(
        case_id="CASE_TEST",
        source_path=src_file,
        object_type=VaultObjectType.RECOVERED,
        destination_name="artifact_01.bin",
    )
    
    assert v_obj.object_type == VaultObjectType.RECOVERED
    assert (vault.recovered_dir / "artifact_01.bin").exists()
    assert v_obj.sha256_hash == hashlib.sha256(b"RECOVERED_FORENSIC_DATA").hexdigest()
    
    listed = vault.list_objects()
    assert len(listed) == 1
    assert listed[0].object_id == v_obj.object_id


def test_06_evidence_vault_filename_sanitization_and_collision_avoidance(tmp_path):
    """Verify dangerous characters are sanitized and collisions generate unique filenames."""
    vault = EvidenceVault(tmp_path / "case_vault")
    
    src_file1 = tmp_path / "test1.txt"
    src_file1.write_bytes(b"data 1")
    src_file2 = tmp_path / "test2.txt"
    src_file2.write_bytes(b"data 2")
    
    # Store with unsafe filename containing directory traversal chars
    v1 = vault.store_file("CASE_1", src_file1, VaultObjectType.REPORT, destination_name="../../unsafe_report.txt")
    assert ".." not in v1.relative_path
    
    # Store duplicate name
    v2 = vault.store_file("CASE_1", src_file2, VaultObjectType.REPORT, destination_name="unsafe_report.txt")
    assert v1.relative_path != v2.relative_path


# ─── 5. Hash-Chained Audit Ledger Verification ────────────────────────────────

def test_07_audit_ledger_hash_chain_integrity():
    """Verify SHA-256 hash chaining detects untampered ledger events."""
    e0 = AuditEvent.create(
        sequence_number=0,
        case_id="CASE_AUDIT",
        actor="ForensicAnalyst_01",
        event_type="RECOVERY_STARTED",
        payload={"candidate_count": 5},
        previous_hash="0" * 64,
    )
    e1 = AuditEvent.create(
        sequence_number=1,
        case_id="CASE_AUDIT",
        actor="ForensicAnalyst_01",
        event_type="RECOVERY_COMPLETED",
        payload={"recovered_count": 5, "verified": True},
        previous_hash=e0.current_hash,
    )
    
    events = [e0, e1]
    res = IndependentAuditVerifier.verify_chain(events)
    assert res.status == AuditVerificationStatus.VALID
    assert res.verified_events == 2


def test_08_audit_ledger_detects_tampered_payload():
    """Verify IndependentAuditVerifier flags TAMPERED_EVENT if payload data is altered."""
    e0 = AuditEvent.create(0, "CASE_T", "Examiner", "ACQUIRED", {"size": 100}, "0" * 64)
    e1 = AuditEvent.create(1, "CASE_T", "Examiner", "VERIFIED", {"status": "OK"}, e0.current_hash)
    
    events = [e0, e1]
    # Tamper with payload of first event
    events[0].canonical_payload["size"] = 999999
    
    res = IndependentAuditVerifier.verify_chain(events)
    assert res.status in (AuditVerificationStatus.TAMPERED_EVENT, AuditVerificationStatus.BROKEN_CHAIN, AuditVerificationStatus.INVALID)


# ─── 6. Certificate Attestation Binding ───────────────────────────────────────

def test_09_certificate_truth_model_and_attestation():
    """Verify ForensicSanitizationCertificate binds truth model and cryptographic digests."""
    cert = ForensicSanitizationCertificate(
        certificate_id="CERT-2026-001",
        case_id="CASE-CERT-01",
        target=CertificateTargetInfo(
            target_name="SanitizedEvidenceDrive",
            target_type="DRIVE",
            capacity_bytes=1024 * 1024 * 1024,
        ),
        method=CertificateMethodInfo(
            method_id=1,
            canonical_name="NIST 800-88 Clear",
            standard_reference="NIST SP 800-88 Rev. 2 aligned",
        ),
        verification=CertificateVerificationInfo(
            primary_verification_method="EXACT_BYTE_READBACK",
            exact_readback_verified=True,
            post_wipe_sha256=hashlib.sha256(b"\x00" * 1024).hexdigest(),
        ),
        truth_model=CertificateTruthModel(
            execution="REAL",
            verification="EXACT_READBACK",
            qualification="SOFTWARE-QUALIFIED",
        ),
    )
    
    assert cert.certificate_id == "CERT-2026-001"
    assert cert.truth_model.execution == "REAL"
    assert cert.truth_model.qualification == "SOFTWARE-QUALIFIED"
    assert cert.verification.exact_readback_verified is True


# ─── 7. Streaming Cryptographic Hasher ────────────────────────────────────────

def test_10_streaming_hasher_matches_standard_hashlib(tmp_path):
    """Verify StreamingHasher produces identical SHA-256 and SHA-512 hashes as hashlib."""
    import os
    test_file = tmp_path / "stream_test.dat"
    raw_data = os.urandom(256 * 1024)  # 256 KB
    test_file.write_bytes(raw_data)
    
    sha256_expected = hashlib.sha256(raw_data).hexdigest()
    sha512_expected = hashlib.sha512(raw_data).hexdigest()
    
    rec_sha256 = StreamingHasher.hash_file(test_file, algorithm="sha256")
    rec_sha512 = StreamingHasher.hash_file(test_file, algorithm="sha512")
    
    assert rec_sha256.digest == sha256_expected
    assert rec_sha256.byte_count == len(raw_data)
    assert rec_sha512.digest == sha512_expected
    assert rec_sha512.byte_count == len(raw_data)
