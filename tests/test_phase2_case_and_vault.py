"""
DREX-V2 Phase 2 Forensic Subsystem Tests
========================================
Comprehensive test suite covering:
- Case Management lifecycle (creation, status transitions, persistence)
- Evidence Sources (registration, unknown hardware handling, hashing)
- Streaming Cryptographic Hasher (SHA-256/SHA-512, chunked memory bounds)
- Forensic Timeline (chronological events, integrity verification)
- Hash-Chained Audit Ledger (SHA-256 hash chaining, independent audit verifier)
- Tamper Detection (payload mutations, altered prev_hash, broken sequence, deleted/inserted events)
- Chain of Custody (intake, transfer, access, sealing, immutable history)
- Evidence Vault (categorized object isolation: SOURCE, DERIVED, RECOVERED, REPORT, CERTIFICATE, AUDIT)
- Recovery & Sanitization Provenance (candidate tracking, confidence scores, evidence records)
- Case Package Export & Import (manifest validation, corruption rejection, path-traversal safety)
- Crash Safety & Concurrency (atomic writes, multi-threaded operations)
"""

import copy
import io
import json
import os
import shutil
import tarfile
import tempfile
import threading
from pathlib import Path
from typing import List

import pytest

from forensic_vault import (
    ForensicCase,
    ForensicCaseManager,
    EvidenceSource,
    EvidenceSourceType,
    CaseStatus,
    StreamingHasher,
    ForensicTimelineEvent,
    TimelineEventType,
    AuditEvent,
    AuditVerificationStatus,
    IndependentAuditVerifier,
    ChainOfCustodyRecord,
    CustodyAction,
    CustodyVerificationStatus,
    CustodyVerificationResult,
    IndependentCustodyVerifier,
    EvidenceVault,
    VaultObjectType,
    VaultObject,
    RecoveryArtifactRecord,
    RecoveryCandidateState,
    SanitizationProvenanceRecord,
    CasePackageManager,
    PackageValidationStatus,
    canonical_json_bytes,
    safe_atomic_json_write,
    safe_atomic_write,
    sanitize_filename,
    compute_event_hash,
)


@pytest.fixture
def vault_env(tmp_path: Path) -> ForensicCaseManager:
    """Fixture providing an isolated ForensicCaseManager workspace."""
    base_dir = tmp_path / "drex_vault_test"
    base_dir.mkdir(parents=True, exist_ok=True)
    return ForensicCaseManager(base_dir)


# ─── 1. Case Lifecycle Tests ──────────────────────────────────────────────────

class TestCaseLifecycle:
    def test_create_and_retrieve_case(self, vault_env: ForensicCaseManager):
        case = vault_env.create_case(
            case_number="CR-2026-0042",
            title="Operation Digital Fortress",
            examiner="Detective Sharma",
            organization="Cyber Crime Division",
            description="Forensic investigation into unauthorized data exfiltration.",
            classification="LAW_ENFORCEMENT",
            tags=["exfiltration", "nvme", "priority_alpha"],
        )

        assert case.case_id.startswith("CASE-")
        assert case.case_number == "CR-2026-0042"
        assert case.status == CaseStatus.OPEN
        assert case.classification == "LAW_ENFORCEMENT"
        assert "exfiltration" in case.tags

        # Verify retrieval
        retrieved = vault_env.get_case(case.case_id)
        assert retrieved is not None
        assert retrieved.case_id == case.case_id
        assert retrieved.title == case.title
        assert retrieved.examiner == "Detective Sharma"

    def test_case_status_transitions(self, vault_env: ForensicCaseManager):
        case = vault_env.create_case(
            case_number="CR-2026-0099",
            title="Status Transition Test",
            examiner="Lead Forensic Specialist",
            organization="Forensics Lab",
        )
        assert case.status == CaseStatus.OPEN

        # OPEN -> ACTIVE -> PAUSED -> CLOSED -> ARCHIVED
        for target_status in (CaseStatus.ACTIVE, CaseStatus.PAUSED, CaseStatus.CLOSED, CaseStatus.ARCHIVED):
            updated = vault_env.update_case_status(case.case_id, target_status, actor="Lead Specialist")
            assert updated.status == target_status
            fetched = vault_env.get_case(case.case_id)
            assert fetched.status == target_status

    def test_list_multiple_cases(self, vault_env: ForensicCaseManager):
        c1 = vault_env.create_case("C-01", "Case One", "Examiner 1", "Org")
        c2 = vault_env.create_case("C-02", "Case Two", "Examiner 2", "Org")
        cases = vault_env.list_cases()
        assert len(cases) >= 2
        ids = [c.case_id for c in cases]
        assert c1.case_id in ids
        assert c2.case_id in ids


# ─── 2. Evidence Source Tests ─────────────────────────────────────────────────

class TestEvidenceSource:
    def test_register_file_evidence_computes_source_hash(self, vault_env: ForensicCaseManager, tmp_path: Path):
        case = vault_env.create_case("C-EV-01", "Evidence Test", "Examiner", "Org")

        # Create a sample evidence file
        ev_file = tmp_path / "seized_document.pdf"
        sample_data = b"%PDF-1.4 authentic evidence payload byte stream\n%%EOF"
        ev_file.write_bytes(sample_data)

        ev_source = vault_env.register_evidence(
            case_id=case.case_id,
            source_type=EvidenceSourceType.FILE,
            source_path=str(ev_file),
            examiner="Inspector Verma",
            provenance="Seized from suspect workstation",
        )

        assert ev_source.evidence_id.startswith("EVID-")
        assert ev_source.case_id == case.case_id
        assert ev_source.source_type == EvidenceSourceType.FILE
        assert ev_source.source_hash is not None

        # Verify hash matches independent calculation
        expected_hash = StreamingHasher.hash_file(ev_file).digest
        assert ev_source.source_hash == expected_hash

    def test_register_device_evidence_preserves_unknown_fields(self, vault_env: ForensicCaseManager):
        case = vault_env.create_case("C-EV-02", "Device Evidence Test", "Examiner", "Org")

        # Register physical device with some unknown hardware metadata
        ev_source = vault_env.register_evidence(
            case_id=case.case_id,
            source_type=EvidenceSourceType.PHYSICAL_DEVICE,
            source_path=r"\\.\PhysicalDrive2",
            examiner="Examiner",
            device_identity="PhysicalDrive2",
            model="SanDisk Ultra",
            serial=None,  # Unknown serial
            transport="USB",
            capacity=64_000_000_000,
            filesystem=None,  # Unknown filesystem
        )

        assert ev_source.serial is None
        assert ev_source.filesystem is None
        assert ev_source.transport == "USB"
        assert ev_source.capacity == 64_000_000_000

        # Verify listed evidence
        ev_list = vault_env.list_evidence(case.case_id)
        assert len(ev_list) == 1
        assert ev_list[0].evidence_id == ev_source.evidence_id


# ─── 3. Streaming Cryptographic Hasher Tests ──────────────────────────────────

class TestStreamingCryptographicHasher:
    def test_streaming_sha256_known_answer(self, tmp_path: Path):
        test_file = tmp_path / "known_string.txt"
        test_file.write_bytes(b"DREX-V2 Forensic Verification Stream 2026")

        h_rec = StreamingHasher.hash_file(test_file, algorithm="sha256")
        assert h_rec.algorithm == "sha256"
        assert h_rec.byte_count == len(b"DREX-V2 Forensic Verification Stream 2026")
        assert len(h_rec.digest) == 64

        import hashlib
        expected = hashlib.sha256(b"DREX-V2 Forensic Verification Stream 2026").hexdigest()
        assert h_rec.digest == expected

    def test_streaming_sha512_known_answer(self, tmp_path: Path):
        test_file = tmp_path / "sha512_test.bin"
        test_file.write_bytes(b"SHA512 Extended Forensic Integrity Block")

        h_rec = StreamingHasher.hash_file(test_file, algorithm="sha512")
        assert h_rec.algorithm == "sha512"
        assert len(h_rec.digest) == 128

        import hashlib
        expected = hashlib.sha512(b"SHA512 Extended Forensic Integrity Block").hexdigest()
        assert h_rec.digest == expected

    def test_large_fixture_streaming_memory_bounds(self, tmp_path: Path):
        # Create a 2 MB synthetic stream with repeating patterns
        test_file = tmp_path / "large_stream.raw"
        chunk_pattern = b"A" * 65536  # 64 KB
        with open(test_file, "wb") as f:
            for _ in range(32):  # 32 * 64 KB = 2097152 bytes (2 MB)
                f.write(chunk_pattern)

        callback_counts = []

        def on_progress(bytes_done: int):
            callback_counts.append(bytes_done)

        h_rec = StreamingHasher.hash_file(test_file, chunk_size=32768, progress_callback=on_progress)
        assert h_rec.byte_count == 2 * 1024 * 1024
        assert len(callback_counts) == 64  # 2 MB / 32 KB = 64 chunks
        assert callback_counts[-1] == 2 * 1024 * 1024


# ─── 4. Forensic Timeline Tests ───────────────────────────────────────────────

class TestForensicTimeline:
    def test_timeline_chronology_and_integrity_hashes(self, vault_env: ForensicCaseManager):
        case = vault_env.create_case("C-TL-01", "Timeline Test", "Detective Sharma", "Org")

        # Adding evidence generates timeline event
        vault_env.register_evidence(
            case_id=case.case_id,
            source_type=EvidenceSourceType.DISK_IMAGE,
            source_path="/images/disk.raw",
            examiner="Detective Sharma",
        )

        # Updating status generates timeline event
        vault_env.update_case_status(case.case_id, CaseStatus.ACTIVE, actor="Detective Sharma")

        timeline = vault_env.get_timeline(case.case_id)
        assert len(timeline) >= 3  # CASE_CREATED, EVIDENCE_ADDED, CASE_UPDATED (+ CUSTODY_CHANGE)

        # Verify all timeline events have valid calculated integrity hashes
        for evt in timeline:
            assert evt.integrity_hash != ""
            assert evt.integrity_hash == evt.calculate_integrity_hash()


# ─── 5. Hash-Chained Audit & Tamper Detection Tests ───────────────────────────

class TestHashChainedAuditAndTamperDetection:
    def test_valid_audit_chain_verification(self, vault_env: ForensicCaseManager):
        case = vault_env.create_case("C-AUD-01", "Audit Test", "Examiner", "Org")

        # Perform mutations that record audit events
        vault_env.register_evidence(case.case_id, EvidenceSourceType.FILE, "/path/1", "Examiner")
        vault_env.update_case_status(case.case_id, CaseStatus.ACTIVE, actor="Examiner")
        vault_env.update_case_status(case.case_id, CaseStatus.CLOSED, actor="Examiner")

        chain = vault_env.get_audit_chain(case.case_id)
        assert len(chain) >= 4

        # Genesis event check
        assert chain[0].previous_hash == IndependentAuditVerifier.GENESIS_HASH

        # Verify cryptographic link: H_i = SHA256(H_{i-1} || canonical(payload_i))
        for i in range(1, len(chain)):
            assert chain[i].previous_hash == chain[i - 1].current_hash

        # Run independent verification
        res = vault_env.verify_case_audit_chain(case.case_id)
        assert res.status == AuditVerificationStatus.VALID
        assert res.total_events == len(chain)
        assert res.verified_events == len(chain)

    def test_tamper_detection_modified_payload(self, vault_env: ForensicCaseManager):
        case = vault_env.create_case("C-TAMPER-01", "Tamper Test 1", "Examiner", "Org")
        vault_env.update_case_status(case.case_id, CaseStatus.ACTIVE, actor="Examiner")

        chain = vault_env.get_audit_chain(case.case_id)
        assert len(chain) >= 2

        # Maliciously modify payload of event 1
        tampered_chain = [copy.deepcopy(e) for e in chain]
        tampered_chain[1].canonical_payload["malicious_field"] = "forged_data"

        res = IndependentAuditVerifier.verify_chain(tampered_chain)
        assert res.status == AuditVerificationStatus.TAMPERED_EVENT
        assert res.broken_sequence_index == 1
        assert "Tampered event payload" in res.error_message

    def test_tamper_detection_modified_prev_hash(self, vault_env: ForensicCaseManager):
        case = vault_env.create_case("C-TAMPER-02", "Tamper Test 2", "Examiner", "Org")
        vault_env.update_case_status(case.case_id, CaseStatus.ACTIVE, actor="Examiner")

        chain = vault_env.get_audit_chain(case.case_id)
        tampered_chain = [copy.deepcopy(e) for e in chain]
        tampered_chain[1].previous_hash = "f" * 64  # Corrupted previous hash

        res = IndependentAuditVerifier.verify_chain(tampered_chain)
        assert res.status == AuditVerificationStatus.BROKEN_CHAIN
        assert res.broken_sequence_index == 1
        assert "Previous hash mismatch" in res.error_message

    def test_tamper_detection_deleted_event(self, vault_env: ForensicCaseManager):
        case = vault_env.create_case("C-TAMPER-03", "Tamper Test 3", "Examiner", "Org")
        vault_env.update_case_status(case.case_id, CaseStatus.ACTIVE, actor="Examiner")
        vault_env.update_case_status(case.case_id, CaseStatus.CLOSED, actor="Examiner")

        chain = vault_env.get_audit_chain(case.case_id)
        assert len(chain) == 3

        # Delete intermediate event (index 1)
        tampered_chain = [chain[0], chain[2]]

        res = IndependentAuditVerifier.verify_chain(tampered_chain)
        # Sequence number at index 1 is now 2 (broken sequence)
        assert res.status == AuditVerificationStatus.BROKEN_CHAIN
        assert res.broken_sequence_index == 1

    def test_tamper_detection_inserted_event(self, vault_env: ForensicCaseManager):
        case = vault_env.create_case("C-TAMPER-05", "Tamper Test 5", "Examiner", "Org")
        vault_env.update_case_status(case.case_id, CaseStatus.ACTIVE, actor="Examiner")
        chain = vault_env.get_audit_chain(case.case_id)

        # Forge an inserted event
        inserted = AuditEvent.create(
            sequence_number=1,
            case_id=case.case_id,
            actor="Attacker",
            event_type="UNAUTHORIZED_MUTATION",
            payload={"injected": True},
            previous_hash=chain[0].current_hash,
        )
        tampered_chain = [chain[0], inserted, chain[1]]
        res = IndependentAuditVerifier.verify_chain(tampered_chain)
        assert res.status == AuditVerificationStatus.BROKEN_CHAIN
        assert res.broken_sequence_index == 2

    def test_tamper_detection_modified_case_id(self, vault_env: ForensicCaseManager):
        case = vault_env.create_case("C-TAMPER-06", "Tamper Test 6", "Examiner", "Org")
        chain = vault_env.get_audit_chain(case.case_id)
        tampered = [copy.deepcopy(e) for e in chain]
        tampered[0].case_id = "CASE-FORGED-9999"

        res = IndependentAuditVerifier.verify_chain(tampered)
        assert res.status == AuditVerificationStatus.TAMPERED_EVENT
        assert res.broken_sequence_index == 0

    def test_tamper_detection_modified_operation_id(self, vault_env: ForensicCaseManager):
        case = vault_env.create_case("C-TAMPER-07", "Tamper Test 7", "Examiner", "Org")
        vault_env.record_recovery_event(case.case_id, "OP-ORIG-01", "EVID-01", "Examiner", TimelineEventType.RECOVERY_COMPLETED, "Recovery done")
        chain = vault_env.get_audit_chain(case.case_id)
        tampered = [copy.deepcopy(e) for e in chain]
        tampered[-1].operation_id = "OP-FORGED-99"

        res = IndependentAuditVerifier.verify_chain(tampered)
        assert res.status == AuditVerificationStatus.TAMPERED_EVENT

    def test_tamper_detection_modified_timestamp(self, vault_env: ForensicCaseManager):
        case = vault_env.create_case("C-TAMPER-08", "Tamper Test 8", "Examiner", "Org")
        chain = vault_env.get_audit_chain(case.case_id)
        tampered = [copy.deepcopy(e) for e in chain]
        tampered[0].timestamp = "1999-01-01T00:00:00Z"

        res = IndependentAuditVerifier.verify_chain(tampered)
        assert res.status == AuditVerificationStatus.TAMPERED_EVENT

    def test_tamper_detection_modified_actor_or_event_type(self, vault_env: ForensicCaseManager):
        case = vault_env.create_case("C-TAMPER-09", "Tamper Test 9", "Examiner", "Org")
        chain = vault_env.get_audit_chain(case.case_id)
        tampered = [copy.deepcopy(e) for e in chain]
        tampered[0].actor = "MaliciousAttacker"

        res = IndependentAuditVerifier.verify_chain(tampered)
        assert res.status == AuditVerificationStatus.TAMPERED_EVENT


# ─── 6. Chain of Custody Tests ────────────────────────────────────────────────

class TestChainOfCustody:
    def test_all_eight_custody_actions_lifecycle(self, vault_env: ForensicCaseManager):
        case = vault_env.create_case("C-CUST-01", "Custody Test", "Officer A", "Police Dept")
        ev = vault_env.register_evidence(
            case_id=case.case_id,
            source_type=EvidenceSourceType.PHYSICAL_DEVICE,
            source_path=r"\\.\PhysicalDrive1",
            examiner="Officer A",
        )

        all_actions = [
            CustodyAction.RECEIVED,
            CustodyAction.TRANSFERRED,
            CustodyAction.ACCESSED,
            CustodyAction.COPIED,
            CustodyAction.ANALYZED,
            CustodyAction.EXPORTED,
            CustodyAction.SEALED,
            CustodyAction.RELEASED,
        ]

        for act in all_actions:
            rec = vault_env.record_custody_event(
                evidence_id=ev.evidence_id,
                case_id=case.case_id,
                custodian="Examiner Jones",
                action=act,
                reason=f"Action {act.value} verification",
                source_location="Lab A",
                destination="Lab B",
                hash_before="a" * 64,
                hash_after="b" * 64,
            )
            assert rec.action == act
            assert rec.integrity_reference == rec.calculate_integrity()

        # Independent verification of full custody chain
        v_res = vault_env.verify_case_custody(case.case_id)
        assert v_res.status == CustodyVerificationStatus.VALID
        assert v_res.total_records >= len(all_actions)

    def test_custody_tamper_modified_custodian(self, vault_env: ForensicCaseManager):
        case = vault_env.create_case("C-CUST-TAMPER-01", "Tamper Custody 1", "Officer A", "Police")
        ev = vault_env.register_evidence(case.case_id, EvidenceSourceType.FILE, "/path/1", "Officer A")
        records = vault_env.list_custody_records(case.case_id)
        tampered = [copy.deepcopy(r) for r in records]
        tampered[0].custodian = "Attacker"

        res = IndependentCustodyVerifier.verify_custody_records(tampered)
        assert res.status == CustodyVerificationStatus.TAMPERED_RECORD
        assert "Tampered custody record" in res.error_message

    def test_custody_tamper_modified_action(self, vault_env: ForensicCaseManager):
        case = vault_env.create_case("C-CUST-TAMPER-02", "Tamper Custody 2", "Officer A", "Police")
        ev = vault_env.register_evidence(case.case_id, EvidenceSourceType.FILE, "/path/1", "Officer A")
        records = vault_env.list_custody_records(case.case_id)
        tampered = [copy.deepcopy(r) for r in records]
        tampered[0].action = CustodyAction.RELEASED

        res = IndependentCustodyVerifier.verify_custody_records(tampered)
        assert res.status == CustodyVerificationStatus.TAMPERED_RECORD

    def test_custody_tamper_modified_timestamp(self, vault_env: ForensicCaseManager):
        case = vault_env.create_case("C-CUST-TAMPER-03", "Tamper Custody 3", "Officer A", "Police")
        ev = vault_env.register_evidence(case.case_id, EvidenceSourceType.FILE, "/path/1", "Officer A")
        records = vault_env.list_custody_records(case.case_id)
        tampered = [copy.deepcopy(r) for r in records]
        tampered[0].timestamp = "2000-01-01T00:00:00Z"

        res = IndependentCustodyVerifier.verify_custody_records(tampered)
        assert res.status == CustodyVerificationStatus.TAMPERED_RECORD

    def test_custody_tamper_modified_evidence_id(self, vault_env: ForensicCaseManager):
        case = vault_env.create_case("C-CUST-TAMPER-04", "Tamper Custody 4", "Officer A", "Police")
        ev = vault_env.register_evidence(case.case_id, EvidenceSourceType.FILE, "/path/1", "Officer A")
        records = vault_env.list_custody_records(case.case_id)
        tampered = [copy.deepcopy(r) for r in records]
        tampered[0].evidence_id = "EVID-FORGED-01"

        res = IndependentCustodyVerifier.verify_custody_records(tampered)
        assert res.status == CustodyVerificationStatus.TAMPERED_RECORD

    def test_custody_tamper_deleted_or_reordered_event(self, vault_env: ForensicCaseManager):
        case = vault_env.create_case("C-CUST-TAMPER-05", "Tamper Custody 5", "Officer A", "Police")
        ev = vault_env.register_evidence(case.case_id, EvidenceSourceType.FILE, "/path/1", "Officer A")
        vault_env.record_custody_event(ev.evidence_id, case.case_id, "Specialist B", CustodyAction.TRANSFERRED, "Transfer", "Locker", "Desk")
        vault_env.record_custody_event(ev.evidence_id, case.case_id, "Specialist B", CustodyAction.ANALYZED, "Analysis", "Desk", "Desk")

        records = vault_env.list_custody_records(case.case_id)
        audits = vault_env.get_audit_chain(case.case_id)

        # 1. Deleted record
        deleted_records = [records[0], records[2]]
        res_del = IndependentCustodyVerifier.verify_custody_records(deleted_records, audits)
        assert res_del.status == CustodyVerificationStatus.AUDIT_MISMATCH

        # 2. Reordered records
        reordered_records = [records[1], records[0], records[2]]
        res_reord = IndependentCustodyVerifier.verify_custody_records(reordered_records, audits)
        assert res_reord.status == CustodyVerificationStatus.AUDIT_MISMATCH


# ─── 7. Evidence Vault Categorization Tests ───────────────────────────────────

class TestEvidenceVault:
    def test_vault_object_storage_and_categorization(self, vault_env: ForensicCaseManager, tmp_path: Path):
        case = vault_env.create_case("C-VLT-01", "Vault Test", "Examiner", "Org")
        cdir = vault_env._case_path(case.case_id)
        vault = EvidenceVault(cdir)

        # Create sample files for different categories
        src_file = tmp_path / "raw_image.bin"
        src_file.write_bytes(b"RAW DISK SECTORS" * 100)

        rec_file = tmp_path / "carved_image.jpg"
        rec_file.write_bytes(b"\xff\xd8\xff\xe0" + b"\x00" * 50 + b"\xff\xd9")

        # Store in vault
        v_src = vault.store_file(case.case_id, src_file, VaultObjectType.SOURCE, "source_disk.bin")
        v_rec = vault.store_file(case.case_id, rec_file, VaultObjectType.RECOVERED, "recovered_photo.jpg")

        assert v_src.object_type == VaultObjectType.SOURCE
        assert v_rec.object_type == VaultObjectType.RECOVERED

        # Verify physical directory locations
        assert (vault.source_dir / "source_disk.bin").is_file()
        assert (vault.recovered_dir / "recovered_photo.jpg").is_file()

        objects = vault.list_objects()
        assert len(objects) == 2

    def test_vault_duplicate_name_collision_handling(self, vault_env: ForensicCaseManager, tmp_path: Path):
        case = vault_env.create_case("C-VLT-02", "Collision Test", "Examiner", "Org")
        cdir = vault_env._case_path(case.case_id)
        vault = EvidenceVault(cdir)

        sample = tmp_path / "file.txt"
        sample.write_bytes(b"content 1")
        vault.store_file(case.case_id, sample, VaultObjectType.DERIVED, "file.txt")

        sample2 = tmp_path / "file.txt"
        sample2.write_bytes(b"content 2")
        # Store with same name: must not overwrite, must generate unique name
        vault.store_file(case.case_id, sample2, VaultObjectType.DERIVED, "file.txt")

        objects = vault.list_objects()
        assert len(objects) == 2
        assert objects[0].relative_path != objects[1].relative_path


# ─── 8. Recovery & Sanitization Provenance Tests ───────────────────────────────

class TestProvenanceRecords:
    def test_recovery_artifact_record_dataclass(self):
        rec = RecoveryArtifactRecord(
            candidate_id="cand-001",
            case_id="CASE-2026-01",
            source_evidence_id="EVID-001",
            source_offset=512000,
            filesystem_origin="NTFS",
            carving_method="FormatValidator.validate_png",
            reconstruction_method="FragmentReassembler",
            evidence_confidence_score=0.95,
            validation_state=RecoveryCandidateState.VALIDATED_CANDIDATE,
            output_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            output_size=4096,
        )
        assert rec.validation_state == RecoveryCandidateState.VALIDATED_CANDIDATE
        assert rec.evidence_confidence_score == 0.95

        d = rec.to_dict()
        assert d["validation_state"] == "VALIDATED_CANDIDATE"

        reconstructed = RecoveryArtifactRecord.from_dict(d)
        assert reconstructed.candidate_id == "cand-001"
        assert reconstructed.validation_state == RecoveryCandidateState.VALIDATED_CANDIDATE

    def test_recovery_artifact_full_lifecycle_and_persistence(self, vault_env: ForensicCaseManager, tmp_path: Path):
        case = vault_env.create_case("C-REC-PROV-01", "Recovery Provenance", "Examiner", "Lab")
        ev = vault_env.register_evidence(case.case_id, EvidenceSourceType.DISK_IMAGE, "/disk.raw", "Examiner")

        # Lifecycle: CANDIDATE -> VALIDATED_CANDIDATE -> RECONSTRUCTED_CANDIDATE -> RECOVERED_ARTIFACT
        states = [
            RecoveryCandidateState.CANDIDATE,
            RecoveryCandidateState.VALIDATED_CANDIDATE,
            RecoveryCandidateState.RECONSTRUCTED_CANDIDATE,
            RecoveryCandidateState.RECOVERED_ARTIFACT,
        ]

        for idx, st in enumerate(states):
            art = RecoveryArtifactRecord(
                candidate_id=f"cand-{idx:03d}",
                case_id=case.case_id,
                source_evidence_id=ev.evidence_id,
                source_offset=idx * 1024 * 1024,
                filesystem_origin="NTFS",
                carving_method="DeepCarverEngine.carve",
                reconstruction_method="FragmentReassembler.reassemble",
                evidence_confidence_score=0.90 + (idx * 0.02),
                validation_state=st,
                output_hash=f"hash_{idx}" * 8,
                output_size=1024 * (idx + 1),
                limitations=["CLUSTER_CONTIGUITY: NON_CONTIGUOUS_VALIDATED"],
            )
            saved = vault_env.record_recovery_artifact(case.case_id, art, actor="Lead Examiner")
            assert saved.validation_state == st

        # Reload from persistence
        persisted = vault_env.list_recovery_artifacts(case.case_id)
        assert len(persisted) == 4
        assert persisted[-1].validation_state == RecoveryCandidateState.RECOVERED_ARTIFACT
        assert persisted[-1].limitations == ["CLUSTER_CONTIGUITY: NON_CONTIGUOUS_VALIDATED"]

        # Export and import verification
        cdir = vault_env._case_path(case.case_id)
        pkg_path = tmp_path / "rec_case_pkg.tar.gz"
        CasePackageManager.export_package(cdir, pkg_path)
        dest_vault = tmp_path / "imported_rec_vault"
        res = CasePackageManager.validate_and_import(pkg_path, dest_vault)
        assert res.status == PackageValidationStatus.VALID

    def test_sanitization_provenance_record_dataclass(self):
        rec = SanitizationProvenanceRecord(
            operation_id="op-san-001",
            case_id="CASE-2026-01",
            evidence_id="EVID-002",
            device_identity="PhysicalDrive1",
            transport="SATA",
            method_id="ata",
            method_name="ATA Secure Erase",
            capability_state="SUPPORTED",
            execution_backend="NativeHardwareEngine",
            execution_status="SIMULATION_QUALIFIED",
            verification_method="ShannonEntropyEngine",
            verification_result="VERIFIED",
            evidence_data={"mean_entropy": 7.999},
            limitations=["PHYSICAL_HARDWARE_QUALIFICATION: PENDING"],
            safety_checks=["Boot disk protection verified", "Freeze state checked"],
            confirmation_state=True,
            started_at="2026-09-14T00:00:00Z",
            completed_at="2026-09-14T00:00:05Z",
        )
        assert rec.execution_status == "SIMULATION_QUALIFIED"
        assert rec.verification_result == "VERIFIED"

    def test_sanitization_provenance_truth_states_and_persistence(self, vault_env: ForensicCaseManager):
        case = vault_env.create_case("C-SAN-PROV-01", "Sanitization Provenance", "Examiner", "Lab")
        ev = vault_env.register_evidence(case.case_id, EvidenceSourceType.PHYSICAL_DEVICE, r"\\.\PhysicalDrive3", "Examiner")

        truth_statuses = [
            ("SUCCESS", "VERIFIED"),
            ("SIMULATION_QUALIFIED", "VERIFIED"),
            ("PARTIAL", "PARTIAL"),
            ("FAILED", "NOT_EXECUTED"),
            ("EXECUTION_BLOCKED", "NOT_EXECUTED"),
        ]

        for idx, (status, verif) in enumerate(truth_statuses):
            rec = SanitizationProvenanceRecord(
                operation_id=f"op-san-{idx:03d}",
                case_id=case.case_id,
                evidence_id=ev.evidence_id,
                device_identity="PhysicalDrive3",
                transport="NVMe",
                method_id="nvme_crypto_scramble",
                method_name="NVMe Format Cryptographic Erase",
                capability_state="SUPPORTED",
                execution_backend="NativeHardwareEngine",
                execution_status=status,
                verification_method="ShannonEntropyEngine",
                verification_result=verif,
                evidence_data={"test_idx": idx},
                limitations=["PHYSICAL_HARDWARE_QUALIFICATION: PENDING"],
                safety_checks=["Safety interlock confirmed"],
                confirmation_state=True,
                started_at="2026-09-14T01:00:00Z",
                completed_at="2026-09-14T01:00:02Z",
            )
            vault_env.record_sanitization_provenance(case.case_id, rec, actor="Examiner")

        # Verify listed records
        san_list = vault_env.list_sanitization_provenance(case.case_id)
        assert len(san_list) == len(truth_statuses)
        assert san_list[0].execution_status == "SUCCESS"
        assert san_list[1].execution_status == "SIMULATION_QUALIFIED"
        assert san_list[2].execution_status == "PARTIAL"


# ─── 9. Case Package Export & Import Integrity Tests ──────────────────────────

class TestCasePackageExportAndImport:
    def test_export_and_import_valid_case_package(self, vault_env: ForensicCaseManager, tmp_path: Path):
        case = vault_env.create_case("C-EXP-01", "Exportable Case", "Examiner A", "Cyber Lab")
        ev_file = tmp_path / "sample_doc.txt"
        ev_file.write_bytes(b"Sample case evidence text data")
        vault_env.register_evidence(case.case_id, EvidenceSourceType.FILE, str(ev_file), "Examiner A")

        cdir = vault_env._case_path(case.case_id)
        vault = EvidenceVault(cdir)
        vault.store_file(case.case_id, ev_file, VaultObjectType.RECOVERED, "doc.txt")

        pkg_path = tmp_path / "case_export.drex.tar.gz"
        CasePackageManager.export_package(cdir, pkg_path)
        assert pkg_path.is_file()

        import_vault_dir = tmp_path / "imported_vault"
        res = CasePackageManager.validate_and_import(pkg_path, import_vault_dir)

        assert res.status == PackageValidationStatus.VALID
        assert res.manifest_valid is True
        assert res.audit_chain_valid is True
        assert res.objects_corrupted == 0
        assert (import_vault_dir / case.case_id / "case.json").is_file()

    def test_import_detects_corrupted_object_in_package(self, vault_env: ForensicCaseManager, tmp_path: Path):
        case = vault_env.create_case("C-EXP-02", "Corruption Test", "Examiner", "Org")
        cdir = vault_env._case_path(case.case_id)
        pkg_path = tmp_path / "corrupted_pkg.drex.tar.gz"
        CasePackageManager.export_package(cdir, pkg_path)

        tamper_dir = tmp_path / "tamper_scratch"
        tamper_dir.mkdir()
        with tarfile.open(pkg_path, "r:gz") as tar:
            tar.extractall(tamper_dir)

        case_json_file = tamper_dir / "case.json"
        case_json_file.write_text("Corrupted content that does not match manifest hash", encoding="utf-8")

        tampered_pkg = tmp_path / "tampered.drex.tar.gz"
        with tarfile.open(tampered_pkg, "w:gz") as tar:
            for f in sorted(tamper_dir.rglob("*")):
                if f.is_file():
                    tar.add(f, arcname=f.relative_to(tamper_dir).as_posix())

        dest_vault = tmp_path / "dest_vault"
        res = CasePackageManager.validate_and_import(tampered_pkg, dest_vault)
        assert res.status == PackageValidationStatus.CORRUPTED_OBJECT
        assert res.objects_corrupted >= 1

    def test_import_detects_path_traversal_attack(self, tmp_path: Path):
        evil_tar = tmp_path / "evil_traversal.tar.gz"
        with tarfile.open(evil_tar, "w:gz") as tar:
            data = b"malicious script"
            ti = tarfile.TarInfo(name="../../windows/system32/evil.dll")
            ti.size = len(data)
            tar.addfile(ti, io.BytesIO(data))

        dest_vault = tmp_path / "safe_dest"
        res = CasePackageManager.validate_and_import(evil_tar, dest_vault)
        assert res.status == PackageValidationStatus.UNSAFE_PATH
        assert "unsafe path detected" in res.error_message

    def test_windows_unc_and_drive_traversal_attack(self, tmp_path: Path):
        # Test UNC path in tar member
        unc_tar = tmp_path / "unc_attack.tar.gz"
        with tarfile.open(unc_tar, "w:gz") as tar:
            data = b"unc exploit"
            ti = tarfile.TarInfo(name=r"\\attacker-server\share\exploit.exe")
            ti.size = len(data)
            tar.addfile(ti, io.BytesIO(data))

        dest_vault = tmp_path / "safe_dest_2"
        res = CasePackageManager.validate_and_import(unc_tar, dest_vault)
        assert res.status == PackageValidationStatus.UNSAFE_PATH

        # Test Windows drive letter path in tar member
        drive_tar = tmp_path / "drive_attack.tar.gz"
        with tarfile.open(drive_tar, "w:gz") as tar:
            data = b"drive exploit"
            ti = tarfile.TarInfo(name="C:/Windows/System32/evil.sys")
            ti.size = len(data)
            tar.addfile(ti, io.BytesIO(data))

        res2 = CasePackageManager.validate_and_import(drive_tar, dest_vault)
        assert res2.status == PackageValidationStatus.UNSAFE_PATH

    def test_archive_symlink_attack_rejected(self, tmp_path: Path):
        sym_tar = tmp_path / "symlink_attack.tar.gz"
        with tarfile.open(sym_tar, "w:gz") as tar:
            ti = tarfile.TarInfo(name="symlink_link")
            ti.type = tarfile.SYMTYPE
            ti.linkname = "/etc/shadow"
            tar.addfile(ti)

        dest_vault = tmp_path / "safe_dest_sym"
        res = CasePackageManager.validate_and_import(sym_tar, dest_vault)
        assert res.status == PackageValidationStatus.UNSAFE_PATH


# ─── 10. Crash Safety & Concurrency Tests ─────────────────────────────────────

class TestCrashSafetyAndConcurrency:
    def test_safe_atomic_json_write(self, tmp_path: Path):
        target = tmp_path / "atomic_test.json"
        data = {"key": "value", "numbers": [1, 2, 3]}
        safe_atomic_json_write(target, data)
        assert target.is_file()

        loaded = json.loads(target.read_text(encoding="utf-8"))
        assert loaded == data

    def test_safe_atomic_write_crash_simulation(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        target = tmp_path / "crucial_file.json"
        original_data = {"status": "INITIAL_STABLE_STATE"}
        safe_atomic_json_write(target, original_data)
        assert target.is_file()

        # Simulate crash/failure right before atomic replacement (monkeypatch os.replace)
        def crashing_replace(src: str, dst: str):
            raise OSError("Simulated crash: disk full or power failure")

        monkeypatch.setattr(os, "replace", crashing_replace)

        with pytest.raises(OSError, match="Simulated crash"):
            safe_atomic_json_write(target, {"status": "UNFINISHED_CORRUPTED_STATE"})

        # The original target file must remain intact and valid
        assert target.is_file()
        current_data = json.loads(target.read_text(encoding="utf-8"))
        assert current_data == original_data

    def test_concurrent_evidence_registration_thread_safety(self, vault_env: ForensicCaseManager, tmp_path: Path):
        case = vault_env.create_case("C-CONCUR-01", "Concurrency Test", "Examiner", "Org")

        # Run 10 threads adding evidence simultaneously
        threads = []
        errors = []

        def worker(idx: int):
            try:
                vault_env.register_evidence(
                    case_id=case.case_id,
                    source_type=EvidenceSourceType.FILE,
                    source_path=f"/path/evidence_{idx}.raw",
                    examiner=f"Examiner_{idx}",
                )
            except Exception as e:
                errors.append(e)

        for i in range(10):
            t = threading.Thread(target=worker, args=(i,))
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        assert len(errors) == 0
        ev_list = vault_env.list_evidence(case.case_id)
        assert len(ev_list) == 10

        # Verify audit chain integrity remains 100% valid under concurrency
        audit_res = vault_env.verify_case_audit_chain(case.case_id)
        assert audit_res.status == AuditVerificationStatus.VALID


# ─── 11. Timeline ↔ Audit Consistency Tests ───────────────────────────────────

class TestTimelineAuditConsistency:
    def test_timeline_audit_consistency_on_all_lifecycle_mutations(self, vault_env: ForensicCaseManager):
        case = vault_env.create_case("C-TAC-01", "Consistency Test", "Examiner", "Cyber Dept")
        ev = vault_env.register_evidence(case.case_id, EvidenceSourceType.FILE, "/evidence.img", "Examiner")
        vault_env.update_case_status(case.case_id, CaseStatus.ACTIVE, actor="Examiner")

        # Record operational mutations
        vault_env.record_recovery_event(case.case_id, "OP-REC-1", ev.evidence_id, "Examiner", TimelineEventType.RECOVERY_STARTED, "Starting deep carving")
        vault_env.record_recovery_event(case.case_id, "OP-REC-1", ev.evidence_id, "Examiner", TimelineEventType.RECOVERY_COMPLETED, "Carving complete")

        vault_env.record_sanitization_event(case.case_id, "OP-SAN-1", ev.evidence_id, "Examiner", TimelineEventType.SANITIZATION_STARTED, "Starting sanitization")
        vault_env.record_sanitization_event(case.case_id, "OP-SAN-1", ev.evidence_id, "Examiner", TimelineEventType.SANITIZATION_COMPLETED, "Sanitization complete")

        vault_env.record_verification_event(case.case_id, "OP-VER-1", ev.evidence_id, "Examiner", TimelineEventType.VERIFICATION_STARTED, "Starting entropy verification")
        vault_env.record_verification_event(case.case_id, "OP-VER-1", ev.evidence_id, "Examiner", TimelineEventType.VERIFICATION_COMPLETED, "Entropy verified")

        vault_env.record_certificate_event(case.case_id, "CERT-001", "OP-SAN-1", ev.evidence_id, "Examiner", TimelineEventType.CERTIFICATE_CREATED, "Sanitization certificate generated")

        vault_env.record_export_event(case.case_id, "/exports/case.drex.tar.gz", "Examiner", "Case exported to archive")

        timeline = vault_env.get_timeline(case.case_id)
        audit_chain = vault_env.get_audit_chain(case.case_id)

        # Timeline and Audit Chain must have recorded all major operational events
        assert len(timeline) >= 10
        assert len(audit_chain) >= 10

        # Verify audit chain validity
        v_res = vault_env.verify_case_audit_chain(case.case_id)
        assert v_res.status == AuditVerificationStatus.VALID
        assert v_res.verified_events == len(audit_chain)

        # Verify timeline integrity hashes
        for t in timeline:
            assert t.calculate_integrity_hash() == t.integrity_hash


# ─── 12. Cross-Case Isolation & Path Security Tests ───────────────────────────

class TestCrossCaseIsolationAndPathSecurity:
    def test_cross_case_isolation_cannot_access_other_case(self, vault_env: ForensicCaseManager, tmp_path: Path):
        case_a = vault_env.create_case("CA-01", "Case Alpha", "Examiner A", "Org A")
        case_b = vault_env.create_case("CB-01", "Case Beta", "Examiner B", "Org B")

        ev_a_file = tmp_path / "alpha_doc.txt"
        ev_a_file.write_bytes(b"Alpha Confidential Data")
        ev_a = vault_env.register_evidence(case_a.case_id, EvidenceSourceType.FILE, str(ev_a_file), "Examiner A")

        ev_b_file = tmp_path / "beta_doc.txt"
        ev_b_file.write_bytes(b"Beta Top Secret Data")
        ev_b = vault_env.register_evidence(case_b.case_id, EvidenceSourceType.FILE, str(ev_b_file), "Examiner B")

        # Listing evidence for Case A must not contain Case B evidence
        ev_list_a = vault_env.list_evidence(case_a.case_id)
        ev_list_b = vault_env.list_evidence(case_b.case_id)

        a_ids = [e.evidence_id for e in ev_list_a]
        b_ids = [e.evidence_id for e in ev_list_b]

        assert ev_a.evidence_id in a_ids
        assert ev_b.evidence_id not in a_ids
        assert ev_b.evidence_id in b_ids
        assert ev_a.evidence_id not in b_ids

    def test_case_path_traversal_sanitization(self, vault_env: ForensicCaseManager):
        # Attempting path traversal case_id is sanitized safely
        evil_id = "../CASE-EVIL"
        c_path = vault_env._case_path(evil_id)
        assert c_path.is_relative_to(vault_env.cases_dir)
        assert ".." not in str(c_path.name)

    def test_unc_and_colon_path_sanitization(self):
        assert sanitize_filename("C:\\malicious\\path") == "malicious_path"
        assert sanitize_filename("\\\\server\\share\\file.txt") == "server_share_file.txt"
        assert sanitize_filename("NUL") == "_NUL_"
        assert sanitize_filename("CON") == "_CON_"
        assert sanitize_filename("COM1") == "_COM1_"


# ─── 13. Schema Versioning Tests ──────────────────────────────────────────────

class TestSchemaVersioning:
    def test_schema_version_validation_on_models(self):
        case = ForensicCase("CASE-01", "C-01", "Title", "Desc", "Ex", "Org", "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z")
        assert case.schema_version == 1

        ev = EvidenceSource("EVID-01", "CASE-01", EvidenceSourceType.FILE, "/path")
        assert ev.schema_version == 1

        vobj = VaultObject("VLT-01", "CASE-01", VaultObjectType.SOURCE, "rel/path", 100, "hash", "2026-01-01T00:00:00Z")
        assert vobj.schema_version == 1

    def test_package_schema_mismatch_detection(self, vault_env: ForensicCaseManager, tmp_path: Path):
        case = vault_env.create_case("C-SCH-01", "Schema Test", "Examiner", "Org")
        cdir = vault_env._case_path(case.case_id)
        pkg_path = tmp_path / "schema_pkg.tar.gz"
        CasePackageManager.export_package(cdir, pkg_path)

        # Unpack, alter schema_version, repack
        tamper_dir = tmp_path / "tamper_schema"
        tamper_dir.mkdir()
        with tarfile.open(pkg_path, "r:gz") as tar:
            tar.extractall(tamper_dir)

        manifest_file = tamper_dir / "manifest.json"
        manifest_data = json.loads(manifest_file.read_text(encoding="utf-8"))
        manifest_data["schema_version"] = 999  # Unsupported version
        manifest_file.write_text(json.dumps(manifest_data), encoding="utf-8")

        tampered_pkg = tmp_path / "unsupported_schema.tar.gz"
        with tarfile.open(tampered_pkg, "w:gz") as tar:
            for f in sorted(tamper_dir.rglob("*")):
                if f.is_file():
                    tar.add(f, arcname=f.relative_to(tamper_dir).as_posix())

        dest_vault = tmp_path / "dest_schema_vault"
        res = CasePackageManager.validate_and_import(tampered_pkg, dest_vault)
        assert res.status == PackageValidationStatus.SCHEMA_MISMATCH
        assert "Unsupported package schema version" in res.error_message
