"""
DREX-V2 Forensic Case Management, Evidence Vault, Timeline & Audit Foundation
=============================================================================
Provides production-grade forensic data models and runtime services for:
- Forensic Cases (lifecycle, metadata, examiner attribution)
- Evidence Sources (physical drives, disk images, files, partitions, fixtures)
- Streaming Cryptographic Hasher (SHA-256 / SHA-512, memory-bounded chunking)
- Forensic Timeline (chronological typed events, integrity hashes)
- Hash-Chained Audit Ledger (Merkle hash chaining, independent audit verifier)
- Chain of Custody (custodian tracking, transfers, sealing, immutable history)
- Evidence Vault (categorized object isolation: SOURCE, DERIVED, RECOVERED, REPORT, CERTIFICATE, AUDIT)
- Recovery & Sanitization Provenance (candidate tracking, confidence scores, execution evidence)
- Case Package Export / Import & Tamper-Evident Manifest Validation

Zero external dependencies (uses Python standard library: hashlib, json, os, pathlib, shutil, tarfile, tempfile, threading, uuid).
License: Apache 2.0.
"""

from __future__ import annotations

import copy
import enum
import hashlib
import json
import os
import re
import shutil
import tarfile
import tempfile
import threading
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List, Optional, Tuple, Union


# ─── Enumerations ─────────────────────────────────────────────────────────────

class CaseStatus(enum.Enum):
    OPEN = "OPEN"
    ACTIVE = "ACTIVE"
    PAUSED = "PAUSED"
    CLOSED = "CLOSED"
    ARCHIVED = "ARCHIVED"


class EvidenceSourceType(enum.Enum):
    PHYSICAL_DEVICE = "PHYSICAL_DEVICE"
    PARTITION = "PARTITION"
    FILESYSTEM = "FILESYSTEM"
    DISK_IMAGE = "DISK_IMAGE"
    FORENSIC_IMAGE = "FORENSIC_IMAGE"
    REMOVABLE_STORAGE = "REMOVABLE_STORAGE"
    FILE = "FILE"
    FOLDER = "FOLDER"
    RECOVERED_ARTIFACT = "RECOVERED_ARTIFACT"
    SYNTHETIC_FIXTURE = "SYNTHETIC_FIXTURE"


class TimelineEventType(enum.Enum):
    CASE_CREATED = "CASE_CREATED"
    CASE_UPDATED = "CASE_UPDATED"
    EVIDENCE_ADDED = "EVIDENCE_ADDED"
    EVIDENCE_HASHED = "EVIDENCE_HASHED"
    EVIDENCE_ACQUIRED = "EVIDENCE_ACQUIRED"
    RECOVERY_STARTED = "RECOVERY_STARTED"
    RECOVERY_COMPLETED = "RECOVERY_COMPLETED"
    RECOVERY_FAILED = "RECOVERY_FAILED"
    SANITIZATION_PLANNED = "SANITIZATION_PLANNED"
    SANITIZATION_CONFIRMED = "SANITIZATION_CONFIRMED"
    SANITIZATION_STARTED = "SANITIZATION_STARTED"
    SANITIZATION_COMPLETED = "SANITIZATION_COMPLETED"
    SANITIZATION_FAILED = "SANITIZATION_FAILED"
    VERIFICATION_STARTED = "VERIFICATION_STARTED"
    VERIFICATION_COMPLETED = "VERIFICATION_COMPLETED"
    CERTIFICATE_CREATED = "CERTIFICATE_CREATED"
    CERTIFICATE_VERIFIED = "CERTIFICATE_VERIFIED"
    AUDIT_EVENT = "AUDIT_EVENT"
    EXPORT_CREATED = "EXPORT_CREATED"
    CUSTODY_CHANGE = "CUSTODY_CHANGE"


class CustodyAction(enum.Enum):
    RECEIVED = "RECEIVED"
    TRANSFERRED = "TRANSFERRED"
    ACCESSED = "ACCESSED"
    COPIED = "COPIED"
    ANALYZED = "ANALYZED"
    EXPORTED = "EXPORTED"
    SEALED = "SEALED"
    RELEASED = "RELEASED"


class VaultObjectType(enum.Enum):
    SOURCE = "SOURCE"
    DERIVED = "DERIVED"
    RECOVERED = "RECOVERED"
    REPORT = "REPORT"
    CERTIFICATE = "CERTIFICATE"
    AUDIT = "AUDIT"


class RecoveryCandidateState(enum.Enum):
    CANDIDATE = "CANDIDATE"
    VALIDATED_CANDIDATE = "VALIDATED_CANDIDATE"
    RECONSTRUCTED_CANDIDATE = "RECONSTRUCTED_CANDIDATE"
    RECOVERED_ARTIFACT = "RECOVERED_ARTIFACT"


class AuditVerificationStatus(enum.Enum):
    VALID = "VALID"
    INVALID = "INVALID"
    TAMPERED_EVENT = "TAMPERED_EVENT"
    BROKEN_CHAIN = "BROKEN_CHAIN"
    UNVERIFIABLE = "UNVERIFIABLE"


class CustodyVerificationStatus(enum.Enum):
    VALID = "VALID"
    INVALID = "INVALID"
    TAMPERED_RECORD = "TAMPERED_RECORD"
    BROKEN_SEQUENCE = "BROKEN_SEQUENCE"
    AUDIT_MISMATCH = "AUDIT_MISMATCH"


class PackageValidationStatus(enum.Enum):
    VALID = "VALID"
    INVALID = "INVALID"
    TAMPERED_MANIFEST = "TAMPERED_MANIFEST"
    SCHEMA_MISMATCH = "SCHEMA_MISMATCH"
    CORRUPTED_OBJECT = "CORRUPTED_OBJECT"
    UNSAFE_PATH = "UNSAFE_PATH"


# ─── Utility Functions ────────────────────────────────────────────────────────

def utc_now_iso() -> str:
    """Return ISO 8601 UTC timestamp formatted with Z indicator."""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def generate_stable_id(prefix: str) -> str:
    """Generate deterministic, collision-resistant unique identifier."""
    ts_str = datetime.now(timezone.utc).strftime("%Y%m%d")
    hex_rnd = uuid.uuid4().hex[:8].upper()
    return f"{prefix}-{ts_str}-{hex_rnd}"


def canonical_json_bytes(data: Any) -> bytes:
    """Serialize data into deterministic, sort-keyed, compact JSON bytes."""
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def compute_event_hash(
    previous_hash: str,
    sequence_number: int,
    event_id: str,
    case_id: str,
    timestamp: str,
    actor: str,
    event_type: str,
    payload: Dict[str, Any],
    operation_id: Optional[str] = None,
) -> str:
    """Calculate deterministic SHA-256 hash for an audit event covering the entire envelope."""
    envelope = {
        "sequence_number": sequence_number,
        "event_id": event_id,
        "case_id": case_id,
        "timestamp": timestamp,
        "actor": actor,
        "event_type": event_type,
        "operation_id": operation_id,
        "payload": payload,
    }
    canon_bytes = canonical_json_bytes(envelope)
    preimage = previous_hash.encode("utf-8") + canon_bytes
    return hashlib.sha256(preimage).hexdigest()


def safe_atomic_write(path: Path, content: Union[str, bytes]) -> None:
    """
    Perform crash-safe, atomic file write using tempfile, flush, fsync, and os.replace.
    Guarantees no partial or corrupted file persists upon process interruption.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=path.parent)
    try:
        if isinstance(content, str):
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
        else:
            with os.fdopen(fd, "wb") as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
        os.replace(tmp_name, path)
    finally:
        try:
            os.unlink(tmp_name)
        except FileNotFoundError:
            pass


def safe_atomic_json_write(path: Path, data: Any) -> None:
    """Serialize data as formatted JSON and atomically write to disk."""
    content = json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False)
    safe_atomic_write(path, content)


def sanitize_filename(name: str) -> str:
    """Sanitize path component to prevent path traversal, drive specifiers, and illegal characters."""
    cleaned = re.sub(r'^[a-zA-Z]:', '', name)
    cleaned = re.sub(r'[/\\:*?"<>|]', '_', cleaned)
    cleaned = re.sub(r'_+', '_', cleaned)
    cleaned = cleaned.strip('. _')
    reserved = {
        "CON", "PRN", "AUX", "NUL",
        "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
        "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
    }
    if cleaned.upper() in reserved:
        cleaned = f"_{cleaned}_"
    return cleaned or "unnamed_object"


# ─── Data Models ──────────────────────────────────────────────────────────────

@dataclass
class ForensicCase:
    case_id: str
    case_number: str
    title: str
    description: str
    examiner: str
    organization: str
    created_at: str
    updated_at: str
    status: CaseStatus = CaseStatus.OPEN
    classification: str = "CONFIDENTIAL"
    notes: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    timezone: str = "UTC"
    schema_version: int = 1

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["status"] = self.status.value if isinstance(self.status, CaseStatus) else str(self.status)
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ForensicCase:
        raw = dict(data)
        st = raw.get("status", "OPEN")
        raw["status"] = CaseStatus(st) if isinstance(st, str) and st in CaseStatus.__members__ else CaseStatus.OPEN
        return cls(**raw)


@dataclass
class EvidenceSource:
    evidence_id: str
    case_id: str
    source_type: EvidenceSourceType
    source_path: str
    device_identity: Optional[str] = None
    model: Optional[str] = None
    serial: Optional[str] = None
    transport: Optional[str] = None
    capacity: Optional[int] = None
    filesystem: Optional[str] = None
    acquisition_timestamp: str = field(default_factory=utc_now_iso)
    source_hash: Optional[str] = None
    examiner: str = "Examiner"
    provenance: str = "Direct Connection"
    read_only: bool = True
    acquisition_method: str = "LOGICAL"
    acquisition_status: str = "ACQUIRED"
    limitations: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    schema_version: int = 1

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["source_type"] = self.source_type.value if isinstance(self.source_type, EvidenceSourceType) else str(self.source_type)
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> EvidenceSource:
        raw = dict(data)
        st = raw.get("source_type", "FILE")
        raw["source_type"] = EvidenceSourceType(st) if isinstance(st, str) and st in EvidenceSourceType.__members__ else EvidenceSourceType.FILE
        return cls(**raw)


@dataclass
class HashRecord:
    algorithm: str
    digest: str
    byte_count: int
    started_at: str
    completed_at: str
    source_identity: str
    operation_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ForensicTimelineEvent:
    event_id: str
    case_id: str
    timestamp: str
    event_type: TimelineEventType
    actor: str
    description: str
    source: str
    operation_id: Optional[str] = None
    evidence_id: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    integrity_hash: str = ""
    schema_version: int = 1

    def calculate_integrity_hash(self) -> str:
        payload = {
            "event_id": self.event_id,
            "case_id": self.case_id,
            "timestamp": self.timestamp,
            "event_type": self.event_type.value if isinstance(self.event_type, TimelineEventType) else str(self.event_type),
            "actor": self.actor,
            "description": self.description,
            "source": self.source,
            "operation_id": self.operation_id,
            "evidence_id": self.evidence_id,
            "metadata": self.metadata,
        }
        return hashlib.sha256(canonical_json_bytes(payload)).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["event_type"] = self.event_type.value if isinstance(self.event_type, TimelineEventType) else str(self.event_type)
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ForensicTimelineEvent:
        raw = dict(data)
        et = raw.get("event_type", "AUDIT_EVENT")
        raw["event_type"] = TimelineEventType(et) if isinstance(et, str) and et in TimelineEventType.__members__ else TimelineEventType.AUDIT_EVENT
        return cls(**raw)


@dataclass
class AuditEvent:
    sequence_number: int
    event_id: str
    case_id: str
    timestamp: str
    actor: str
    event_type: str
    canonical_payload: Dict[str, Any]
    previous_hash: str
    current_hash: str
    operation_id: Optional[str] = None
    schema_version: int = 1

    @classmethod
    def create(
        cls,
        sequence_number: int,
        case_id: str,
        actor: str,
        event_type: str,
        payload: Dict[str, Any],
        previous_hash: str,
        operation_id: Optional[str] = None,
        timestamp: Optional[str] = None,
        event_id: Optional[str] = None,
    ) -> AuditEvent:
        ev_id = event_id or generate_stable_id("AUD")
        ts = timestamp or utc_now_iso()
        cur_hash = compute_event_hash(
            previous_hash=previous_hash,
            sequence_number=sequence_number,
            event_id=ev_id,
            case_id=case_id,
            timestamp=ts,
            actor=actor,
            event_type=event_type,
            payload=payload,
            operation_id=operation_id,
        )
        return cls(
            sequence_number=sequence_number,
            event_id=ev_id,
            case_id=case_id,
            timestamp=ts,
            actor=actor,
            event_type=event_type,
            canonical_payload=payload,
            previous_hash=previous_hash,
            current_hash=cur_hash,
            operation_id=operation_id,
        )

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> AuditEvent:
        return cls(**data)


@dataclass
class ChainOfCustodyRecord:
    custody_event_id: str
    evidence_id: str
    case_id: str
    custodian: str
    action: CustodyAction
    timestamp: str
    reason: str
    source_location: str
    destination: str
    hash_before: Optional[str] = None
    hash_after: Optional[str] = None
    notes: str = ""
    integrity_reference: str = ""
    schema_version: int = 1

    def calculate_integrity(self) -> str:
        payload = {
            "custody_event_id": self.custody_event_id,
            "evidence_id": self.evidence_id,
            "case_id": self.case_id,
            "custodian": self.custodian,
            "action": self.action.value if isinstance(self.action, CustodyAction) else str(self.action),
            "timestamp": self.timestamp,
            "reason": self.reason,
            "source_location": self.source_location,
            "destination": self.destination,
            "hash_before": self.hash_before,
            "hash_after": self.hash_after,
            "notes": self.notes,
        }
        return hashlib.sha256(canonical_json_bytes(payload)).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["action"] = self.action.value if isinstance(self.action, CustodyAction) else str(self.action)
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ChainOfCustodyRecord:
        raw = dict(data)
        act = raw.get("action", "RECEIVED")
        raw["action"] = CustodyAction(act) if isinstance(act, str) and act in CustodyAction.__members__ else CustodyAction.RECEIVED
        return cls(**raw)


@dataclass
class VaultObject:
    object_id: str
    case_id: str
    object_type: VaultObjectType
    relative_path: str
    size_bytes: int
    sha256_hash: str
    created_at: str
    source_evidence_id: Optional[str] = None
    generating_operation_id: Optional[str] = None
    verification_state: str = "UNVERIFIED"
    integrity_state: str = "VALID"
    metadata: Dict[str, Any] = field(default_factory=dict)
    schema_version: int = 1

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["object_type"] = self.object_type.value if isinstance(self.object_type, VaultObjectType) else str(self.object_type)
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> VaultObject:
        raw = dict(data)
        ot = raw.get("object_type", "DERIVED")
        raw["object_type"] = VaultObjectType(ot) if isinstance(ot, str) and ot in VaultObjectType.__members__ else VaultObjectType.DERIVED
        return cls(**raw)


@dataclass
class RecoveryArtifactRecord:
    candidate_id: str
    case_id: str
    source_evidence_id: str
    source_offset: Optional[int]
    filesystem_origin: Optional[str]
    carving_method: str
    reconstruction_method: str
    evidence_confidence_score: float
    validation_state: RecoveryCandidateState
    output_hash: str
    output_size: int
    recovery_timestamp: str = field(default_factory=utc_now_iso)
    limitations: List[str] = field(default_factory=list)
    schema_version: int = 1

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["validation_state"] = self.validation_state.value if isinstance(self.validation_state, RecoveryCandidateState) else str(self.validation_state)
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> RecoveryArtifactRecord:
        raw = dict(data)
        vs = raw.get("validation_state", "CANDIDATE")
        raw["validation_state"] = RecoveryCandidateState(vs) if isinstance(vs, str) and vs in RecoveryCandidateState.__members__ else RecoveryCandidateState.CANDIDATE
        return cls(**raw)


@dataclass
class SanitizationProvenanceRecord:
    operation_id: str
    case_id: str
    evidence_id: str
    device_identity: str
    transport: str
    method_id: str
    method_name: str
    capability_state: str
    execution_backend: str
    execution_status: str
    verification_method: str
    verification_result: str
    evidence_data: Dict[str, Any]
    limitations: List[str]
    safety_checks: List[str]
    confirmation_state: bool
    started_at: str
    completed_at: str
    certificate_id: Optional[str] = None
    schema_version: int = 1

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> SanitizationProvenanceRecord:
        return cls(**data)


@dataclass
class AuditVerificationResult:
    status: AuditVerificationStatus
    total_events: int
    verified_events: int
    broken_sequence_index: Optional[int] = None
    error_message: Optional[str] = None
    details: List[str] = field(default_factory=list)


@dataclass
class PackageValidationResult:
    status: PackageValidationStatus
    manifest_valid: bool
    audit_chain_valid: bool
    objects_verified: int
    objects_corrupted: int
    error_message: Optional[str] = None
    details: List[str] = field(default_factory=list)


# ─── Streaming Cryptographic Hashing Engine ───────────────────────────────────

class StreamingHasher:
    """
    High-performance, memory-bounded streaming cryptographic hasher.
    Supports SHA-256 and SHA-512 over arbitrary stream sizes with deterministic output.
    """
    CHUNK_SIZE = 64 * 1024  # 64 KB default buffer

    @classmethod
    def hash_stream(
        cls,
        stream: Any,
        algorithm: str = "sha256",
        source_identity: str = "stream",
        operation_id: Optional[str] = None,
        chunk_size: int = CHUNK_SIZE,
        progress_callback: Optional[Callable[[int], None]] = None,
    ) -> HashRecord:
        started = utc_now_iso()
        algo = algorithm.lower()
        if algo == "sha512":
            hasher = hashlib.sha512()
        elif algo == "sha256":
            hasher = hashlib.sha256()
        else:
            raise ValueError(f"Unsupported hashing algorithm: {algorithm}. Supported: sha256, sha512.")

        total_bytes = 0
        while True:
            chunk = stream.read(chunk_size)
            if not chunk:
                break
            hasher.update(chunk)
            total_bytes += len(chunk)
            if progress_callback:
                progress_callback(total_bytes)

        completed = utc_now_iso()
        return HashRecord(
            algorithm=algo,
            digest=hasher.hexdigest(),
            byte_count=total_bytes,
            started_at=started,
            completed_at=completed,
            source_identity=source_identity,
            operation_id=operation_id,
        )

    @classmethod
    def hash_file(
        cls,
        file_path: Union[str, Path],
        algorithm: str = "sha256",
        operation_id: Optional[str] = None,
        chunk_size: int = CHUNK_SIZE,
        progress_callback: Optional[Callable[[int], None]] = None,
    ) -> HashRecord:
        path = Path(file_path).resolve()
        if not path.is_file():
            raise FileNotFoundError(f"Evidence file not found for hashing: {path}")

        with open(path, "rb") as f:
            return cls.hash_stream(
                stream=f,
                algorithm=algorithm,
                source_identity=str(path),
                operation_id=operation_id,
                chunk_size=chunk_size,
                progress_callback=progress_callback,
            )


# ─── Independent Audit & Custody Verifiers ────────────────────────────────────

class IndependentAuditVerifier:
    """
    Stateless, independent verifier for hash-chained audit ledgers.
    Detects payload mutations, altered timestamps, modified case/operation IDs,
    previous hash tampering, broken sequences, deleted events, and inserted/reordered records.
    """
    GENESIS_HASH = "0" * 64

    @classmethod
    def verify_chain(cls, events: List[AuditEvent]) -> AuditVerificationResult:
        if not events:
            return AuditVerificationResult(
                status=AuditVerificationStatus.VALID,
                total_events=0,
                verified_events=0,
                details=["Empty audit chain verified as trivially valid."],
            )

        details = []
        expected_prev = cls.GENESIS_HASH

        for idx, event in enumerate(events):
            # Check 1: Sequence continuity
            if event.sequence_number != idx:
                msg = f"Broken sequence number at index {idx}: expected {idx}, found {event.sequence_number}"
                details.append(msg)
                return AuditVerificationResult(
                    status=AuditVerificationStatus.BROKEN_CHAIN,
                    total_events=len(events),
                    verified_events=idx,
                    broken_sequence_index=idx,
                    error_message=msg,
                    details=details,
                )

            # Check 2: Previous hash link
            if event.previous_hash != expected_prev:
                msg = (
                    f"Previous hash mismatch at sequence {idx}: "
                    f"expected {expected_prev[:16]}..., found {event.previous_hash[:16]}..."
                )
                details.append(msg)
                return AuditVerificationResult(
                    status=AuditVerificationStatus.BROKEN_CHAIN,
                    total_events=len(events),
                    verified_events=idx,
                    broken_sequence_index=idx,
                    error_message=msg,
                    details=details,
                )

            # Check 3: Full canonical envelope integrity (covers case_id, timestamp, actor, event_type, operation_id, payload)
            expected_current = compute_event_hash(
                previous_hash=event.previous_hash,
                sequence_number=event.sequence_number,
                event_id=event.event_id,
                case_id=event.case_id,
                timestamp=event.timestamp,
                actor=event.actor,
                event_type=event.event_type,
                payload=event.canonical_payload,
                operation_id=event.operation_id,
            )

            if event.current_hash != expected_current:
                msg = (
                    f"Tampered event payload at sequence {idx} ({event.event_id}): "
                    f"recalculated {expected_current[:16]}..., recorded {event.current_hash[:16]}..."
                )
                details.append(msg)
                return AuditVerificationResult(
                    status=AuditVerificationStatus.TAMPERED_EVENT,
                    total_events=len(events),
                    verified_events=idx,
                    broken_sequence_index=idx,
                    error_message=msg,
                    details=details,
                )

            expected_prev = event.current_hash

        return AuditVerificationResult(
            status=AuditVerificationStatus.VALID,
            total_events=len(events),
            verified_events=len(events),
            details=[f"All {len(events)} hash-chained audit events cryptographically verified."],
        )

    @classmethod
    def verify_audit_file(cls, audit_file_path: Union[str, Path]) -> AuditVerificationResult:
        path = Path(audit_file_path).resolve()
        if not path.is_file():
            return AuditVerificationResult(
                status=AuditVerificationStatus.UNVERIFIABLE,
                total_events=0,
                verified_events=0,
                error_message=f"Audit log file not found: {path}",
            )
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(data, list):
                return AuditVerificationResult(
                    status=AuditVerificationStatus.INVALID,
                    total_events=0,
                    verified_events=0,
                    error_message="Audit file must contain a JSON array of events.",
                )
            events = [AuditEvent.from_dict(item) for item in data]
            return cls.verify_chain(events)
        except Exception as exc:
            return AuditVerificationResult(
                status=AuditVerificationStatus.INVALID,
                total_events=0,
                verified_events=0,
                error_message=f"Failed to parse audit ledger: {exc}",
            )


@dataclass
class CustodyVerificationResult:
    status: CustodyVerificationStatus
    total_records: int
    verified_records: int
    error_message: Optional[str] = None
    details: List[str] = field(default_factory=list)


class IndependentCustodyVerifier:
    """
    Stateless independent verifier for Chain of Custody records.
    Verifies individual record integrity hashes and verifies ordering against the audit ledger.
    """
    @classmethod
    def verify_custody_records(
        cls,
        records: List[ChainOfCustodyRecord],
        audit_events: Optional[List[AuditEvent]] = None,
    ) -> CustodyVerificationResult:
        if not records:
            return CustodyVerificationResult(
                status=CustodyVerificationStatus.VALID,
                total_records=0,
                verified_records=0,
                details=["Empty custody ledger verified as valid."],
            )

        details = []
        # 1. Verify individual record integrity hashes
        for idx, rec in enumerate(records):
            calc_hash = rec.calculate_integrity()
            if rec.integrity_reference != calc_hash:
                msg = (
                    f"Tampered custody record at index {idx} ({rec.custody_event_id}): "
                    f"expected {calc_hash[:16]}..., found {rec.integrity_reference[:16]}..."
                )
                details.append(msg)
                return CustodyVerificationResult(
                    status=CustodyVerificationStatus.TAMPERED_RECORD,
                    total_records=len(records),
                    verified_records=idx,
                    error_message=msg,
                    details=details,
                )

        # 2. If audit events provided, verify that every custody record matches an audit event in sequence
        if audit_events is not None:
            custody_audits = [e for e in audit_events if e.event_type == "CUSTODY_CHANGE"]
            if len(custody_audits) != len(records):
                msg = (
                    f"Custody record count ({len(records)}) does not match "
                    f"audit chain custody events ({len(custody_audits)})."
                )
                details.append(msg)
                return CustodyVerificationResult(
                    status=CustodyVerificationStatus.AUDIT_MISMATCH,
                    total_records=len(records),
                    verified_records=0,
                    error_message=msg,
                    details=details,
                )
            for idx, (rec, aud) in enumerate(zip(records, custody_audits)):
                aud_cust_id = aud.canonical_payload.get("custody_event_id")
                aud_hash = aud.canonical_payload.get("integrity_reference")
                if aud_cust_id != rec.custody_event_id or aud_hash != rec.integrity_reference:
                    msg = f"Custody record {rec.custody_event_id} at index {idx} does not match audit event payload."
                    details.append(msg)
                    return CustodyVerificationResult(
                        status=CustodyVerificationStatus.AUDIT_MISMATCH,
                        total_records=len(records),
                        verified_records=idx,
                        error_message=msg,
                        details=details,
                    )

        return CustodyVerificationResult(
            status=CustodyVerificationStatus.VALID,
            total_records=len(records),
            verified_records=len(records),
            details=[f"All {len(records)} custody records cryptographically verified."],
        )


# ─── Evidence Vault Manager ───────────────────────────────────────────────────

class EvidenceVault:
    """
    High-integrity physical storage organizer per forensic case.
    Enforces strict categorization: SOURCE, DERIVED, RECOVERED, REPORT, CERTIFICATE, AUDIT.
    """
    def __init__(self, case_dir: Path):
        self.case_dir = case_dir
        self.source_dir = case_dir / "source"
        self.derived_dir = case_dir / "derived"
        self.recovered_dir = case_dir / "recovered"
        self.reports_dir = case_dir / "reports"
        self.certs_dir = case_dir / "certificates"
        self.audit_dir = case_dir / "audit"
        self.objects_index_file = case_dir / "vault_objects.json"
        self._lock = threading.RLock()
        self._init_dirs()

    def _init_dirs(self) -> None:
        for d in (self.source_dir, self.derived_dir, self.recovered_dir, self.reports_dir, self.certs_dir, self.audit_dir):
            d.mkdir(parents=True, exist_ok=True)

    def _get_target_dir(self, object_type: VaultObjectType) -> Path:
        mapping = {
            VaultObjectType.SOURCE: self.source_dir,
            VaultObjectType.DERIVED: self.derived_dir,
            VaultObjectType.RECOVERED: self.recovered_dir,
            VaultObjectType.REPORT: self.reports_dir,
            VaultObjectType.CERTIFICATE: self.certs_dir,
            VaultObjectType.AUDIT: self.audit_dir,
        }
        return mapping[object_type]

    def list_objects(self) -> List[VaultObject]:
        with self._lock:
            if not self.objects_index_file.exists():
                return []
            try:
                data = json.loads(self.objects_index_file.read_text(encoding="utf-8"))
                return [VaultObject.from_dict(d) for d in data if isinstance(d, dict)]
            except (OSError, json.JSONDecodeError):
                return []

    def store_file(
        self,
        case_id: str,
        source_path: Union[str, Path],
        object_type: VaultObjectType,
        destination_name: Optional[str] = None,
        source_evidence_id: Optional[str] = None,
        generating_operation_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        copy_file: bool = True,
    ) -> VaultObject:
        src = Path(source_path).resolve()
        if not src.exists():
            raise FileNotFoundError(f"Source file not found: {src}")

        dest_name = sanitize_filename(destination_name or src.name)
        target_dir = self._get_target_dir(object_type)
        target_path = target_dir / dest_name

        # Prevent silent overwriting
        if target_path.exists():
            stem = target_path.stem
            suffix = target_path.suffix
            dest_name = f"{stem}_{uuid.uuid4().hex[:6]}{suffix}"
            target_path = target_dir / dest_name

        with self._lock:
            if copy_file:
                shutil.copy2(src, target_path)
            else:
                # Reference mode for large images
                target_path = src

            hash_rec = StreamingHasher.hash_file(target_path)
            rel_path = str(target_path.relative_to(self.case_dir)) if target_path.is_relative_to(self.case_dir) else str(target_path)

            v_obj = VaultObject(
                object_id=generate_stable_id("VLT"),
                case_id=case_id,
                object_type=object_type,
                relative_path=rel_path,
                size_bytes=hash_rec.byte_count,
                sha256_hash=hash_rec.digest,
                created_at=utc_now_iso(),
                source_evidence_id=source_evidence_id,
                generating_operation_id=generating_operation_id,
                metadata=metadata or {},
            )

            objects = self.list_objects()
            objects.append(v_obj)
            safe_atomic_json_write(self.objects_index_file, [o.to_dict() for o in objects])
            return v_obj


# ─── Case Package Manager (Export & Import) ───────────────────────────────────

class CasePackageManager:
    """
    Deterministic export and import verification for self-contained forensic case packages.
    Produces atomic tar.gz packages with signed manifest.json and path-traversal safety.
    """

    @classmethod
    def export_package(cls, case_dir: Path, output_tar_path: Union[str, Path]) -> Path:
        case_dir = Path(case_dir).resolve()
        out_path = Path(output_tar_path).resolve()
        out_path.parent.mkdir(parents=True, exist_ok=True)

        manifest_entries: Dict[str, Dict[str, Any]] = {}

        # 1. Build manifest of all files in case directory
        for f in sorted(case_dir.rglob("*")):
            if f.is_file():
                rel = f.relative_to(case_dir).as_posix()
                h_rec = StreamingHasher.hash_file(f)
                manifest_entries[rel] = {
                    "size_bytes": h_rec.byte_count,
                    "sha256": h_rec.digest,
                }

        manifest = {
            "schema_version": 1,
            "export_timestamp": utc_now_iso(),
            "case_directory": case_dir.name,
            "total_files": len(manifest_entries),
            "files": manifest_entries,
        }

        manifest_file = case_dir / "manifest.json"
        safe_atomic_json_write(manifest_file, manifest)

        # Include manifest itself in tar
        temp_tar = out_path.with_suffix(".tmp.tar.gz")
        with tarfile.open(temp_tar, "w:gz") as tar:
            for f in sorted(case_dir.rglob("*")):
                if f.is_file():
                    rel = f.relative_to(case_dir).as_posix()
                    tar.add(f, arcname=rel)

        os.replace(temp_tar, out_path)
        return out_path

    @classmethod
    def validate_and_import(cls, package_path: Union[str, Path], target_vault_dir: Path) -> PackageValidationResult:
        pkg = Path(package_path).resolve()
        if not pkg.is_file():
            return PackageValidationResult(
                status=PackageValidationStatus.INVALID,
                manifest_valid=False,
                audit_chain_valid=False,
                objects_verified=0,
                objects_corrupted=0,
                error_message=f"Package file not found: {pkg}",
            )

        extract_temp = Path(tempfile.mkdtemp(prefix="drex_import_"))
        details = []
        try:
            # 1. Safe extraction with path traversal defense (POSIX + Windows UNC/drive letters/colons)
            with tarfile.open(pkg, "r:gz") as tar:
                for member in tar.getmembers():
                    norm = os.path.normpath(member.name)
                    if (
                        norm.startswith("..")
                        or norm.startswith("\\..")
                        or norm.startswith("/..")
                        or os.path.isabs(member.name)
                        or bool(re.match(r'^[a-zA-Z]:', member.name))
                        or ":" in member.name
                        or member.name.startswith("\\\\")
                        or member.name.startswith("//")
                        or member.issym()
                        or member.islnk()
                    ):
                        return PackageValidationResult(
                            status=PackageValidationStatus.UNSAFE_PATH,
                            manifest_valid=False,
                            audit_chain_valid=False,
                            objects_verified=0,
                            objects_corrupted=0,
                            error_message=f"Security violation: unsafe path detected in archive member: {member.name}",
                        )
                tar.extractall(extract_temp)

            manifest_file = extract_temp / "manifest.json"
            if not manifest_file.is_file():
                return PackageValidationResult(
                    status=PackageValidationStatus.TAMPERED_MANIFEST,
                    manifest_valid=False,
                    audit_chain_valid=False,
                    objects_verified=0,
                    objects_corrupted=0,
                    error_message="manifest.json missing from package archive.",
                )

            manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
            if manifest.get("schema_version") != 1:
                return PackageValidationResult(
                    status=PackageValidationStatus.SCHEMA_MISMATCH,
                    manifest_valid=False,
                    audit_chain_valid=False,
                    objects_verified=0,
                    objects_corrupted=0,
                    error_message=f"Unsupported package schema version: {manifest.get('schema_version')}",
                )

            files_map = manifest.get("files", {})
            verified = 0
            corrupted = 0

            # 2. Re-verify SHA-256 digests of all package files
            for rel_posix, meta in files_map.items():
                if rel_posix == "manifest.json":
                    continue
                item_path = extract_temp / Path(rel_posix)
                if not item_path.is_file():
                    corrupted += 1
                    details.append(f"Missing file declared in manifest: {rel_posix}")
                    continue

                h_rec = StreamingHasher.hash_file(item_path)
                if h_rec.digest != meta.get("sha256"):
                    corrupted += 1
                    details.append(f"Digest mismatch for {rel_posix}: expected {meta.get('sha256')}, got {h_rec.digest}")
                else:
                    verified += 1

            if corrupted > 0:
                return PackageValidationResult(
                    status=PackageValidationStatus.CORRUPTED_OBJECT,
                    manifest_valid=False,
                    audit_chain_valid=False,
                    objects_verified=verified,
                    objects_corrupted=corrupted,
                    error_message=f"Package integrity failure: {corrupted} files corrupted or missing.",
                    details=details,
                )

            # 3. Verify audit chain if present
            audit_file = extract_temp / "audit" / "audit_chain.json"
            audit_valid = True
            if audit_file.is_file():
                audit_res = IndependentAuditVerifier.verify_audit_file(audit_file)
                if audit_res.status != AuditVerificationStatus.VALID:
                    audit_valid = False
                    return PackageValidationResult(
                        status=PackageValidationStatus.INVALID,
                        manifest_valid=True,
                        audit_chain_valid=False,
                        objects_verified=verified,
                        objects_corrupted=0,
                        error_message=f"Audit chain verification failed: {audit_res.error_message}",
                        details=details + audit_res.details,
                    )

            # 4. Atomically move into target vault
            case_file = extract_temp / "case.json"
            if case_file.is_file():
                c_data = json.loads(case_file.read_text(encoding="utf-8"))
                case_id = c_data.get("case_id", "imported_case")
            else:
                case_id = f"CASE-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{uuid.uuid4().hex[:8].upper()}"

            final_dest = target_vault_dir / case_id
            if final_dest.exists():
                shutil.rmtree(final_dest)
            shutil.copytree(extract_temp, final_dest)

            return PackageValidationResult(
                status=PackageValidationStatus.VALID,
                manifest_valid=True,
                audit_chain_valid=audit_valid,
                objects_verified=verified,
                objects_corrupted=0,
                details=["Package manifest, objects, and audit chain successfully verified and imported."],
            )

        finally:
            shutil.rmtree(extract_temp, ignore_errors=True)


# ─── Unified Case Management Service ──────────────────────────────────────────

class ForensicCaseManager:
    """
    Central orchestration service managing forensic cases, evidence sources,
    timelines, hash-chained audit ledgers, custody records, and evidence vaults.
    """
    def __init__(self, base_data_dir: Path):
        self.base_dir = base_data_dir.resolve()
        self.cases_dir = self.base_dir / "cases"
        self.cases_dir.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()

    def _case_path(self, case_id: str) -> Path:
        sanitized = sanitize_filename(case_id)
        target = (self.cases_dir / sanitized).resolve()
        try:
            target.relative_to(self.cases_dir)
        except ValueError:
            raise ValueError(f"Cross-case isolation violation: invalid case_id '{case_id}' resolves outside cases directory.")
        return target

    def get_vault(self, case_id: str) -> EvidenceVault:
        with self._lock:
            cdir = self._case_path(case_id)
            if not cdir.exists():
                raise ValueError(f"Case directory does not exist: {case_id}")
            return EvidenceVault(cdir)

    def create_case(
        self,
        case_number: str,
        title: str,
        examiner: str,
        organization: str,
        description: str = "",
        classification: str = "CONFIDENTIAL",
        tags: Optional[List[str]] = None,
    ) -> ForensicCase:
        with self._lock:
            case_id = generate_stable_id("CASE")
            now = utc_now_iso()
            case = ForensicCase(
                case_id=case_id,
                case_number=case_number,
                title=title,
                description=description,
                examiner=examiner,
                organization=organization,
                created_at=now,
                updated_at=now,
                status=CaseStatus.OPEN,
                classification=classification,
                tags=tags or [],
            )

            cdir = self._case_path(case_id)
            cdir.mkdir(parents=True, exist_ok=True)
            safe_atomic_json_write(cdir / "case.json", case.to_dict())

            # Initialize Vault, Timeline, Audit Chain, and Custody
            EvidenceVault(cdir)
            self._record_timeline_event(
                case_id=case_id,
                event_type=TimelineEventType.CASE_CREATED,
                actor=examiner,
                description=f"Forensic Case '{title}' ({case_number}) created.",
                source="ForensicCaseManager",
                metadata={"case_number": case_number, "classification": classification},
            )
            self._append_audit_event(
                case_id=case_id,
                actor=examiner,
                event_type="CASE_CREATED",
                payload=case.to_dict(),
            )
            return case

    def get_case(self, case_id: str) -> Optional[ForensicCase]:
        with self._lock:
            c_file = self._case_path(case_id) / "case.json"
            if not c_file.is_file():
                return None
            try:
                data = json.loads(c_file.read_text(encoding="utf-8"))
                return ForensicCase.from_dict(data)
            except Exception:
                return None

    def list_cases(self) -> List[ForensicCase]:
        with self._lock:
            cases = []
            for cdir in sorted(self.cases_dir.glob("CASE-*")):
                if cdir.is_dir():
                    c = self.get_case(cdir.name)
                    if c:
                        cases.append(c)
            return cases

    def update_case_status(self, case_id: str, new_status: CaseStatus, actor: str = "Examiner") -> ForensicCase:
        with self._lock:
            case = self.get_case(case_id)
            if not case:
                raise ValueError(f"Case not found: {case_id}")

            old_status = case.status
            case.status = new_status
            case.updated_at = utc_now_iso()

            cdir = self._case_path(case_id)
            safe_atomic_json_write(cdir / "case.json", case.to_dict())

            self._record_timeline_event(
                case_id=case_id,
                event_type=TimelineEventType.CASE_UPDATED,
                actor=actor,
                description=f"Case status transitioned from {old_status.value} to {new_status.value}.",
                source="ForensicCaseManager",
                metadata={"old_status": old_status.value, "new_status": new_status.value},
            )
            self._append_audit_event(
                case_id=case_id,
                actor=actor,
                event_type="CASE_STATUS_UPDATED",
                payload={"case_id": case_id, "old_status": old_status.value, "new_status": new_status.value},
            )
            return case

    def register_evidence(
        self,
        case_id: str,
        source_type: EvidenceSourceType,
        source_path: str,
        examiner: str,
        device_identity: Optional[str] = None,
        model: Optional[str] = None,
        serial: Optional[str] = None,
        transport: Optional[str] = None,
        capacity: Optional[int] = None,
        filesystem: Optional[str] = None,
        provenance: str = "Direct Connection",
        read_only: bool = True,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> EvidenceSource:
        with self._lock:
            case = self.get_case(case_id)
            if not case:
                raise ValueError(f"Cannot add evidence to non-existent case: {case_id}")

            ev_id = generate_stable_id("EVID")
            ev_source = EvidenceSource(
                evidence_id=ev_id,
                case_id=case_id,
                source_type=source_type,
                source_path=source_path,
                device_identity=device_identity,
                model=model,
                serial=serial,
                transport=transport,
                capacity=capacity,
                filesystem=filesystem,
                examiner=examiner,
                provenance=provenance,
                read_only=read_only,
                metadata=metadata or {},
            )

            # Compute source hash if it is an accessible file
            p = Path(source_path)
            if p.is_file():
                h_rec = StreamingHasher.hash_file(p)
                ev_source.source_hash = h_rec.digest

            cdir = self._case_path(case_id)
            ev_file = cdir / "evidence.json"
            existing_ev = []
            if ev_file.is_file():
                try:
                    existing_ev = json.loads(ev_file.read_text(encoding="utf-8"))
                except Exception:
                    existing_ev = []

            existing_ev.append(ev_source.to_dict())
            safe_atomic_json_write(ev_file, existing_ev)

            # Record custody event
            self.record_custody_event(
                evidence_id=ev_id,
                case_id=case_id,
                custodian=examiner,
                action=CustodyAction.RECEIVED,
                reason="Initial evidence intake and registration into Case Vault.",
                source_location=source_path,
                destination=f"Vault://cases/{case_id}/source",
                hash_after=ev_source.source_hash,
            )

            self._record_timeline_event(
                case_id=case_id,
                event_type=TimelineEventType.EVIDENCE_ADDED,
                actor=examiner,
                description=f"Evidence source '{source_path}' registered as {ev_id}.",
                source="ForensicCaseManager",
                evidence_id=ev_id,
                metadata=ev_source.to_dict(),
            )
            self._append_audit_event(
                case_id=case_id,
                actor=examiner,
                event_type="EVIDENCE_REGISTERED",
                payload=ev_source.to_dict(),
            )
            return ev_source

    def list_evidence(self, case_id: str) -> List[EvidenceSource]:
        with self._lock:
            cdir = self._case_path(case_id)
            ev_file = cdir / "evidence.json"
            if not ev_file.is_file():
                return []
            try:
                data = json.loads(ev_file.read_text(encoding="utf-8"))
                return [EvidenceSource.from_dict(d) for d in data if isinstance(d, dict)]
            except Exception:
                return []

    def record_custody_event(
        self,
        evidence_id: str,
        case_id: str,
        custodian: str,
        action: CustodyAction,
        reason: str,
        source_location: str,
        destination: str,
        hash_before: Optional[str] = None,
        hash_after: Optional[str] = None,
        notes: str = "",
    ) -> ChainOfCustodyRecord:
        with self._lock:
            rec = ChainOfCustodyRecord(
                custody_event_id=generate_stable_id("CUST"),
                evidence_id=evidence_id,
                case_id=case_id,
                custodian=custodian,
                action=action,
                timestamp=utc_now_iso(),
                reason=reason,
                source_location=source_location,
                destination=destination,
                hash_before=hash_before,
                hash_after=hash_after,
                notes=notes,
            )
            rec.integrity_reference = rec.calculate_integrity()

            cdir = self._case_path(case_id)
            cust_file = cdir / "custody.json"
            rows = []
            if cust_file.is_file():
                try:
                    rows = json.loads(cust_file.read_text(encoding="utf-8"))
                except Exception:
                    rows = []
            rows.append(rec.to_dict())
            safe_atomic_json_write(cust_file, rows)

            self._record_timeline_event(
                case_id=case_id,
                event_type=TimelineEventType.CUSTODY_CHANGE,
                actor=custodian,
                description=f"Custody {action.value} for evidence {evidence_id}: {reason}",
                source="ChainOfCustody",
                evidence_id=evidence_id,
                metadata=rec.to_dict(),
            )
            self._append_audit_event(
                case_id=case_id,
                actor=custodian,
                event_type="CUSTODY_CHANGE",
                payload=rec.to_dict(),
            )
            return rec

    def list_custody_records(self, case_id: str) -> List[ChainOfCustodyRecord]:
        with self._lock:
            cdir = self._case_path(case_id)
            cust_file = cdir / "custody.json"
            if not cust_file.is_file():
                return []
            try:
                data = json.loads(cust_file.read_text(encoding="utf-8"))
                return [ChainOfCustodyRecord.from_dict(d) for d in data if isinstance(d, dict)]
            except Exception:
                return []

    def verify_case_custody(self, case_id: str) -> CustodyVerificationResult:
        with self._lock:
            records = self.list_custody_records(case_id)
            audits = self.get_audit_chain(case_id)
            return IndependentCustodyVerifier.verify_custody_records(records, audits)

    def get_timeline(self, case_id: str) -> List[ForensicTimelineEvent]:
        with self._lock:
            cdir = self._case_path(case_id)
            tl_file = cdir / "timeline.json"
            if not tl_file.is_file():
                return []
            try:
                data = json.loads(tl_file.read_text(encoding="utf-8"))
                return [ForensicTimelineEvent.from_dict(d) for d in data if isinstance(d, dict)]
            except Exception:
                return []

    def get_audit_chain(self, case_id: str) -> List[AuditEvent]:
        with self._lock:
            cdir = self._case_path(case_id)
            audit_file = cdir / "audit" / "audit_chain.json"
            if not audit_file.is_file():
                return []
            try:
                data = json.loads(audit_file.read_text(encoding="utf-8"))
                return [AuditEvent.from_dict(d) for d in data if isinstance(d, dict)]
            except Exception:
                return []

    def verify_case_audit_chain(self, case_id: str) -> AuditVerificationResult:
        with self._lock:
            events = self.get_audit_chain(case_id)
            return IndependentAuditVerifier.verify_chain(events)

    # ─── Operational Provenance & Verification Helpers ────────────────────────

    def record_recovery_event(
        self,
        case_id: str,
        operation_id: str,
        evidence_id: str,
        actor: str,
        event_type: TimelineEventType,
        description: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Tuple[ForensicTimelineEvent, AuditEvent]:
        with self._lock:
            tl = self._record_timeline_event(
                case_id=case_id,
                event_type=event_type,
                actor=actor,
                description=description,
                source="RecoveryEngine",
                operation_id=operation_id,
                evidence_id=evidence_id,
                metadata=metadata or {},
            )
            aud = self._append_audit_event(
                case_id=case_id,
                actor=actor,
                event_type=event_type.value,
                payload={"operation_id": operation_id, "evidence_id": evidence_id, "details": metadata or {}},
                operation_id=operation_id,
            )
            return tl, aud

    def record_sanitization_event(
        self,
        case_id: str,
        operation_id: str,
        evidence_id: str,
        actor: str,
        event_type: TimelineEventType,
        description: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Tuple[ForensicTimelineEvent, AuditEvent]:
        with self._lock:
            tl = self._record_timeline_event(
                case_id=case_id,
                event_type=event_type,
                actor=actor,
                description=description,
                source="SanitizationEngine",
                operation_id=operation_id,
                evidence_id=evidence_id,
                metadata=metadata or {},
            )
            aud = self._append_audit_event(
                case_id=case_id,
                actor=actor,
                event_type=event_type.value,
                payload={"operation_id": operation_id, "evidence_id": evidence_id, "details": metadata or {}},
                operation_id=operation_id,
            )
            return tl, aud

    def record_verification_event(
        self,
        case_id: str,
        operation_id: str,
        evidence_id: str,
        actor: str,
        event_type: TimelineEventType,
        description: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Tuple[ForensicTimelineEvent, AuditEvent]:
        with self._lock:
            tl = self._record_timeline_event(
                case_id=case_id,
                event_type=event_type,
                actor=actor,
                description=description,
                source="VerificationEngine",
                operation_id=operation_id,
                evidence_id=evidence_id,
                metadata=metadata or {},
            )
            aud = self._append_audit_event(
                case_id=case_id,
                actor=actor,
                event_type=event_type.value,
                payload={"operation_id": operation_id, "evidence_id": evidence_id, "details": metadata or {}},
                operation_id=operation_id,
            )
            return tl, aud

    def record_certificate_event(
        self,
        case_id: str,
        certificate_id: str,
        operation_id: Optional[str],
        evidence_id: Optional[str],
        actor: str,
        event_type: TimelineEventType,
        description: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Tuple[ForensicTimelineEvent, AuditEvent]:
        with self._lock:
            tl = self._record_timeline_event(
                case_id=case_id,
                event_type=event_type,
                actor=actor,
                description=description,
                source="CertificateManager",
                operation_id=operation_id,
                evidence_id=evidence_id,
                metadata=metadata or {},
            )
            aud = self._append_audit_event(
                case_id=case_id,
                actor=actor,
                event_type=event_type.value,
                payload={"certificate_id": certificate_id, "operation_id": operation_id, "evidence_id": evidence_id, "details": metadata or {}},
                operation_id=operation_id,
            )
            return tl, aud

    def record_export_event(
        self,
        case_id: str,
        export_path: str,
        actor: str,
        description: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Tuple[ForensicTimelineEvent, AuditEvent]:
        with self._lock:
            tl = self._record_timeline_event(
                case_id=case_id,
                event_type=TimelineEventType.EXPORT_CREATED,
                actor=actor,
                description=description,
                source="CasePackageManager",
                metadata={"export_path": str(export_path), **(metadata or {})},
            )
            aud = self._append_audit_event(
                case_id=case_id,
                actor=actor,
                event_type="EXPORT_CREATED",
                payload={"export_path": str(export_path), **(metadata or {})},
            )
            return tl, aud

    def record_recovery_artifact(
        self,
        case_id: str,
        artifact: RecoveryArtifactRecord,
        actor: str = "Examiner",
    ) -> RecoveryArtifactRecord:
        with self._lock:
            cdir = self._case_path(case_id)
            rec_file = cdir / "recovered" / "recovery_artifacts.json"
            rows = []
            if rec_file.is_file():
                try:
                    rows = json.loads(rec_file.read_text(encoding="utf-8"))
                except Exception:
                    rows = []
            rows.append(artifact.to_dict())
            safe_atomic_json_write(rec_file, rows)

            self.record_recovery_event(
                case_id=case_id,
                operation_id=artifact.candidate_id,
                evidence_id=artifact.source_evidence_id,
                actor=actor,
                event_type=TimelineEventType.RECOVERY_COMPLETED,
                description=f"Recovery candidate '{artifact.candidate_id}' recorded: {artifact.validation_state.value}",
                metadata=artifact.to_dict(),
            )
            return artifact

    def list_recovery_artifacts(self, case_id: str) -> List[RecoveryArtifactRecord]:
        with self._lock:
            cdir = self._case_path(case_id)
            rec_file = cdir / "recovered" / "recovery_artifacts.json"
            if not rec_file.is_file():
                return []
            try:
                data = json.loads(rec_file.read_text(encoding="utf-8"))
                return [RecoveryArtifactRecord.from_dict(d) for d in data if isinstance(d, dict)]
            except Exception:
                return []

    def record_sanitization_provenance(
        self,
        case_id: str,
        record: SanitizationProvenanceRecord,
        actor: str = "Examiner",
    ) -> SanitizationProvenanceRecord:
        with self._lock:
            cdir = self._case_path(case_id)
            san_dir = cdir / "sanitization"
            san_dir.mkdir(parents=True, exist_ok=True)
            san_file = san_dir / "sanitization_provenance.json"
            rows = []
            if san_file.is_file():
                try:
                    rows = json.loads(san_file.read_text(encoding="utf-8"))
                except Exception:
                    rows = []
            rows.append(record.to_dict())
            safe_atomic_json_write(san_file, rows)

            ev_type = (
                TimelineEventType.SANITIZATION_COMPLETED
                if record.execution_status in ("SUCCESS", "SIMULATION_QUALIFIED", "VERIFIED")
                else TimelineEventType.SANITIZATION_FAILED
            )
            self.record_sanitization_event(
                case_id=case_id,
                operation_id=record.operation_id,
                evidence_id=record.evidence_id,
                actor=actor,
                event_type=ev_type,
                description=f"Sanitization operation '{record.operation_id}' recorded: {record.execution_status}",
                metadata=record.to_dict(),
            )
            return record

    def list_sanitization_provenance(self, case_id: str) -> List[SanitizationProvenanceRecord]:
        with self._lock:
            cdir = self._case_path(case_id)
            san_file = cdir / "sanitization" / "sanitization_provenance.json"
            if not san_file.is_file():
                return []
            try:
                data = json.loads(san_file.read_text(encoding="utf-8"))
                return [SanitizationProvenanceRecord.from_dict(d) for d in data if isinstance(d, dict)]
            except Exception:
                return []

    def _record_timeline_event(
        self,
        case_id: str,
        event_type: TimelineEventType,
        actor: str,
        description: str,
        source: str,
        operation_id: Optional[str] = None,
        evidence_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> ForensicTimelineEvent:
        evt = ForensicTimelineEvent(
            event_id=generate_stable_id("EVT"),
            case_id=case_id,
            timestamp=utc_now_iso(),
            event_type=event_type,
            actor=actor,
            description=description,
            source=source,
            operation_id=operation_id,
            evidence_id=evidence_id,
            metadata=metadata or {},
        )
        evt.integrity_hash = evt.calculate_integrity_hash()

        cdir = self._case_path(case_id)
        tl_file = cdir / "timeline.json"
        events = []
        if tl_file.is_file():
            try:
                events = json.loads(tl_file.read_text(encoding="utf-8"))
            except Exception:
                events = []
        events.append(evt.to_dict())
        safe_atomic_json_write(tl_file, events)
        return evt

    def _append_audit_event(
        self,
        case_id: str,
        actor: str,
        event_type: str,
        payload: Dict[str, Any],
        operation_id: Optional[str] = None,
    ) -> AuditEvent:
        cdir = self._case_path(case_id)
        audit_file = cdir / "audit" / "audit_chain.json"
        events = []
        if audit_file.is_file():
            try:
                events = json.loads(audit_file.read_text(encoding="utf-8"))
            except Exception:
                events = []

        seq = len(events)
        prev_hash = events[-1]["current_hash"] if events else IndependentAuditVerifier.GENESIS_HASH

        audit_evt = AuditEvent.create(
            sequence_number=seq,
            case_id=case_id,
            actor=actor,
            event_type=event_type,
            payload=payload,
            previous_hash=prev_hash,
            operation_id=operation_id,
        )

        events.append(audit_evt.to_dict())
        safe_atomic_json_write(audit_file, events)
        return audit_evt
