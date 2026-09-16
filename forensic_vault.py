"""
DREX-V2 Forensic Case Management, Evidence Vault, Timeline & Audit Foundation
=============================================================================
Provides production-grade forensic data models and runtime services for:
- Forensic Cases (lifecycle, metadata, examiner attribution)
- Evidence Sources (physical drives, disk images, files, partitions, fixtures)
- Streaming Cryptographic Hasher (SHA-256 / SHA-512, memory-bounded chunking)
- Forensic Timeline (chronological typed events, integrity hashes)
- Hash-Chained Audit Ledger (cryptographic SHA-256 hash chaining, independent audit verifier)
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
import zipfile
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
    """DREX canonical JSON serialization using UTF-8, sorted object keys, and compact separators."""
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
            with os.fdopen(fd, "w", encoding="utf-8", newline="") as handle:
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
    def export_package(cls, case_dir: Path, output_tar_path: Union[str, Path], schema_version: str = "2.0") -> Path:
        case_dir = Path(case_dir).resolve()
        out_path = Path(output_tar_path).resolve()
        out_path.parent.mkdir(parents=True, exist_ok=True)

        manifest_entries: Dict[str, Dict[str, Any]] = {}
        objects_list: List[Dict[str, Any]] = []

        # 1. Build manifest of all files in case directory
        for f in sorted(case_dir.rglob("*")):
            if f.is_file():
                rel = f.relative_to(case_dir).as_posix()
                if rel in ("manifest.json", "manifest.sha256", "manifest.tmp.json"):
                    continue
                h_rec = StreamingHasher.hash_file(f)
                manifest_entries[rel] = {
                    "size_bytes": h_rec.byte_count,
                    "sha256": h_rec.digest,
                }
                # Determine object type from parent directory
                parent_dir = rel.split("/")[0].upper() if "/" in rel else "ROOT"
                objects_list.append({
                    "object_id": f"OBJ-{h_rec.digest[:12].upper()}",
                    "relative_path": rel,
                    "object_type": parent_dir,
                    "size_bytes": h_rec.byte_count,
                    "sha256": h_rec.digest,
                })

        # Deterministically sort objects by relative_path
        objects_list.sort(key=lambda o: o["relative_path"])

        manifest = {
            "schema_version": schema_version,
            "drex_version": "1.0.0",
            "export_timestamp": utc_now_iso(),
            "case_directory": case_dir.name,
            "case_id": case_dir.name,
            "total_files": len(manifest_entries),
            "total_declared_objects": len(objects_list),
            "files": manifest_entries,
            "objects": objects_list,
        }

        manifest_file = case_dir / "manifest.json"
        manifest_content = json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False)
        safe_atomic_write(manifest_file, manifest_content)

        # Generate manifest.sha256 root digest
        manifest_sha = hashlib.sha256(manifest_content.encode("utf-8")).hexdigest()
        manifest_sha_file = case_dir / "manifest.sha256"
        safe_atomic_write(manifest_sha_file, f"{manifest_sha}  manifest.json\n")

        # Include all files including manifest and manifest.sha256 in tar
        temp_tar = out_path.with_suffix(".tmp.tar.gz")
        with tarfile.open(temp_tar, "w:gz") as tar:
            for f in sorted(case_dir.rglob("*")):
                if f.is_file() and not f.name.endswith(".tmp") and not f.name.endswith(".tmp.json"):
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
            s_ver = manifest.get("schema_version")
            if s_ver not in (1, "1", "1.0", 2, "2", "2.0"):
                return PackageValidationResult(
                    status=PackageValidationStatus.SCHEMA_MISMATCH,
                    manifest_valid=False,
                    audit_chain_valid=False,
                    objects_verified=0,
                    objects_corrupted=0,
                    error_message=f"Unsupported package schema version: {manifest.get('schema_version')}",
                )

            files_map = manifest.get("files")
            if files_map is None and "objects" in manifest:
                files_map = {obj["relative_path"]: {"size_bytes": obj.get("size_bytes"), "sha256": obj.get("sha256")} for obj in manifest["objects"]}
            elif files_map is None:
                files_map = {}

            verified = 0
            corrupted = 0

            # 2. Re-verify SHA-256 digests of all package files
            for rel_posix, meta in files_map.items():
                if rel_posix in ("manifest.json", "manifest.sha256"):
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
    def __init__(self, base_data_dir: Union[str, Path]):
        self.base_dir = Path(base_data_dir).resolve()
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

    def add_recovery_candidate(
        self,
        case_id: str,
        artifact: RecoveryArtifactRecord,
        payload_bytes: Optional[bytes] = None,
        actor: str = "Examiner",
    ) -> RecoveryArtifactRecord:
        """Atomically persist a discovery/reconstruction candidate and its raw payload."""
        with self._lock:
            cdir = self._case_path(case_id)
            cand_dir = cdir / "candidates"
            cand_dir.mkdir(parents=True, exist_ok=True)

            if payload_bytes is not None:
                p_file = cand_dir / f"{artifact.candidate_id}.bin"
                p_file.write_bytes(payload_bytes)
                artifact.output_size = len(payload_bytes)
                artifact.output_hash = hashlib.sha256(payload_bytes).hexdigest()

            cand_file = cdir / "candidates.json"
            rows = []
            if cand_file.is_file():
                try:
                    rows = json.loads(cand_file.read_text(encoding="utf-8"))
                except Exception:
                    rows = []
            rows = [r for r in rows if r.get("candidate_id") != artifact.candidate_id]
            rows.append(artifact.to_dict())
            safe_atomic_json_write(cand_file, rows)
            return artifact

    def list_recovery_candidates(
        self,
        case_id: str,
        limit: int = 50,
        offset: int = 0,
        file_type: Optional[str] = None,
        validation_state: Optional[str] = None,
    ) -> List[RecoveryArtifactRecord]:
        """List and filter candidate records for a case with pagination."""
        with self._lock:
            cdir = self._case_path(case_id)
            cand_file = cdir / "candidates.json"
            if not cand_file.is_file():
                return []
            try:
                data = json.loads(cand_file.read_text(encoding="utf-8"))
                recs = [RecoveryArtifactRecord.from_dict(d) for d in data if isinstance(d, dict)]
                if file_type:
                    recs = [r for r in recs if r.carving_method.upper() == file_type.upper() or (r.filesystem_origin and file_type.lower() in r.filesystem_origin.lower())]
                if validation_state:
                    recs = [r for r in recs if r.validation_state.value.upper() == validation_state.upper()]
                return recs[offset : offset + limit]
            except Exception:
                return []

    def get_recovery_candidate(self, case_id: str, candidate_id: str) -> Optional[RecoveryArtifactRecord]:
        """Get candidate record by ID."""
        with self._lock:
            cdir = self._case_path(case_id)
            cand_file = cdir / "candidates.json"
            if not cand_file.is_file():
                return None
            try:
                data = json.loads(cand_file.read_text(encoding="utf-8"))
                for d in data:
                    if d.get("candidate_id") == candidate_id:
                        return RecoveryArtifactRecord.from_dict(d)
                return None
            except Exception:
                return None

    def get_recovery_candidate_payload(self, case_id: str, candidate_id: str) -> Optional[bytes]:
        """Get candidate raw bytes if available."""
        with self._lock:
            cdir = self._case_path(case_id)
            p_file = cdir / "candidates" / f"{candidate_id}.bin"
            if p_file.is_file():
                return p_file.read_bytes()
            return None

    def promote_recovery_candidate_to_vault(
        self,
        case_id: str,
        candidate_id: str,
        examiner: str,
        destination_filename: Optional[str] = None,
        notes: str = "",
    ) -> Tuple[RecoveryArtifactRecord, VaultObject]:
        """
        Promote a candidate to an authenticated VaultObject in the Evidence Vault.
        Validates structural integrity, writes to recovered vault, and records audit chain event.
        """
        with self._lock:
            cand = self.get_recovery_candidate(case_id, candidate_id)
            if not cand:
                raise KeyError(f"Recovery candidate '{candidate_id}' not found in case '{case_id}'.")

            payload = self.get_recovery_candidate_payload(case_id, candidate_id)
            if not payload:
                raise ValueError(f"Recovery candidate payload for '{candidate_id}' is empty or missing.")

            # Validate structural integrity via FormatRegistry
            from validators import FormatRegistry, CandidateState
            fmt = cand.carving_method.upper()
            if not fmt and cand.filesystem_origin and "." in cand.filesystem_origin:
                fmt = cand.filesystem_origin.split(".")[-1].upper()
            
            val_res = FormatRegistry.validate_buffer(fmt, payload)
            if not val_res.is_valid:
                v_state = getattr(val_res, 'state', CandidateState.DISCOVERED).value
                v_conf = val_res.evidence.composite_score() if hasattr(val_res, 'evidence') else 0.0
                raise ValueError(
                    f"Structural validation rejected candidate '{candidate_id}' for format {fmt}: "
                    f"{v_state} (Confidence: {v_conf:.2f})"
                )

            vault = self.get_vault(case_id)
            dest_name = sanitize_filename(destination_filename or cand.filesystem_origin or f"recovered_{candidate_id}.bin")

            with tempfile.NamedTemporaryFile(delete=False) as tf:
                tf.write(payload)
                tmp_p = Path(tf.name)
            try:
                vault_obj = vault.store_file(
                    case_id=case_id,
                    source_path=tmp_p,
                    object_type=VaultObjectType.RECOVERED,
                    destination_name=dest_name,
                    source_evidence_id=cand.source_evidence_id,
                    generating_operation_id=cand.candidate_id,
                    metadata={"candidate_id": candidate_id, "confidence": cand.evidence_confidence_score, "notes": notes},
                    copy_file=True,
                )
            finally:
                if tmp_p.exists():
                    tmp_p.unlink(missing_ok=True)

            # Update candidate state to RECOVERED_ARTIFACT
            cand.validation_state = RecoveryCandidateState.RECOVERED_ARTIFACT
            self.add_recovery_candidate(case_id, cand, payload, actor=examiner)

            # Record timeline and audit events
            self._record_timeline_event(
                case_id=case_id,
                event_type=TimelineEventType.RECOVERY_COMPLETED,
                actor=examiner,
                description=f"Candidate '{candidate_id}' validated and ingested into Vault as '{dest_name}'.",
                source="ForensicVault",
                evidence_id=cand.source_evidence_id,
                metadata={"vault_object_id": vault_obj.object_id, "sha256": vault_obj.sha256_hash, "size": vault_obj.size_bytes},
            )
            self._append_audit_event(
                case_id=case_id,
                actor=examiner,
                event_type="EVIDENCE_ACQUIRED",
                payload={
                    "candidate_id": candidate_id,
                    "vault_object_id": vault_obj.object_id,
                    "sha256": vault_obj.sha256_hash,
                    "size_bytes": vault_obj.size_bytes,
                    "destination_name": dest_name,
                },
                operation_id=cand.candidate_id,
            )

            return cand, vault_obj

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

    def get_latest_audit_hash(self, case_id: str) -> str:
        """Retrieve the latest cryptographic SHA-256 hash in the case audit chain."""
        with self._lock:
            cdir = self._case_path(case_id)
            audit_file = cdir / "audit" / "audit_chain.json"
            if audit_file.is_file():
                try:
                    events = json.loads(audit_file.read_text(encoding="utf-8"))
                    if events and isinstance(events, list):
                        return events[-1].get("current_hash", IndependentAuditVerifier.GENESIS_HASH)
                except Exception:
                    pass
            return IndependentAuditVerifier.GENESIS_HASH

    def store_certificate(
        self,
        case_id: str,
        cert_data: Dict[str, Any],
        pdf_bytes: bytes,
        actor: str = "Forensic Examiner",
        operation_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Atomically persist forensic certificate JSON and PDF into case vault, register vault objects, and append audit event."""
        with self._lock:
            case = self.get_case(case_id)
            if not case:
                raise ValueError(f"Case not found: {case_id}")

            cert_id = cert_data.get("certificate_id")
            if not cert_id:
                raise ValueError("Certificate data missing certificate_id")

            sanitized_cert_id = sanitize_filename(cert_id)
            cdir = self._case_path(case_id)
            cert_dir = cdir / "certificates"
            cert_dir.mkdir(parents=True, exist_ok=True)

            json_path = cert_dir / f"{sanitized_cert_id}.json"
            pdf_path = cert_dir / f"{sanitized_cert_id}.pdf"

            # Compute PDF SHA-256
            pdf_sha256 = hashlib.sha256(pdf_bytes).hexdigest()
            cert_data["pdf_sha256"] = pdf_sha256

            # Compute JSON bytes and SHA-256
            json_str = json.dumps(cert_data, indent=2, sort_keys=True, ensure_ascii=False)
            json_sha256 = hashlib.sha256(json_str.encode("utf-8")).hexdigest()
            cert_data["json_sha256"] = json_sha256

            # Atomic crash-safe writes
            safe_atomic_json_write(json_path, cert_data)
            safe_atomic_write(pdf_path, pdf_bytes)

            # Register in Vault
            vault = self.get_vault(case_id)
            v_obj_json = VaultObject(
                object_id=generate_stable_id("VLT-CERT-JSON"),
                case_id=case_id,
                object_type=VaultObjectType.CERTIFICATE,
                relative_path=str(json_path.relative_to(cdir)),
                size_bytes=len(json_str.encode("utf-8")),
                sha256_hash=json_sha256,
                created_at=utc_now_iso(),
                generating_operation_id=operation_id,
                metadata={"certificate_id": cert_id, "format": "JSON", "signature": cert_data.get("tamper_evident_signature")},
            )
            v_obj_pdf = VaultObject(
                object_id=generate_stable_id("VLT-CERT-PDF"),
                case_id=case_id,
                object_type=VaultObjectType.CERTIFICATE,
                relative_path=str(pdf_path.relative_to(cdir)),
                size_bytes=len(pdf_bytes),
                sha256_hash=pdf_sha256,
                created_at=utc_now_iso(),
                generating_operation_id=operation_id,
                metadata={"certificate_id": cert_id, "format": "PDF"},
            )
            objs = vault.list_objects()
            objs = [o for o in objs if o.metadata.get("certificate_id") != cert_id]
            objs.extend([v_obj_json, v_obj_pdf])
            safe_atomic_json_write(vault.objects_index_file, [o.to_dict() for o in objs])

            # Record Timeline Event
            self._record_timeline_event(
                case_id=case_id,
                event_type=TimelineEventType.CERTIFICATE_CREATED,
                actor=actor,
                description=f"Cryptographic Forensic Certificate '{cert_id}' generated and signed.",
                source="ForensicCertificateEngine",
                operation_id=operation_id,
                metadata={
                    "certificate_id": cert_id,
                    "target": cert_data.get("target", {}).get("target_name"),
                    "method_id": cert_data.get("method", {}).get("method_id"),
                    "tamper_evident_signature": cert_data.get("tamper_evident_signature"),
                    "pdf_sha256": pdf_sha256,
                },
            )

            # Append Audit Event CERTIFICATE_ISSUED
            self._append_audit_event(
                case_id=case_id,
                actor=actor,
                event_type="CERTIFICATE_ISSUED",
                payload={
                    "certificate_id": cert_id,
                    "case_id": case_id,
                    "operation_id": operation_id,
                    "certificate_hash": cert_data.get("tamper_evident_signature"),
                    "event_hash": cert_data.get("audit_chain_event_hash"),
                    "pdf_hash": pdf_sha256,
                    "json_hash": json_sha256,
                    "timestamp": cert_data.get("timestamp_utc"),
                },
                operation_id=operation_id,
            )

            return cert_data

    def list_certificates(self, case_id: str) -> List[Dict[str, Any]]:
        """List all forensic certificates issued under the given case."""
        with self._lock:
            cdir = self._case_path(case_id)
            cert_dir = cdir / "certificates"
            if not cert_dir.is_dir():
                return []
            certs = []
            for jf in sorted(cert_dir.glob("*.json")):
                try:
                    cdata = json.loads(jf.read_text(encoding="utf-8"))
                    if isinstance(cdata, dict) and "certificate_id" in cdata:
                        certs.append(cdata)
                except Exception:
                    continue
            return certs

    def get_certificate(self, case_id: str, cert_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve certificate JSON record with strict path traversal protections."""
        with self._lock:
            sanitized = sanitize_filename(cert_id)
            cdir = self._case_path(case_id)
            jpath = cdir / "certificates" / f"{sanitized}.json"
            if not jpath.is_file():
                return None
            try:
                cdata = json.loads(jpath.read_text(encoding="utf-8"))
                return cdata if isinstance(cdata, dict) else None
            except Exception:
                return None

    def get_certificate_pdf_path(self, case_id: str, cert_id: str) -> Optional[Path]:
        """Retrieve path to certificate PDF artifact."""
        with self._lock:
            sanitized = sanitize_filename(cert_id)
            cdir = self._case_path(case_id)
            ppath = cdir / "certificates" / f"{sanitized}.pdf"
            if ppath.is_file():
                return ppath
            return None

    def verify_certificate(self, case_id: str, cert_id: str) -> Dict[str, Any]:
        """Independently verify certificate structure, SHA-256 integrity token, PDF hash, audit chain linkage, and case binding."""
        from certificate_engine import ForensicCertificateEngine
        with self._lock:
            details = []
            cert_data = self.get_certificate(case_id, cert_id)
            if not cert_data:
                return {
                    "certificate_id": cert_id,
                    "case_id": case_id,
                    "valid": False,
                    "certificate_hash_valid": False,
                    "pdf_hash_valid": False,
                    "audit_chain_valid": False,
                    "case_binding_valid": False,
                    "operation_binding_valid": False,
                    "verdict": "FAIL — Certificate Not Found",
                    "details": [f"Certificate record '{cert_id}' does not exist in case '{case_id}'."],
                }

            # 1. Case binding check
            bound_case_id = cert_data.get("case_id")
            case_binding_valid = (bound_case_id == case_id)
            if case_binding_valid:
                details.append("Case binding verified: certificate case_id matches target case.")
            else:
                details.append(f"Case binding MISMATCH: certificate specifies '{bound_case_id}' but queried for '{case_id}'.")

            # 2. Certificate integrity hash
            cert_hash_valid = ForensicCertificateEngine.verify_certificate_integrity(cert_data)
            if cert_hash_valid:
                details.append("Cryptographic integrity verified: SHA-256 signature binding matches canonical fields.")
            else:
                details.append("Cryptographic integrity FAILURE: signature does not match recomputed SHA-256 hash.")

            # 3. PDF Hash check
            pdf_path = self.get_certificate_pdf_path(case_id, cert_id)
            pdf_hash_valid = False
            if pdf_path and pdf_path.is_file():
                calc_pdf_sha = StreamingHasher.hash_file(pdf_path).digest
                stored_pdf_sha = cert_data.get("pdf_sha256")
                if stored_pdf_sha and calc_pdf_sha.lower() == stored_pdf_sha.lower():
                    pdf_hash_valid = True
                    details.append(f"PDF integrity verified: SHA-256 digest ({calc_pdf_sha[:16]}...) matches record.")
                else:
                    details.append(f"PDF integrity FAILURE: file digest {calc_pdf_sha} != recorded {stored_pdf_sha}.")
            else:
                details.append("PDF artifact missing from vault certificate directory.")

            # 4. Audit Chain Verification
            cert_event = None
            audit_chain_res = self.verify_case_audit_chain(case_id)
            audit_chain_valid = (audit_chain_res.status == AuditVerificationStatus.VALID)
            if audit_chain_valid:
                chain = self.get_audit_chain(case_id)
                cert_event = next((e for e in chain if e.event_type == "CERTIFICATE_ISSUED" and e.canonical_payload.get("certificate_id") == cert_id), None)
                if cert_event:
                    if cert_event.canonical_payload.get("certificate_hash") == cert_data.get("tamper_evident_signature"):
                        details.append(f"Audit chain verified: CERTIFICATE_ISSUED event {cert_event.event_id} sequence #{cert_event.sequence_number} intact.")
                    else:
                        audit_chain_valid = False
                        details.append("Audit chain mismatch: event payload certificate_hash does not match certificate signature.")
                else:
                    audit_chain_valid = False
                    details.append("Audit chain error: CERTIFICATE_ISSUED event not found in case audit chain.")
            else:
                details.append(f"Audit chain verification FAILURE: {audit_chain_res.status.value} - {audit_chain_res.details}")

            # 5. Operation Binding
            operation_binding_valid = True
            op_id = cert_data.get("operation_id")
            if cert_event:
                expected_op = cert_event.canonical_payload.get("operation_id")
                if expected_op and op_id != expected_op:
                    operation_binding_valid = False
                    details.append(f"Operation binding MISMATCH: certificate specifies '{op_id}' but audit event bound to '{expected_op}'.")
                elif op_id:
                    details.append(f"Operation binding verified: bound to operation {op_id}.")
            elif op_id:
                details.append(f"Operation binding verified: bound to operation {op_id}.")

            overall_valid = bool(
                case_binding_valid and
                cert_hash_valid and
                pdf_hash_valid and
                audit_chain_valid and
                operation_binding_valid
            )

            verdict = "PASS — Attestation Cryptographically Verified" if overall_valid else "FAIL — Integrity / Chain Failure"

            return {
                "certificate_id": cert_id,
                "case_id": case_id,
                "valid": overall_valid,
                "certificate_hash_valid": cert_hash_valid,
                "pdf_hash_valid": pdf_hash_valid,
                "audit_chain_valid": audit_chain_valid,
                "case_binding_valid": case_binding_valid,
                "operation_binding_valid": operation_binding_valid,
                "verdict": verdict,
                "details": details,
            }

    def record_validation_report(self, case_id: str, report_dict: Dict[str, Any], actor: str = "SYSTEM") -> Dict[str, Any]:
        """Persist a Validation Lab report as a case evidence artifact and append audit event."""
        with self._lock:
            case = self.get_case(case_id)
            if not case:
                raise ValueError(f"Case not found: {case_id}")
            report_id = report_dict.get("report_id") or f"VAL-{uuid.uuid4().hex[:8].upper()}"
            report_dict["report_id"] = report_id
            report_dict["case_id"] = case_id
            if "timestamp_utc" not in report_dict:
                report_dict["timestamp_utc"] = utc_now_iso()

            # Canonical SHA-256 for report content
            clean_copy = {k: v for k, v in report_dict.items() if k not in ("report_hash", "audit_chain_event_hash", "audit_chain_prior_hash")}
            canonical_json = json.dumps(clean_copy, sort_keys=True, separators=(",", ":"))
            report_hash = hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()
            report_dict["report_hash"] = report_hash

            cdir = self._case_path(case_id)
            reports_dir = cdir / "reports"
            reports_dir.mkdir(parents=True, exist_ok=True)
            sanitized_id = sanitize_filename(report_id)
            jpath = reports_dir / f"{sanitized_id}.json"
            safe_atomic_json_write(jpath, report_dict)

            # Register in EvidenceVault
            vault = self.get_vault(case_id)
            v_obj = VaultObject(
                object_id=generate_stable_id("VLT-VAL"),
                case_id=case_id,
                object_type=VaultObjectType.REPORT,
                relative_path=str(jpath.relative_to(cdir)),
                size_bytes=jpath.stat().st_size,
                sha256_hash=report_hash,
                created_at=utc_now_iso(),
                metadata={"report_id": report_id, "type": "VALIDATION_LAB_REPORT"},
            )
            objs = vault.list_objects()
            objs = [o for o in objs if o.metadata.get("report_id") != report_id]
            objs.append(v_obj)
            safe_atomic_json_write(vault.objects_index_file, [o.to_dict() for o in objs])

            # Timeline event
            self._record_timeline_event(
                case_id=case_id,
                event_type=TimelineEventType.VERIFICATION_COMPLETED,
                actor=actor,
                description=f"Validation Lab Report '{report_id}' compiled: overall_verdict={report_dict.get('overall_verdict')}",
                source="ValidationLabEngine",
                metadata={"report_id": report_id, "report_hash": report_hash, "overall_verdict": report_dict.get("overall_verdict")},
            )

            # Audit event
            event_type = "VALIDATION_RUN_COMPLETED" if report_dict.get("overall_verdict") in ("ALL_REQUIRED_PASS", "HARDWARE_LIMITED", "PASS") else "VALIDATION_RUN_FAILED"
            audit_evt = self._append_audit_event(
                case_id=case_id,
                actor=actor,
                event_type=event_type,
                payload={
                    "report_id": report_id,
                    "case_id": case_id,
                    "report_hash": report_hash,
                    "overall_verdict": report_dict.get("overall_verdict"),
                    "total_tests": report_dict.get("total_tests", 0),
                    "total_passed": report_dict.get("total_passed", 0),
                    "timestamp": report_dict.get("timestamp_utc"),
                },
            )
            report_dict["audit_chain_event_hash"] = audit_evt.current_hash
            report_dict["audit_chain_prior_hash"] = audit_evt.previous_hash
            safe_atomic_json_write(jpath, report_dict)
            return report_dict

    def list_validation_reports(self, case_id: str) -> List[Dict[str, Any]]:
        """List all Validation Lab reports registered under case."""
        with self._lock:
            cdir = self._case_path(case_id)
            rdir = cdir / "reports"
            if not rdir.is_dir():
                return []
            reports = []
            for jf in sorted(rdir.glob("*.json")):
                try:
                    data = json.loads(jf.read_text(encoding="utf-8"))
                    if isinstance(data, dict) and "report_id" in data:
                        reports.append(data)
                except Exception:
                    continue
            return reports

    def get_validation_report(self, case_id: str, report_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve a Validation Lab report by ID with path traversal protection."""
        with self._lock:
            sanitized = sanitize_filename(report_id)
            cdir = self._case_path(case_id)
            jpath = cdir / "reports" / f"{sanitized}.json"
            if not jpath.is_file():
                return None
            try:
                data = json.loads(jpath.read_text(encoding="utf-8"))
                return data if isinstance(data, dict) else None
            except Exception:
                return None

    def verify_validation_report(self, case_id: str, report_id: str) -> Dict[str, Any]:
        """Independently verify report SHA-256 integrity, audit chain linkage, and case binding."""
        with self._lock:
            details = []
            rep = self.get_validation_report(case_id, report_id)
            if not rep:
                return {
                    "report_id": report_id,
                    "case_id": case_id,
                    "valid": False,
                    "report_hash_valid": False,
                    "audit_chain_valid": False,
                    "case_binding_valid": False,
                    "verdict": "FAIL — Report Not Found",
                    "details": [f"Validation report '{report_id}' not found in case '{case_id}'."],
                }

            # 1. Case binding check
            bound_case = rep.get("case_id")
            case_binding_valid = (bound_case == case_id)
            if case_binding_valid:
                details.append("Case binding verified: report case_id matches target case.")
            else:
                details.append(f"Case binding MISMATCH: report specifies '{bound_case}' but queried for '{case_id}'.")

            # 2. Hash integrity check
            stored_hash = rep.get("report_hash")
            clean_copy = {k: v for k, v in rep.items() if k not in ("report_hash", "audit_chain_event_hash", "audit_chain_prior_hash")}
            canonical_json = json.dumps(clean_copy, sort_keys=True, separators=(",", ":"))
            calc_hash = hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()
            hash_valid = (stored_hash is not None and (stored_hash == calc_hash))
            if hash_valid:
                details.append("Report hash verified: SHA-256 digest matches canonical payload.")
            else:
                details.append(f"Report hash MISMATCH: calculated {calc_hash} != stored {stored_hash}.")

            # 3. Audit chain verification
            audit_res = self.verify_case_audit_chain(case_id)
            audit_chain_valid = (audit_res.status == AuditVerificationStatus.VALID)
            if audit_chain_valid:
                chain = self.get_audit_chain(case_id)
                evt = next((e for e in chain if e.event_type in ("VALIDATION_RUN_COMPLETED", "VALIDATION_RUN_FAILED") and e.canonical_payload.get("report_id") == report_id), None)
                if evt:
                    if evt.canonical_payload.get("report_hash") == stored_hash:
                        details.append(f"Audit chain verified: {evt.event_type} event {evt.event_id} sequence #{evt.sequence_number} intact.")
                    else:
                        audit_chain_valid = False
                        details.append("Audit event payload report_hash does not match report stored hash.")
                else:
                    audit_chain_valid = False
                    details.append(f"Audit chain error: validation event not found for report '{report_id}'.")
            else:
                details.append(f"Audit chain verification FAILURE: {audit_res.status.value} - {audit_res.details}")

            overall_valid = bool(case_binding_valid and hash_valid and audit_chain_valid)
            verdict = "PASS — Validation Report Cryptographically Verified" if overall_valid else "FAIL — Integrity / Audit Chain Failure"

            return {
                "report_id": report_id,
                "case_id": case_id,
                "valid": overall_valid,
                "report_hash_valid": hash_valid,
                "audit_chain_valid": audit_chain_valid,
                "case_binding_valid": case_binding_valid,
                "verdict": verdict,
                "details": details,
            }

    def record_performance_benchmark(self, case_id: str, benchmark_dict: Dict[str, Any], actor: str = "SYSTEM") -> Dict[str, Any]:
        """Persist a Performance Lab benchmark result and record audit event."""
        with self._lock:
            case = self.get_case(case_id)
            if not case:
                raise ValueError(f"Case not found: {case_id}")
            bench_id = benchmark_dict.get("benchmark_id") or f"BENCH-{uuid.uuid4().hex[:8].upper()}"
            benchmark_dict["benchmark_id"] = bench_id
            benchmark_dict["case_id"] = case_id
            if "timestamp_utc" not in benchmark_dict:
                benchmark_dict["timestamp_utc"] = utc_now_iso()

            clean_copy = {k: v for k, v in benchmark_dict.items() if k not in ("benchmark_hash", "audit_chain_event_hash", "audit_chain_prior_hash")}
            canonical_json = json.dumps(clean_copy, sort_keys=True, separators=(",", ":"))
            bench_hash = hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()
            benchmark_dict["benchmark_hash"] = bench_hash

            cdir = self._case_path(case_id)
            bench_dir = cdir / "benchmarks"
            bench_dir.mkdir(parents=True, exist_ok=True)
            sanitized_id = sanitize_filename(bench_id)
            jpath = bench_dir / f"{sanitized_id}.json"
            safe_atomic_json_write(jpath, benchmark_dict)

            # EvidenceVault
            vault = self.get_vault(case_id)
            v_obj = VaultObject(
                object_id=generate_stable_id("VLT-BENCH"),
                case_id=case_id,
                object_type=VaultObjectType.REPORT,
                relative_path=str(jpath.relative_to(cdir)),
                size_bytes=jpath.stat().st_size,
                sha256_hash=bench_hash,
                created_at=utc_now_iso(),
                metadata={"benchmark_id": bench_id, "type": "PERFORMANCE_BENCHMARK"},
            )
            objs = vault.list_objects()
            objs = [o for o in objs if o.metadata.get("benchmark_id") != bench_id]
            objs.append(v_obj)
            safe_atomic_json_write(vault.objects_index_file, [o.to_dict() for o in objs])

            # Audit event
            audit_evt = self._append_audit_event(
                case_id=case_id,
                actor=actor,
                event_type="PERFORMANCE_BENCHMARK_COMPLETED",
                payload={
                    "benchmark_id": bench_id,
                    "case_id": case_id,
                    "benchmark_hash": bench_hash,
                    "operation_name": benchmark_dict.get("operation_name"),
                    "throughput_mb_s": benchmark_dict.get("throughput_mb_per_sec"),
                    "bounded_streaming_verified": benchmark_dict.get("bounded_streaming_verified"),
                    "timestamp": benchmark_dict.get("timestamp_utc"),
                },
            )
            benchmark_dict["audit_chain_event_hash"] = audit_evt.current_hash
            benchmark_dict["audit_chain_prior_hash"] = audit_evt.previous_hash
            safe_atomic_json_write(jpath, benchmark_dict)
            return benchmark_dict

    def create_case_backup(self, case_id: str, destination_dir: Optional[Union[Path, str]] = None) -> Tuple[Path, str]:
        """Create a sealed, verifiable ZIP backup of the case directory with a detached SHA-256 manifest."""
        with self._lock:
            case = self.get_case(case_id)
            if not case:
                raise ValueError(f"Case not found: {case_id}")
            cdir = self._case_path(case_id)
            if destination_dir:
                dpath = Path(destination_dir).resolve()
                if dpath.suffix.lower() == ".zip":
                    archive_path = dpath
                    dest = dpath.parent
                else:
                    dest = dpath
                    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
                    archive_path = dest / f"case_backup_{case_id}_{ts}.zip"
            else:
                dest = (self.base_dir / "backups").resolve()
                ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
                archive_path = dest / f"case_backup_{case_id}_{ts}.zip"
            dest.mkdir(parents=True, exist_ok=True)

            with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
                for root, _, files in os.walk(cdir):
                    for file in files:
                        fp = Path(root) / file
                        arcname = fp.relative_to(cdir)
                        zf.write(fp, arcname=str(arcname))

            archive_sha256 = StreamingHasher.hash_file(archive_path).digest
            manifest_path = dest / f"{archive_path.stem}.manifest.json"
            manifest = {
                "schema_version": "2.0",
                "backup_type": "DREX_CASE_BACKUP",
                "case_id": case_id,
                "case_number": case.case_number,
                "created_at_utc": utc_now_iso(),
                "archive_filename": archive_path.name,
                "archive_sha256": archive_sha256,
            }
            safe_atomic_json_write(manifest_path, manifest)
            return archive_path, archive_sha256

    def restore_case_backup(self, archive_path: Union[Path, str], expected_sha256: Optional[str] = None) -> ForensicCase:
        """Restore a case from a backup archive with strict integrity checks and cross-case overwrite protection."""
        with self._lock:
            archive_path = Path(archive_path)
            if not archive_path.is_file():
                raise FileNotFoundError(f"Backup archive not found: {archive_path}")

            actual_sha256 = StreamingHasher.hash_file(archive_path).digest
            if expected_sha256 and actual_sha256.lower() != expected_sha256.lower():
                raise ValueError(f"Backup archive integrity failure: SHA-256 mismatch ({actual_sha256} != {expected_sha256})")

            with zipfile.ZipFile(archive_path, "r") as zf:
                total_size = 0
                for info in zf.infolist():
                    if ".." in info.filename or info.filename.startswith(("/", "\\")):
                        raise ValueError(f"Zip slip attempt detected in backup archive: {info.filename}")
                    total_size += info.file_size
                    if total_size > 10 * 1024 * 1024 * 1024:  # 10 GB limit
                        raise ValueError("Backup archive exceeds maximum allowable uncompressed size (10 GB).")

                if "case.json" not in zf.namelist():
                    raise ValueError("Invalid backup archive: missing root 'case.json'.")

                case_raw = json.loads(zf.read("case.json").decode("utf-8"))
                case_id = case_raw.get("case_id")
                if not case_id:
                    raise ValueError("Invalid backup archive: 'case.json' missing case_id.")

                target_cdir = self._case_path(case_id)
                if target_cdir.exists():
                    raise ValueError(f"Cross-case overwrite violation: case '{case_id}' already exists. Refusing silent overwrite.")

                target_cdir.mkdir(parents=True, exist_ok=True)
                zf.extractall(target_cdir)

            try:
                verification = self.verify_case_audit_chain(case_id)
                if verification.status != AuditVerificationStatus.VALID:
                    shutil.rmtree(target_cdir, ignore_errors=True)
                    raise ValueError(f"Audit chain verification failed for restored case: {verification.details}")
            except Exception as e:
                shutil.rmtree(target_cdir, ignore_errors=True)
                raise ValueError(f"Restoration integrity verification failed: {e}")

            restored = self.get_case(case_id)
            if not restored:
                raise ValueError(f"Failed to load restored case: {case_id}")
            return restored

