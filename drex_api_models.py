"""
DREX-V2 API Request & Response Schemas
======================================
Strict, typed Pydantic models for the DREX REST & WebSocket API surfaces.
Provides full fidelity for cases, evidence, recovery scans, candidates,
sanitization plans, device intelligence, audit records, and certificates.

License: Apache 2.0.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, Field


# ─── Enumerations ─────────────────────────────────────────────────────────────

class UserRole(str, Enum):
    ADMIN = "ADMIN"
    FORENSIC_ANALYST = "FORENSIC_ANALYST"
    INVESTIGATOR = "INVESTIGATOR"
    OPERATOR = "OPERATOR"
    AUDITOR = "AUDITOR"
    JUDGE_DEMO = "JUDGE_DEMO"


class ExecutionTruthState(str, Enum):
    LIVE = "LIVE"
    PASS_REAL = "PASS — REAL EXECUTION VERIFIED"
    PASS_DECISION = "PASS — DECISION ENGINE VERIFIED"
    PASS_SYNTHETIC = "PASS — SYNTHETIC BACKEND VERIFIED"
    PARTIAL = "PARTIAL"
    UNSUPPORTED = "UNSUPPORTED"
    BACKEND_UNAVAILABLE = "BACKEND UNAVAILABLE"
    USB_BRIDGE_LIMITED = "USB_BRIDGE_LIMITED"
    FAILED = "FAILED"


class JobLifecycleState(str, Enum):
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    CANCELLING = "CANCELLING"
    CANCELLED = "CANCELLED"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    INTERRUPTED = "INTERRUPTED"
    DEVICE_DISCONNECTED = "DEVICE_DISCONNECTED"
    VERIFICATION_FAILED = "VERIFICATION_FAILED"


# ─── Authentication Models ───────────────────────────────────────────────────

class LoginRequest(BaseModel):
    username: str = Field(..., max_length=100)
    password: str = Field(..., max_length=200)


class AuthTokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: UserRole
    username: str
    display_name: str
    permissions: List[str]


class DemoPersonaSwitchRequest(BaseModel):
    target_role: UserRole


# ─── Case & Evidence Models ───────────────────────────────────────────────────

class ForensicCaseCreate(BaseModel):
    case_number: str = Field(..., min_length=1, max_length=64)
    title: str = Field(..., min_length=1, max_length=200)
    examiner: str = Field(..., min_length=1, max_length=100)
    organization: Optional[str] = Field("Forensic Assurance Lab", max_length=200)
    notes: Optional[str] = Field("", max_length=2000)


class ForensicCaseRecord(BaseModel):
    case_id: str
    case_number: str
    title: str
    examiner: str
    organization: str
    status: str
    created_utc: str
    updated_utc: str
    evidence_count: int = 0
    notes: str = ""


class EvidenceItemRecord(BaseModel):
    evidence_id: str
    case_id: str
    name: str
    source_type: str
    source_path: str
    size_bytes: int
    sha256_hash: str
    custodian: str
    created_utc: str
    is_sealed: bool = False


class TimelineEventRecord(BaseModel):
    event_id: str
    case_id: str
    timestamp_utc: str
    event_type: str
    summary: str
    actor: str
    details: Dict[str, Any] = Field(default_factory=dict)
    event_hash: str = ""


# ─── Device Intelligence Models ───────────────────────────────────────────────

class DeviceDescriptor(BaseModel):
    device_id: str
    device_path: str
    model: str
    serial_number: str
    bus_type: str
    media_type: str
    capacity_bytes: int
    capacity_human: str
    sector_size: int
    is_system_disk: bool
    is_boot_disk: bool
    is_removable: bool
    is_write_protected: bool
    mount_points: List[str] = Field(default_factory=list)
    hardware_qualification_status: str
    safety_block_reason: Optional[str] = None


class MethodQualificationItem(BaseModel):
    method_id: int
    method_name: str
    category: str
    status: str
    explanation: str


# ─── Recovery Models ──────────────────────────────────────────────────────────

class RecoveryScanRequest(BaseModel):
    source_path: str
    destination_dir: str
    case_id: Optional[str] = None
    engine: str = "TSK"  # "TSK", "CARVER", "SMART"
    max_candidates: int = 500


class RecoveryCandidateRecord(BaseModel):
    candidate_id: str
    filename: str
    file_type: str
    size_bytes: int
    confidence_score: float
    confidence_tier: str  # "HIGH", "MEDIUM", "LOW"
    confidence_factors: Dict[str, float]
    provenance: str
    sha256: str = ""
    offset: int = 0
    is_recovered: bool = False
    validation_verdict: str = "VALIDATED"


# ─── Sanitization Models ──────────────────────────────────────────────────────

class SanitizationPlanRequest(BaseModel):
    target_path: str
    target_type: str  # "DRIVE", "FILE", "FOLDER", "FREE_SPACE"
    standard_profile: str = "NIST_800_88_REV2"
    pass_count: int = 1


class SanitizationPlanResponse(BaseModel):
    plan_id: str
    target_path: str
    qualified_method_id: int
    qualified_method_name: str
    safety_clearance: bool
    system_disk_blocked: bool
    requires_safety_phrase: bool
    safety_phrase: str
    verification_technique: str
    expected_duration_seconds: int


class SanitizationExecuteRequest(BaseModel):
    target_path: str
    method_id: int
    safety_phrase_entered: str
    case_id: Optional[str] = None
    simulate_only: bool = False


# ─── Verification & Audit Models ──────────────────────────────────────────────

class AuditEventRecord(BaseModel):
    sequence: int
    event_id: str
    timestamp_utc: str
    actor: str
    operation: str
    event_type: str
    payload_summary: str
    previous_hash: str
    current_hash: str
    verification_status: str = "VERIFIED"


class IndependentVerifyResult(BaseModel):
    verdict: str  # "PASS", "TAMPERED", "INCOMPLETE", "INVALID", "INDETERMINATE"
    exit_code: int
    package_name: str
    schema_version: str
    details: List[str]
    manifest_hash_match: bool


class SectorBlockState(BaseModel):
    block_index: int
    state: str  # "ZEROED", "CSPRNG", "SLACK_WIPED", "UNALLOCATED", "DAMAGED"
    entropy: float


# ─── Real-Time Job Models ────────────────────────────────────────────────────

class JobProgressUpdate(BaseModel):
    job_id: str
    operation_type: str
    status: str  # "RUNNING", "COMPLETED", "FAILED", "CANCELLED"
    percent_complete: float
    throughput_mb_s: float
    elapsed_seconds: float
    estimated_remaining_seconds: float
    current_stage: str
    items_processed: int
    total_items: int
    log_line: Optional[str] = None


class JobStatusRecord(BaseModel):
    operation_id: str
    job_id: str
    case_id: str
    evidence_id: Optional[str] = None
    actor: str
    method_id: Optional[int] = None
    target_path: str
    operation_type: str
    status: JobLifecycleState
    percent_complete: float = 0.0
    start_time_utc: str
    end_time_utc: Optional[str] = None
    elapsed_seconds: float = 0.0
    details: Dict[str, Any] = Field(default_factory=dict)
    error_code: Optional[str] = None
    error_message: Optional[str] = None


class PaginationQuery(BaseModel):
    limit: int = Field(100, ge=1, le=1000)
    offset: int = Field(0, ge=0)


class DuplicateOperationResponse(BaseModel):
    status: str = "EXISTING_JOB_ATTACHED"
    job_id: str
    operation_id: str
    message: str


class CaseRestoreRequest(BaseModel):
    backup_zip_path: str
    target_cases_dir: Optional[str] = None


class CaseBackupResponse(BaseModel):
    case_id: str
    backup_path: str
    manifest_path: str
    archive_sha256: str
    status: str = "BACKUP_COMPLETED"


class CaseRestoreResponse(BaseModel):
    case_id: str
    restored_path: str
    audit_chain_valid: bool
    status: str = "RESTORE_COMPLETED"


