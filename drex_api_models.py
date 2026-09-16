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
    workflow_id: Optional[str] = None
    target_id: Optional[str] = None
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
    validation_state: str = "CANDIDATE"  # "CANDIDATE", "VALIDATED_CANDIDATE", "RECONSTRUCTED_CANDIDATE", "RECOVERED_ARTIFACT"
    limitations: List[str] = Field(default_factory=list)


class FragmentChunkModel(BaseModel):
    chunk_id: int
    offset: int
    data_hex: Optional[str] = None
    size_bytes: int = 0
    entropy: Optional[float] = None
    is_header: bool = False
    is_footer: bool = False


class RecoveryReconstructRequest(BaseModel):
    case_id: str = Field(..., max_length=64)
    file_type: str = Field(..., max_length=32)
    filename: Optional[str] = Field(None, max_length=255)
    fragments: List[FragmentChunkModel]
    source_target: Optional[str] = None
    strict_structure_validation: bool = True


class RecoveryReconstructResponse(BaseModel):
    reconstruction_id: str
    case_id: str
    file_type: str
    filename: str
    total_size_bytes: int
    is_valid_structure: bool
    validation_verdict: str
    reconstruction_confidence: float
    seam_scores: List[float] = Field(default_factory=list)
    sha256: str
    candidate_id: str
    state: str
    limitations: List[str] = Field(default_factory=list)


class RecoveryExtractRequest(BaseModel):
    case_id: str = Field(..., max_length=64)
    candidate_id: str = Field(..., max_length=64)
    destination_subfolder: Optional[str] = Field("recovered_evidence", max_length=64)
    notes: Optional[str] = Field(None, max_length=1000)


class RecoveryExtractResponse(BaseModel):
    extract_id: str
    case_id: str
    candidate_id: str
    vault_object_id: str
    vault_path: str
    filename: str
    file_type: str
    size_bytes: int
    sha256: str
    is_recovered: bool
    audit_event_id: str
    message: str


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
    workflow_id: Optional[str] = None
    target_id: Optional[str] = None
    simulate_only: bool = False
    preflight_identity: Optional[str] = None


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

class OperationContext(BaseModel):
    case_id: str
    workflow_id: str
    job_id: Optional[str] = None
    method_id: Optional[Union[int, str]] = None
    target_id: Optional[str] = None


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
    case_id: Optional[str] = None
    workflow_id: Optional[str] = None
    method_id: Optional[Union[int, str]] = None
    target_id: Optional[str] = None


class JobStatusRecord(BaseModel):
    operation_id: str
    job_id: str
    case_id: str
    workflow_id: Optional[str] = None
    evidence_id: Optional[str] = None
    actor: str
    method_id: Optional[Union[int, str]] = None
    target_id: Optional[str] = None
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


# ─── Certificate & Attestation Models ─────────────────────────────────────────

class CertificateGenerateRequest(BaseModel):
    case_id: str
    operation_id: Optional[str] = None
    job_id: Optional[str] = None
    target_identifier: Optional[str] = None
    method_id: Optional[int] = None
    examiner_name: Optional[str] = None
    notes: Optional[str] = None


class CertificateRecordModel(BaseModel):
    certificate_id: str
    certificate_version: str = "2.0"
    case_id: str
    case_name: str
    examiner_name: str
    organization: str
    timestamp_utc: str
    target_name: str
    target_type: str
    device_model: str = "GENERIC_STORAGE"
    serial_number: str = "UNKNOWN_SERIAL"
    capacity_bytes: int = 0
    method_id: int
    method_name: str
    standard_reference: str
    pass_count: int = 1
    execution_state: str = "REAL"
    verification_state: str = "EXACT_READBACK"
    physical_execution: str = "NOT_EXECUTED"
    prior_audit_hash: str
    audit_chain_event_hash: str
    tamper_evident_signature: str
    pdf_sha256: Optional[str] = None
    pdf_download_url: Optional[str] = None
    forensic_limitations: List[str] = Field(default_factory=list)


class CertificateVerifyRequest(BaseModel):
    certificate_id: str
    case_id: str


class CertificateVerifyResponse(BaseModel):
    certificate_id: str
    case_id: str
    valid: bool
    certificate_hash_valid: bool
    pdf_hash_valid: bool
    audit_chain_valid: bool
    case_binding_valid: bool
    operation_binding_valid: bool
    verdict: str
    details: List[str] = Field(default_factory=list)


# ─── Validation & Performance Lab Models ──────────────────────────────────────

class ValidationRunRequest(BaseModel):
    case_id: str
    suites: Optional[List[str]] = None
    examiner: Optional[str] = None


class MethodKatStatusItem(BaseModel):
    method_id: int
    method_name: str
    category: str
    truth_status: str = "KAT_VERIFIED"
    software_status: str = "KAT_VERIFIED"
    hardware_status: str = "SOFTWARE_QUALIFIED"
    physical_execution: str = "NOT_EXECUTED"
    kat_status: Optional[str] = None
    algorithm_valid: Optional[bool] = None
    physical_hardware_tested: bool = False
    details: Optional[str] = None
    notes: Optional[str] = None


class ValidationSuiteResultModel(BaseModel):
    suite_id: str
    suite_name: str
    total_tests: int
    passed_tests: int
    failed_tests: int
    skipped_tests: int = 0
    hardware_limited_tests: int = 0
    duration_seconds: float
    status: str  # "PASS", "PARTIAL", "FAIL", "HARDWARE_LIMITED"
    diagnostics: List[str] = Field(default_factory=list)


class ValidationLabReportModel(BaseModel):
    report_id: str
    case_id: str
    timestamp_utc: str
    overall_verdict: str  # "ALL_REQUIRED_PASS", "PARTIAL", "FAILED", "HARDWARE_LIMITED", "ERROR"
    total_suites: int
    total_tests: int
    total_passed: int
    total_failed: int
    total_skipped: int = 0
    duration_seconds: float
    report_hash: Optional[str] = None
    audit_chain_event_hash: Optional[str] = None
    audit_chain_prior_hash: Optional[str] = None
    suite_summaries: List[ValidationSuiteResultModel] = Field(default_factory=list)
    method_matrix: List[MethodKatStatusItem] = Field(default_factory=list)
    benchmarks: List[Dict[str, Any]] = Field(default_factory=list)
    environment: Dict[str, Any] = Field(default_factory=dict)
    disclaimer: str = "Observed under benchmark and synthetic fixture conditions. Physical hardware execution: NOT_EXECUTED."
    vault_object_id: Optional[str] = None
    audit_event_id: Optional[str] = None
    report_sha256: Optional[str] = None


class ValidationReportVerifyRequest(BaseModel):
    case_id: str
    report_id: str


class ValidationReportVerifyResponse(BaseModel):
    report_id: str
    case_id: str
    valid: bool
    report_hash_valid: bool
    audit_chain_valid: bool
    case_binding_valid: bool
    verdict: str
    details: List[str] = Field(default_factory=list)


class PerformanceRunRequest(BaseModel):
    case_id: str
    benchmark_type: str = "STREAMING_SHA256"
    dataset_size_bytes: int = Field(5242880, ge=1024, le=52428800)  # Max 50 MB
    chunk_size_bytes: int = Field(65536, ge=4096, le=1048576)      # 4 KB to 1 MB
    iterations: int = Field(1, ge=1, le=10)                         # Max 10 iterations


class PerformanceResultModel(BaseModel):
    benchmark_id: str
    case_id: str
    operation_name: str
    dataset_size_bytes: int
    chunk_size_bytes: int = 65536
    iterations: int = 1
    duration_seconds: float
    throughput_mb_per_sec: float
    tracemalloc_current_bytes: int = 0
    tracemalloc_peak_bytes: int = 0
    process_rss_bytes: int = 0
    process_vms_bytes: int = 0
    bounded_streaming_verified: bool = True
    benchmark_hash: Optional[str] = None
    audit_chain_event_hash: Optional[str] = None
    audit_chain_prior_hash: Optional[str] = None
    environment_info: Dict[str, Any] = Field(default_factory=dict)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    timestamp_utc: str
    vault_object_id: Optional[str] = None
    audit_event_id: Optional[str] = None
    disclaimer: str = "Observed under benchmark conditions."


class PerformanceTelemetryModel(BaseModel):
    process_rss_bytes: int
    process_vms_bytes: int
    tracemalloc_current_bytes: int
    tracemalloc_peak_bytes: int
    timestamp_utc: str
    python_version: Optional[str] = None
    os_name: Optional[str] = None
    git_commit: Optional[str] = None
    environment_notes: Optional[str] = None


# ─── Phase 21 Native Desktop Dialog & System Version Models ──────────────────

class DialogPickRequest(BaseModel):
    title: Optional[str] = "Select Target"
    initial_dir: Optional[str] = None
    file_types: Optional[List[List[str]]] = None
    path_override: Optional[str] = None  # Automated test / headless bypass


class TargetInspectRequest(BaseModel):
    target_path: str


class TargetMetadataModel(BaseModel):
    path: str
    type: str  # "FILE", "FOLDER", "DEVICE", "UNKNOWN"
    exists: bool
    file_count: int
    total_size: int
    readable: bool
    protected: bool
    filesystem: str
    volume: str
    mtime: Optional[str] = None
    preflight_hash: Optional[str] = None
    status: str = "OK"  # "OK", "CANCELLED", "TARGET_NOT_FOUND", "PROTECTED_BLOCKED"
    message: Optional[str] = None


class SystemVersionModel(BaseModel):
    build_id: str
    commit: str
    asset_version: str
    version: str
    server_timestamp: str
    environment: str


class TestItemModel(BaseModel):
    node_id: str
    module: str
    class_name: Optional[str] = None
    name: str
    category: str
    status: str
    duration_seconds: float = 0.0
    docstring: str = ""
    markers: List[str] = Field(default_factory=list)
    last_run_utc: str = ""
    commit: str = ""
    traceback: Optional[str] = None


class TestCategorySummaryModel(BaseModel):
    total: int
    passed: int
    failed: int
    errors: int
    warnings: int
    desc: str


class TestResultsResponseModel(BaseModel):
    commit: str
    run_timestamp: str
    pytest_version: str
    python_version: str
    environment: str
    collected: int
    passed: int
    failed: int
    errors: int
    skipped: int
    xfailed: int
    xpassed: int
    warnings: int
    duration_seconds: float
    categories: Dict[str, TestCategorySummaryModel]
    tests: List[TestItemModel]





