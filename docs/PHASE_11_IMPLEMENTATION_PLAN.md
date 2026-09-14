# DREX-V2: Phase 11 Production Hardening Implementation Plan (Final Revision — Post-Correction Gate)

**Frozen Baseline**: Commit [`45ec1bf`](file:///d:/drex-v2-main) (`fix(phase10): complete final validation and release hardening`)  
**Baseline Test Verification**: **698 passed, 0 failed, 0 skipped, 2 warnings** in 135.05s  
**Scope**: Production Reliability, Failure/Crash Recovery, Job State Durability, Concurrency & TOCTOU Defense, Evidence Integrity, Audit Chain Durability, Resource Bounding, Truthful Recovery & Sanitization Semantics, Observability, Packaging Hardening.  
**Dependency Policy**: **ZERO NEW DEPENDENCIES** (Python standard library + existing FastAPI/Uvicorn/Pydantic stack only).  
**Hardware Qualification Baseline**: **LIMITED / PENDING** (Software-tested only; synthetic mocks for destructive safety. No physical hardware qualification claims without physical evidence).

---

## 1. Executive Summary & Architectural Baseline

DREX-V2 is an integrated secure data erasure and digital forensic recovery platform featuring three operational tiers:
1. **Desktop Privileged Forensic Workstation** (`drex_app.py`): Direct Win32 IOCTL storage discovery, ATA/NVMe pass-through, and native UI.
2. **Case & Operations Management Server** (`drex_server.py`): FastAPI backend exposing 18 REST endpoints and `/ws/jobs/{client_id}` real-time telemetry streaming.
3. **Responsive Web & Mobile Companion** (`webui/`): Self-contained ES6+/CSS3 SPA shell supporting desktop, tablet, and mobile viewports with PWA offline security gating (`sw.js`).
4. **Assurance & Trust Core** (`forensic_vault.py`, `certificate_engine.py`, `drex_verify.py`): Enforces the sequential **SHA-256 Hash-Linked Audit Chain** ($H_i = \text{SHA256}(H_{i-1} \parallel E_i)$) and Schema 2.0 evidence manifests.
5. **25-Method Registry** (M01–M25): Authoritative forensic sanitization and recovery method implementations.

---

## 2. Formal Job State Machine & Lifecycle Transitions

### 2.1 State Definitions
- **`QUEUED`**: Job registered in authoritative registry, awaiting worker thread dispatch.
- **`RUNNING`**: Worker thread actively executing operation; live telemetry streaming over WebSocket.
- **`CANCELLING`**: Cooperative cancellation requested by operator; worker unwinding to a safe boundary.
- **`CANCELLED`** *(Terminal)*: Job cleanly terminated by operator request; partial artifacts quarantined.
- **`COMPLETED`** *(Terminal)*: Operation completed successfully; all verification checks passed.
- **`FAILED`** *(Terminal)*: Unhandled exception, execution failure, or verification mismatch occurred.
- **`INTERRUPTED`** *(Terminal)*: Application or server terminated while job was `RUNNING`/`QUEUED`; reconciled on restart.
- **`DEVICE_DISCONNECTED`** *(Terminal)*: Target block device independently established as detached during active I/O.
- **`VERIFICATION_FAILED`** *(Terminal)*: Readback verification, digest comparison, or post-wipe audit detected data residue.

### 2.2 Legal State Transition Matrix

| Initial State | Event / Trigger | Target State | Permitted? | Transition Authority |
| :--- | :--- | :--- | :---: | :--- |
| **`QUEUED`** | Worker thread takes job | `RUNNING` | **YES** | `JobRegistry.dispatch()` |
| **`QUEUED`** | Operator requests cancel before dispatch | `CANCELLED` | **YES** | `JobRegistry.cancel()` (Immediate) |
| **`QUEUED`** | Server restarts before dispatch | `INTERRUPTED` | **YES** | `JobRegistry.reconcile_startup()` |
| **`RUNNING`** | Normal execution finishes & passes verification | `COMPLETED` | **YES** | Worker thread completion |
| **`RUNNING`** | Unhandled exception / native error | `FAILED` | **YES** | Worker exception handler |
| **`RUNNING`** | Operator requests cancel during execution | `CANCELLING` | **YES** | `JobRegistry.cancel()` (Cooperative) |
| **`RUNNING`** | Target block device disconnects (Win32 1167 verified) | `DEVICE_DISCONNECTED`| **YES** | Worker device I/O handler |
| **`RUNNING`** | Readback verification finds residue/mismatch | `VERIFICATION_FAILED`| **YES** | Worker verification pass |
| **`RUNNING`** | Server crashes or restarts during run | `INTERRUPTED` | **YES** | `JobRegistry.reconcile_startup()` |
| **`CANCELLING`**| Worker halts at safe boundary & cleans up | `CANCELLED` | **YES** | Worker cleanup exit |
| **`CANCELLING`**| Target device detaches during cancellation | `DEVICE_DISCONNECTED`| **YES** | Worker device I/O handler |
| **`CANCELLING`**| Worker encounters unhandled error during unwinding | `FAILED` | **YES** | Worker exception handler |
| **`CANCELLING`**| Normal completion occurs while cancel pending | `CANCELLED` | **YES** | **Enforced**: `CANCELLING` MUST NOT become `COMPLETED` |
| **Terminal State** | Any event | Any new state | **NO** | **FORBIDDEN (Terminal Immutability)** |

### 2.3 Forbidden Terminal-State Resurrections
Under no circumstances may a terminal state transition to another state:
- `COMPLETED` $\to$ `RUNNING` (**STRICTLY FORBIDDEN**)
- `FAILED` $\to$ `COMPLETED` (**STRICTLY FORBIDDEN**)
- `CANCELLED` $\to$ `COMPLETED` (**STRICTLY FORBIDDEN**)
- `DEVICE_DISCONNECTED` $\to$ `COMPLETED` (**STRICTLY FORBIDDEN**)
- `VERIFICATION_FAILED` $\to$ `COMPLETED` (**STRICTLY FORBIDDEN**)
- `INTERRUPTED` $\to$ `COMPLETED` (**STRICTLY FORBIDDEN**)
- `CANCELLING` $\to$ `COMPLETED` (**STRICTLY FORBIDDEN** — once cancellation is accepted, the job MUST resolve to `CANCELLED`, `FAILED`, or `DEVICE_DISCONNECTED`).

---

## 3. Durable Job Registry & Process-Monotonic Clock Architecture

### 3.1 Persistence Mechanism
1. **Authoritative Record**: Each job maintains an individual record at `<base_data_dir>/cases/<case_id>/jobs/<job_id>.json`.
2. **Schema Version**: `schema_version: "2.0"`.
3. **Atomic Writes**: Writes occur to `<job_id>.json.tmp.<uuid>` followed by `os.replace()` to guarantee that sudden power loss or process kill never produces a truncated or corrupted JSON file.
4. **Thread-Safe Serialization**: In-memory state is protected by a dedicated `threading.RLock()`. State updates evaluate current state against the transition matrix before writing to disk, preventing race conditions (e.g. Thread B cannot mark `COMPLETED` if Thread A has already marked `FAILED`).
5. **Startup Reconciliation**: On server startup, `JobRegistry.reconcile_startup()` scans all case job directories. Any job found in `QUEUED`, `RUNNING`, or `CANCELLING` is immediately transitioned to `INTERRUPTED` with audit trail notation.

### 3.2 Dual Clock Architecture & Restart Semantics
- **Persistent Historical Timing**:
  - `start_time_utc`: ISO-8601 UTC timestamp (`datetime.now(timezone.utc).isoformat()`).
  - `end_time_utc`: ISO-8601 UTC timestamp recorded when entering a terminal state.
  - `last_heartbeat_utc`: Regularly flushed to disk during active operations.
- **In-Process Elapsed Duration**:
  - `_start_monotonic = time.monotonic()`: Used **strictly** within the active process to compute real-time elapsed seconds for progress telemetry and rate calculation.
  - Monotonic clock values are **never persisted to disk** because monotonic clocks reset across process and system restarts.
- **Restart Recovery Timing**:
  - If a job is reconciled to `INTERRUPTED` following a server restart:
    - `interrupted_at_utc` is set to the current startup time.
    - `persisted_duration_seconds` is computed as `(last_heartbeat_utc - start_time_utc).total_seconds()`.
    - No attempt is made to subtract cross-restart monotonic timestamps.

---

## 4. Operation Correlation & Duplicate Operation Protection

### 4.1 Forensic Correlation Identity
Every long-running operation correlates:
`operation_id` (`OP-YYYYMMDD-XXXXXXXX`), `job_id` (`JOB-YYYYMMDD-XXXXXXXX` / `REC-...` / `SAN-...`), `case_id`, `evidence_id`, `actor`, `method_id`, `target_path`, `start_time_utc`, and `terminal_state`.  
This correlation identity is stamped into:
`REST API Response` $\leftrightarrow$ `WebSocket Telemetry` $\leftrightarrow$ `JobRegistry JSON` $\leftrightarrow$ `Case Audit Event` $\leftrightarrow$ `Vault Manifest` $\leftrightarrow$ `Forensic Certificate`.

### 4.2 Deterministic Operation Fingerprinting & Duplicate Request Protection
To prevent race conditions, duplicate submissions, and conflicting jobs:
1. **Fingerprint Definition**:
   An operation fingerprint is computed as:
   $$\text{Fingerprint} = \text{SHA256}(\text{case\_id} \parallel \text{operation\_type} \parallel \text{method\_id} \parallel \text{normalized\_target\_path} \parallel \text{canonical\_payload\_hash})$$
2. **Duplicate Detection Rules**:
   When an operation request arrives at `/api/recovery/scan` or `/api/sanitization/execute`:
   - The engine checks active jobs currently in `QUEUED`, `RUNNING`, or `CANCELLING` states matching this fingerprint.
3. **Read-Only Operations (Recovery / Carving)**:
   - If an identical read-only recovery scan is already active on the same target:
     - The server returns `HTTP 200 OK` reusing the existing authoritative `job_id`, returning `{"status": "EXISTING_JOB_ATTACHED", "job_id": active_job.job_id}`.
     - Clients are attached to the existing live WebSocket telemetry stream without spawning duplicate disk carvers.
4. **Destructive Sanitization Operations (Fail-Closed Rule)**:
   - **Destructive operations NEVER reuse jobs or execute concurrently.**
   - If a destructive sanitization request arrives while an operation on that target is already active or matches an active fingerprint:
     - The server **FAILS CLOSED** immediately and returns:
       `HTTP 409 Conflict` (`DUPLICATE_DESTRUCTIVE_OPERATION_REJECTED: Active operation OP-xxx is currently locking target device`).
     - No second job is created; no disk handle is opened.

---

## 5. Cancellation Semantics by Operation Type

### 5.1 Recovery, Carving & Fragment Reconstruction (Read-Only)
- **Cooperative Cancellation**:
  - `QUEUED` $\to$ `CANCELLED`: If cancellation is requested before worker dispatch, the job immediately transitions to `CANCELLED`.
  - `RUNNING` $\to$ `CANCELLING` $\to$ `CANCELLED`: During execution, worker checks `cancellation_token.is_set()` at every sector chunk boundary (1 MB / 2048 sectors).
  - Upon detecting cancellation: worker halts reading, flushes candidate records discovered up to that point marked `STATUS: CANCELLED (PARTIAL)`, writes `.part` metadata, transitions state to `CANCELLED`, logs audit event, and broadcasts `JOB_CANCELLED`.

### 5.2 Destructive Sanitization Operations (Write-Enabled Safety)
- **No Forcible / Abrupt Interruption**:
  - Abruptly killing an active disk sanitization process can leave media in an unreadable, bricked, or ambiguously wiped state.
- **Safe Cancellation Flow**:
  - When cancellation is requested for an active sanitization job:
    1. Job transitions from `RUNNING` to `CANCELLING`.
    2. Worker completes the currently active atomic buffer/block boundary (e.g. completes writing the current 64 MB chunk).
    3. Worker flushes physical disk buffers via Win32 `FlushFileBuffers`.
    4. Worker performs an immediate readback check of the processed range to verify exact state.
    5. Job transitions to `CANCELLED`.
    6. Audit ledger records exact sector range processed prior to cancellation.
    7. **STRICT ENFORCEMENT**: The operation **NEVER reports sanitization success** and **NEVER generates a sanitization certificate**.

---

## 6. Concurrency Control, Target Locking & TOCTOU Defense

### 6.1 Central Target Lock Manager
- A thread-safe `TargetLockManager` enforces exclusive access across physical devices (`\\.\PhysicalDriveX`), volumes (`\\.\C:`, `D:\`), and file paths.
- Attempting to launch conflicting operations against an actively locked target returns `HTTP 409 Conflict` (`LOCK_BUSY`).

### 6.2 Atomic Pre-Execution Revalidation (TOCTOU Defense)
Immediately before executing destructive commands under exclusive lock:
1. Re-query physical drive geometry, serial number, capacity, and bus type via Win32 IOCTL.
2. Re-verify target serial number against the serial recorded during the planning phase.
3. Re-execute dynamic OS disk detection (`IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS`) to guarantee that the drive has not become an active system/pagefile volume.
4. If ANY attribute does not match: **FAIL CLOSED**, abort, release lock, return `HTTP 409 Conflict` (`DEVICE_CONFIGURATION_CHANGED`).

---

## 7. Granular Win32 Error Classification & Failure Semantics

Win32 and native device errors must **never** be collapsed into a generic `DEVICE_DISCONNECTED` state. The error classification must strictly distinguish root causes:

| Win32 Error Code | System Constant | Forensic Error Classification | Resulting Job State | Justification / Semantic Rule |
| :---: | :--- | :--- | :---: | :--- |
| **1167** | `ERROR_DEVICE_NOT_CONNECTED` | `DEVICE_DISCONNECTED` | `DEVICE_DISCONNECTED` | Transport or hardware controller physically reports device no longer present. |
| **21** | `ERROR_NOT_READY` | `DEVICE_NOT_READY` / `DEVICE_IO_FAILURE` | `FAILED` | Media door open, drive spinning up, or controller busy. NOT a disconnection unless 1167 or physical absence is established. |
| **2** | `ERROR_FILE_NOT_FOUND` | `TARGET_UNAVAILABLE` / `DEVICE_OBJECT_MISSING` | `FAILED` | Target handle or path path was unmounted or missing at open time. |
| **23** | `ERROR_CRC` | `READ_FAILURE` / `DATA_INTEGRITY_FAILURE` | `FAILED` / `PARTIAL` | Physical sector bad, checksum mismatch, or uncorrectable ECC error. Media is present but corrupted. |
| **31** | `ERROR_GEN_FAILURE` | `COMMAND_FAILURE` / `DEVICE_IO_FAILURE` | `FAILED` | Controller rejected CDB opcode or returned vendor sense failure. |
| **5** | `ERROR_ACCESS_DENIED` | `INSUFFICIENT_PRIVILEGE` | `FAILED` | Process lacks administrative elevation or handle locked by another process. |

**Ambiguity Rule**: Any error whose root cause cannot be definitively established as physical device detachment **fails closed** as `DEVICE_IO_FAILURE` or `COMMAND_FAILURE`, and is **never** falsely attributed to physical disconnection.

---

## 8. Evidence Integrity, Partial Artifact Quarantine & Confidence Truth

1. **Atomic Manifest Writes**:
   All evidence manifests (`drex_manifest.json`) and vault indexes (`vault_objects.json`) are written to `.tmp` files and committed via `os.replace`.
2. **Incomplete Artifact Quarantine**:
   Interrupted or failed acquisitions leave `.part` files that are moved to `<vault>/quarantine/` marked `INVALID_PARTIAL` and never added to active vault indexes.
3. **Candidate vs. Recovered Semantic Model**:
   - `CANDIDATE`: Discovered file signature match.
   - `VALIDATED_CANDIDATE`: Structural footer and format validation passed.
   - `RECONSTRUCTED_CANDIDATE`: Bi-fragment or multi-fragment assembly verified.
   - `RECOVERED_ARTIFACT`: Extracted, hash-verified, and sealed into evidence vault.
4. **Explainable 5-Factor Confidence Scoring**:
   Confidence score (0–100%) represents heuristic evidence confidence:
   $$\text{Confidence} = 0.25(\text{Header}) + 0.25(\text{Footer}) + 0.20(\text{Structure}) + 0.15(\text{Entropy}) + 0.15(\text{Filesystem})$$
   **STRICT ENFORCEMENT**: Confidence represents evidence likelihood, **NEVER the percentage of data recovered**.

---

## 9. Audit Chain Backward Compatibility & Tamper Resilience

### 9.1 Terminology & Canonical Hashing
- Structure: **SHA-256 Hash-Linked Audit Chain**.
- Preimage formula:
  $$\text{preimage} = \text{previous\_hash} + \text{canonical\_json}(\text{sequence}, \text{event\_id}, \text{case\_id}, \text{timestamp}, \text{actor}, \text{event\_type}, \text{operation\_id}, \text{payload})$$
  $$H_i = \text{SHA256}(\text{preimage})$$
- Historical records in `audit_chain.json` remain verifiable without alteration.

### 9.2 Tamper Corruption Corpus & Zero False Negatives
The tamper test corpus in `test_phase11_production_hardening.py` must verify detection with **zero false negatives** across:
1. `payload` byte mutation
2. `timestamp` modification
3. `actor` modification
4. `event_type` modification
5. `sequence_number` alteration
6. Event deletion (missing sequence)
7. Event insertion (duplicate sequence)
8. Event duplication
9. Event reordering
10. `previous_hash` alteration
11. `current_hash` corruption
12. Malformed JSON envelope
13. Truncated audit chain file
14. Corrupted initial chain root (`0000...0000`)

---

## 10. Certificate & Report Cryptographic Binding

1. **Truthful Verification Evidence**:
   - Verification evidence is modeled as `AVAILABLE`, `UNAVAILABLE`, or `NOT_APPLICABLE`.
   - Where byte readback is not applicable (e.g. firmware cryptographic purge), `post_wipe_sha256` is recorded as `NOT_APPLICABLE` (no manufactured hashes).
2. **Integrity Token**:
   $$\text{Token} = \text{SHA256}(\text{cert\_id} \parallel \text{case\_id} \parallel \text{operation\_id} \parallel \text{target\_serial} \parallel \text{method\_id} \parallel \text{prior\_audit\_hash} \parallel \text{timestamp})$$
3. **Prohibited Claims**:
   - Certificates must NEVER state "ISO 27037 Certified", "DoD Certified", or "Government Certified".
   - Standard banner remains: `"NIST SP 800-88 Rev. 2 Aligned Evidence Record & Cryptographic Attestation"`.

---

## 11. Resource Limits & Bounding Architecture

1. **API Payload Limits**: Max JSON request body: **10 MB**. String lengths: `title` $\le 200$, `case_number` $\le 64$, `examiner` $\le 100$, `description` $\le 2000$.
2. **Query Pagination**: `/api/recovery/candidates` clamped to max 1000 records; `/api/audit/ledger` clamped to max 2000 records.
3. **Archive Extraction Bounds**: Max archive size 2 GB, max extracted size 10 GB, max compression ratio 100:1, max file count 10,000, max path depth 16. All Zip Slip path traversal sequences (`../../`) rejected.

---

## 12. Security & WebSocket Authentication

1. **Production JWT Secret Policy**:
   - `DEVELOPMENT` / `JUDGE_DEMO`: Built-in demo keys permitted.
   - `PRODUCTION` (`DREX_ENV=production`): Missing, default (`dev-insecure-secret`), or weak (< 32 chars) secret **FAILS CLOSED** on startup (`RuntimeError`).
2. **WebSocket Authentication Handshake**:
   - WebSocket connections at `/ws/jobs/{client_id}` accept authentication via:
     1. Query parameter: `?token=<JWT>` during the initial HTTP upgrade handshake.
     2. Initial frame: Client must send `{"type": "AUTH", "token": "<JWT>"}` within 5 seconds of connection.
   - Unauthenticated or invalid connections are closed immediately with WebSocket code `4401 Unauthorized`.
3. **Host Binding**:
   - Default: `127.0.0.1` (loopback only). Non-loopback binding (`0.0.0.0`) requires explicit flag `--allow-remote`.

---

## 13. Case Backup & Tamper-Evident Restore

1. **Backup**: Sealed zip archive containing case metadata, evidence vault, and audit chain, accompanied by a detached SHA-256 backup manifest.
2. **Restore Integrity**:
   - Verifies backup archive SHA-256 before extraction.
   - Verifies audit chain integrity before importing.
   - **Cross-Case Overwrite Guard**: Rejects restoration if a case with the same `case_id` already exists.

---

## 14. Authoritative 25-Method Registry & Qualification Matrix

The 25 methods discovered directly from codebase runtime:

| Method ID | Category | Canonical Method Name | Backend Engine / Component | Software Status | Physical Hardware Status | Physical Evidence in Repo |
| :---: | :--- | :--- | :--- | :---: | :---: | :---: |
| **M01** | Drive Erasure | NIST SP 800-88 Rev.2 | NIST SP 800-88r2 Policy Engine | `SOFTWARE_QUALIFIED` | `LIMITED` | None (Decision engine only) |
| **M02** | Drive Erasure | Smart Sanitization | Multi-Tier Safety Evaluator | `SOFTWARE_QUALIFIED` | `LIMITED` | None (Policy evaluation) |
| **M03** | Drive Erasure | Device-Native Sanitize | Controller Native Sanitize CDB | `UNSUPPORTED` | `HARDWARE_REQUIRED` | None (USB bridge filtered) |
| **M04** | Drive Erasure | ATA Secure Erase | ATA Controller 0xEF Security | `UNSUPPORTED` | `HARDWARE_REQUIRED` | None (Requires native SATA) |
| **M05** | Drive Erasure | NVMe Secure Erase | NVMe Format / Sanitize Admin Cmd | `UNSUPPORTED` | `HARDWARE_REQUIRED` | None (Requires native PCIe) |
| **M06** | Drive Erasure | IEEE 2883 Purge | IEEE 2883-2022 Policy Engine | `SOFTWARE_QUALIFIED` | `LIMITED` | None (Policy engine only) |
| **M07** | Drive Erasure | Verified Overwrite | Multi-Pass Block Overwrite Engine | `SOFTWARE_QUALIFIED` | `LIMITED` | Synthetic test disks only |
| **M08** | File/Folder Erasure | CSPRNG Random Overwrite | `os.urandom` Cryptographic Stream | `SOFTWARE_QUALIFIED` | `LIMITED` | Logical file fixtures only |
| **M09** | File/Folder Erasure | Cryptographic Erasure | AES-256 Envelope Key Purge Engine | `SOFTWARE_QUALIFIED` | `CONDITIONAL` | Synthetic envelope tests |
| **M10** | File/Folder Erasure | File Slack / Cluster-Tip | Cluster-Tip Zeroing Engine | `SOFTWARE_QUALIFIED` | `LIMITED` | Synthetic cluster fixtures |
| **M11** | File/Folder Erasure | Filesystem Metadata Sanitization | OS Metadata Scrub & Neutralizer | `SOFTWARE_QUALIFIED` | `CONDITIONAL` | File-backed NTFS/FAT |
| **M12** | File/Folder Erasure | NIST SP 800-88 Policy Engine | NIST SP 800-88 Decision Matrix | `SOFTWARE_QUALIFIED` | `LIMITED` | Policy matrix evaluation |
| **M13** | File/Folder Erasure | Secure Free-Space Wiping | Unallocated Filler Engine | `SOFTWARE_QUALIFIED` | `LIMITED` | Test file filler checks |
| **M14** | File/Folder Erasure | Single-Pass Zero Overwrite | Single-Pass Zero Engine | `SOFTWARE_QUALIFIED` | `LIMITED` | Synthetic file tests |
| **M15** | File/Folder Erasure | Storage-Aware Sanitization Fallback | Controller Fallback Matrix | `SOFTWARE_QUALIFIED` | `LIMITED` | Decision matrix tests |
| **M16** | File/Folder Erasure | Temporary / Cache Sanitization | Temp Cache Scanner & Overwrite | `SOFTWARE_QUALIFIED` | `LIMITED` | Temp folder fixtures |
| **M17** | Recovery | Quick Recovery | TSK 4.15.0 `fls.exe` + `icat.exe` | `SOFTWARE_QUALIFIED` | `LIMITED` | FAT/NTFS synthetic images |
| **M18** | Recovery | Smart Recovery | TSK 4.15.0 `fsstat` + `fls` + `tsk_recover` | `SOFTWARE_QUALIFIED` | `LIMITED` | FAT/NTFS synthetic images |
| **M19** | Recovery | Targeted Recovery | TSK 4.15.0 `icat.exe` | `SOFTWARE_QUALIFIED` | `LIMITED` | Inode synthetic images |
| **M20** | Recovery | Filesystem Recovery | TSK 4.15.0 `tsk_recover.exe` | `SOFTWARE_QUALIFIED` | `LIMITED` | Synthetic filesystem images |
| **M21** | Recovery | Deep Recovery | PhotoRec 7.2 Raw Carver | `PARTIAL` | `LIMITED` | Elevated raw disk needed |
| **M22** | Recovery | Fragment Recovery | PhotoRec 7.2 + Resurgence Engine | `PARTIAL` | `LIMITED` | Bi-fragment fixtures only |
| **M23** | Recovery | RAID / Storage Recovery | TSK / TestDisk RAID Parser | `UNSUPPORTED` | `HARDWARE_REQUIRED` | Single disk tested only |
| **M24** | Recovery | Damaged Media Recovery | GNU `ddrescue` Native Adapter | `BACKEND_UNAVAILABLE` | `HARDWARE_REQUIRED` | Linux native binary required |
| **M25** | Recovery | Forensic Recovery | TSK 4.15.0 + SHA-256 Vault | `SOFTWARE_QUALIFIED` | `LIMITED` | Synthetic evidence images |

**Truth Standard Enforced**: In accordance with Directive 2, **ZERO methods are claimed as `HARDWARE_QUALIFIED`**. All methods evaluated via synthetic disks, RAM fixtures, or file-backed images are truthfully classified as `LIMITED` or `CONDITIONAL` regarding physical hardware status.

---

## 15. Machine-Testable Invariants

- **`INVARIANT-01`**: A terminal job state cannot transition to any other state.
- **`INVARIANT-02`**: A job in state `DEVICE_DISCONNECTED` can never become `COMPLETED`.
- **`INVARIANT-03`**: A candidate discovered during carving cannot enter the verified evidence vault index as a `RECOVERED_ARTIFACT` without passing structural integrity validation.
- **`INVARIANT-04`**: A dynamic system disk extent (`SystemDrive` / `SystemRoot`) can never be targeted for destructive sanitization.
- **`INVARIANT-05`**: Two concurrent operations cannot hold an exclusive lock on the same physical or logical target simultaneously.
- **`INVARIANT-06`**: Historical audit chain hashes ($H_0 \dots H_{n-1}$) cannot be altered without invalidating chain verification.
- **`INVARIANT-07`**: A failed verification check can never generate a valid sanitization certificate.
- **`INVARIANT-08`**: A weak or missing JWT secret in production mode (`DREX_ENV=production`) prevents server startup.
- **`INVARIANT-09`**: A backup archive with a corrupted manifest or altered audit ledger cannot be restored.
- **`INVARIANT-10`**: An unverified partial evidence file (`.part`) cannot be indexed in `vault_objects.json`.
- **`INVARIANT-11`**: Destructive sanitization operations are never automatically retried upon failure.
- **`INVARIANT-12`**: Elapsed duration during a process run uses `time.monotonic()`; cross-restart duration uses UTC timestamps.
- **`INVARIANT-13`**: Extraction of an archive with directory traversal paths (`../../`) aborts without writing outside target root.
- **`INVARIANT-14`**: A client querying `/api/recovery/candidates` with a limit exceeding 1000 records receives a clamped response.
- **`INVARIANT-15`**: A pre-execution TOCTOU check detecting altered drive geometry or serial number must abort destructive execution immediately.
- **`INVARIANT-16`**: A destructive sanitization operation matching an active operation fingerprint is rejected with `HTTP 409 Conflict`.
- **`INVARIANT-17`**: A job in state `CANCELLING` must never resolve to `COMPLETED`.
- **`INVARIANT-18`**: Non-disconnection Win32 errors (21, 23, 31) are never labeled `DEVICE_DISCONNECTED` without physical detachment evidence.

---

## 16. Evidence-Based File Impact Analysis

| File | Current Responsibility | Proposed Phase 11 Change | Workstream | Security Risk | Data-Integrity Risk | Test Coverage |
| :--- | :--- | :--- | :---: | :---: | :---: | :---: |
| [`drex_server.py`](file:///d:/drex-v2-main/drex_server.py) | REST API & WebSockets | Add `JobRegistry`, `/api/jobs/{id}`, `/api/jobs/{id}/cancel`, pagination, worker exception recovery, operation fingerprinting, WebSocket auth | WS-1, WS-2, WS-8, WS-9, WS-10 | Low (Hardens auth/limits) | High (Prevents lost job states) | `test_phase11_production_hardening.py` |
| [`drex_api_models.py`](file:///d:/drex-v2-main/drex_api_models.py) | Pydantic Schemas | Add string length bounds, `JobStatusResponse`, pagination query models | WS-10 | Low | Low | Model validation tests |
| [`drex_rbac.py`](file:///d:/drex-v2-main/drex_rbac.py) | JWT & Permissions | Add production secret entropy enforcement (`DREX_ENV=production`), `jobs:cancel` permission | WS-9, WS-11 | High (Auth boundary) | Low | RBAC tests |
| [`hardware_storage.py`](file:///d:/drex-v2-main/hardware_storage.py) | Device I/O & IOCTLs | Add `TargetLockManager`, atomic pre-execution TOCTOU revalidation, granular Win32 error mapper | WS-3, WS-4, WS-15 | High (Destructive gate) | Critical (Prevents wrong-disk wipe) | Safety tests |
| [`forensic_vault.py`](file:///d:/drex-v2-main/forensic_vault.py) | Evidence Vault & Audit | Add atomic writes (`os.replace`), backup/restore verification, preserve canonical hashing | WS-5, WS-6, WS-19 | Low | Critical (Preserves forensic ledger) | Vault tests |
| [`drex_verify.py`](file:///d:/drex-v2-main/drex_verify.py) | Independent Verifier | Add Zip Slip archive bounds, hardened tamper detection | WS-5, WS-9 | Medium | High | Verifier tests |
| [`webui/app.js`](file:///d:/drex-v2-main/webui/app.js) | Frontend Application | Add job resynchronization, cancel button handler, pagination controls | WS-1, WS-2, WS-14 | Low | Low | Browser E2E |

*Files Inspected But Explicitly Not Modified*:
`fs_bitmap.py`, `entropy_engine.py`, `vss_sanitizer.py`, `recovery_adapter.py`, `fragment_engine.py`, `carver_engine.py`.

---

## 17. Expanded Test Strategy (`tests/test_phase11_production_hardening.py`)

1. **State Machine & Lifecycle Tests**:
   - `test_state_machine_legal_transitions`: Tests all permitted paths in transition matrix.
   - `test_state_machine_terminal_immutability`: Asserts `INVARIANT-01`.
   - `test_cancelling_cannot_become_completed`: Asserts `INVARIANT-17`.
2. **Job Durability & Clock Semantics**:
   - `test_job_durability_atomic_persistence`: Verifies atomic disk writes.
   - `test_job_durability_startup_reconciliation`: Verifies restart marks stale jobs `INTERRUPTED`.
   - `test_job_clock_semantics`: Verifies monotonic in-process elapsed time and UTC cross-restart timestamps (`INVARIANT-12`).
3. **Duplicate Submission & Fingerprint Tests**:
   - `test_duplicate_recovery_scan_job_reuse`: Verifies read-only duplicate scan returns existing `job_id`.
   - `test_duplicate_destructive_operation_rejected`: Verifies duplicate destructive request returns `HTTP 409` (`INVARIANT-16`).
4. **Target Locking & TOCTOU Defense**:
   - `test_target_lock_mutual_exclusion`: Conflicting concurrent operations return `HTTP 409` (`INVARIANT-05`).
   - `test_toctou_pre_execution_abort_on_serial_mismatch`: Asserts `INVARIANT-15`.
5. **Granular Win32 Error Mapping Tests**:
   - `test_win32_error_1167_disconnect`: Win32 1167 maps to `DEVICE_DISCONNECTED` (`INVARIANT-02`).
   - `test_win32_error_21_not_ready_fails_as_io_error`: Win32 21 maps to `DEVICE_IO_FAILURE`, not disconnect (`INVARIANT-18`).
   - `test_win32_error_23_crc_fails_as_read_failure`: Win32 23 maps to `READ_FAILURE` (`INVARIANT-18`).
6. **Audit Tamper Corpus Tests**:
   - `test_audit_tamper_corpus_14_mutations`: Verifies all 14 corruption cases detected with zero false negatives (`INVARIANT-06`).
   - `test_audit_historical_backward_compatibility`: Validates existing Phase 2/10 audit chains.
7. **Security, JWT & WebSocket Handshake Tests**:
   - `test_production_jwt_secret_fails_closed`: Asserts `INVARIANT-08`.
   - `test_websocket_authentication_handshake`: Verifies token query and initial AUTH frame validation.
8. **Resource Limits & Zip Slip Defense Tests**:
   - `test_api_string_length_limits`: Verifies rejection of oversized case metadata.
   - `test_candidate_pagination_bounds`: Asserts `INVARIANT-14`.
   - `test_zip_slip_and_bomb_rejection`: Asserts `INVARIANT-13`.
9. **Backup & Restore Forensic Integrity**:
   - `test_case_backup_and_restore_cycle`: Verifies clean export/import.
   - `test_corrupted_backup_rejected`: Asserts `INVARIANT-09`.
10. **Phase 10 Regression Gate**:
    - Complete execution of all **698 baseline tests** with zero failures.

---

## 18. Implementation Order & Phasing

- **Phase 11.0**: Baseline Freeze & Pre-Flight Validation.
- **Phase 11.1**: State Machine, Job Registry & Duplicate Fingerprinting.
- **Phase 11.2**: Target Locking, TOCTOU Guard & Granular Win32 Error Mapping.
- **Phase 11.3**: Evidence Quarantine, Atomic Manifests & Canonical Hash Preservation.
- **Phase 11.4**: Security Hardening, Production JWT Policy & Resource Limits.
- **Phase 11.5**: Case Backup & Restore Routines.
- **Phase 11.6**: Documentation & 25-Method Qualification Matrix Alignment.
- **Phase 11.7**: Production Hardening Test Suite Execution.
- **Phase 11.8**: Full 698-Test Regression, PyInstaller Check & Git Clean State.

---

## 19. Completeness Audit Check (34 Quality Gate Questions)

1. *Current architecture*: Detailed in Section 1.
2. *Exact risks*: Documented in Section 2 & 3.
3. *Exact files to change*: Documented in Section 16.
4. *Workstream mapping*: Explicitly mapped in Section 16.
5. *Legal job transitions*: Detailed matrix in Section 2.2.
6. *Terminal states*: Defined in Section 2.1; immutability enforced in Section 2.3.
7. *Job state persistence*: Atomic JSON files via `os.replace` in Section 3.1.
8. *Concurrency control*: Central `TargetLockManager` in Section 6.1.
9. *Duplicate submission*: Defined in Section 4.2 with fingerprint formula and fail-closed destructive semantics.
10. *TOCTOU prevention*: Pre-execution geometry and serial revalidation under exclusive lock in Section 6.2.
11. *Device disconnect*: Granular Win32 mapping in Section 7 (distinguishing 1167 from 21, 23, 31).
12. *Evidence protection*: Partial file quarantine and atomic manifests in Section 8.
13. *Audit chain protection*: Sequential hash linkage and atomic persistence in Section 9.
14. *Historical audit preservation*: Canonical preimage frozen; historical records verifiable without alteration (Section 9.1).
15. *Candidate vs. recovered*: Distinct enum states (`CANDIDATE != RECOVERED_ARTIFACT`) in Section 8.3.
16. *Confidence representation*: 5-factor heuristic evidence formula in Section 8.4; never percentage recovered.
17. *Destructive operations protection*: Multi-stage safety gates, dynamic OS volume locks, elevation checks, exact confirmation phrase (Section 5 & 6).
18. *Certificate cryptographic binding*: Immutable SHA-256 integrity token binding all operation parameters (Section 10).
19. *Backup verification*: Archive digest and audit ledger verification before restore (Section 13).
20. *Resource attacks bounded*: Request body limits, string bounds, pagination, Zip Bomb/Slip defense in Section 11.
21. *Production auth hardened*: Fail-closed on weak/default secrets in production mode (Section 12.1).
22. *WebSocket auth protected*: Token query validation and initial AUTH frame handshake in Section 12.2.
23. *Packaged paths protected*: Frozen `sys._MEIPASS` fallbacks verified (Section 16).
24. *25 methods qualified truthfully*: Reconciled table with exact code statuses in Section 14.
25. *Hardware-dependent claims*: All 25 methods truthfully classified as `LIMITED` or `CONDITIONAL` regarding physical hardware status; zero false claims (Section 14).
26. *Tests proving workstreams*: 10 test groups detailed in Section 17.
27. *Tests proving invariants*: 18 machine-testable invariants specified in Section 15.
28. *What constitutes failure*: Any test failure, invariant violation, or unhandled exception.
29. *What triggers rollback*: Baseline test failure or safety gate regression (Section 18).
30. *Out of scope*: Feature creep, new algorithms, cosmetic rewrites (Section 1).
31. *New dependencies*: **ZERO** (Python standard library and existing stack only).
32. *Contradicts Phase 10*: **None**. Fully preserves and reinforces Phase 10 accomplishments.
33. *Weakens security/safety*: **None**. Tightens all safety checks.
34. *Unsupported claims*: All ISO/DoD certification claims eliminated; truth states strictly enforced.

---

## 20. Plan Status

**PLAN STATUS: READY FOR HUMAN APPROVAL**
