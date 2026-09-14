# DREX-V2: Repository of Errors, Discrepancies, and Contradictions Audit

This document serves as an exhaustive forensic repository of all errors, runtime exceptions, architectural contradictions, false assumptions, and schema discrepancies identified and remediated across DREX-V2 during Phase 10 validation and release testing.

---

## Index of Categories

1. [Standard Compliance & Certification Contradictions](#1-standard-compliance--certification-contradictions)
2. [Hardware Safety & Operating System Disk Assumptions](#2-hardware-safety--operating-system-disk-assumptions)
3. [RBAC & Server-Side Security Discrepancies](#3-rbac--server-side-security-discrepancies)
4. [PWA Offline Capabilities vs Forensic Reality](#4-pwa-offline-capabilities-vs-forensic-reality)
5. [API Schema, Field Mismatches & Runtime Exceptions](#5-api-schema-field-mismatches--runtime-exceptions)
6. [Frontend JavaScript Scope & DOM Binding Errors](#6-frontend-javascript-scope--dom-binding-errors)
7. [PyInstaller Packaging & Frozen Path Traps](#7-pyinstaller-packaging--frozen-path-traps)
8. [Process Lifecycle & Socket Port Collisions](#8-process-lifecycle--socket-port-collisions)
9. [Physical Hardware Qualification vs Truth States](#9-physical-hardware-qualification-vs-truth-states)
10. [Framework Deprecations & Runtime Warnings](#10-framework-deprecations--runtime-warnings)

---

## 1. Standard Compliance & Certification Contradictions

### Issue 1.1: Unqualified ISO/IEC 27037 Certification Claims
- **Contradiction**: Earlier drafts and mockups claimed that DREX certificates were "ISO/IEC 27037 Certified".
- **Forensic Reality**: ISO/IEC 27037 ("Guidelines for identification, collection, acquisition and preservation of digital evidence") specifies procedural and organizational standards for digital forensic practitioners and labs. A software product or utility *cannot* legally or technically claim to be "ISO 27037 Certified" unless independently qualified and audited by an accredited conformity assessment body.
- **Remediation**: The banner was updated in `certificate_engine.py` to:
  `"NIST SP 800-88 Rev. 2 Aligned Evidence Record & Cryptographic Attestation"`.
  All claims are strictly grounded in verifiable cryptographic proofs (SHA-256 Merkle chain verification).

### Issue 1.2: "Merkle Tree" vs Hash-Chain Nomenclature
- **Discrepancy**: Documentation and code comments frequently conflated a sequential hash-chain (`H_n = SHA256(H_{n-1} || Event)`) with a "Merkle Tree".
- **Forensic Reality**: A Merkle Tree is a balanced binary tree where non-leaf nodes are hashes of their children, enabling $O(\log N)$ inclusion proofs. A blockchain/audit ledger of `prev_hash -> event -> current_hash` is a sequential hash chain with $O(N)$ verification.
- **Remediation**: Clarified terminology across API models and docs to specifically state **"SHA-256 Hash-Linked Audit Chain"** for sequential logs, preserving "Merkle" strictly for hierarchical manifest verification.

---

## 2. Hardware Safety & Operating System Disk Assumptions

### Issue 2.1: The `PhysicalDrive0 == OS Disk` Fallacy
- **Contradiction**: Initial system-drive protection logic assumed that `PhysicalDrive0` is always the active Windows operating system drive.
- **System Reality**: On modern workstations and laptops with multiple NVMe, SATA, or eMMC drives:
  - NVMe controllers often enumerate *after* SATA controllers depending on PCIe initialization order.
  - Windows boot volume (`C:`) frequently resides on `PhysicalDrive1` or `PhysicalDrive2`.
  - Storage Spaces or dynamic RAID volumes can span multiple physical disks.
  - Targeting `PhysicalDrive1` under the assumption that only `PhysicalDrive0` is protected would destroy the host OS.
- **Remediation**: Implemented `get_windows_system_disk_numbers()` in `hardware_storage.py` using Win32 `IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS` via `CreateFileW(..., 0, ...)` querying active `SystemDrive` and `SystemRoot` environment variables. Fails closed (blocks) on any uncertainty.

---

## 3. RBAC & Server-Side Security Discrepancies

### Issue 3.1: Frontend Tab Visibility Mistaken for Authorization
- **Contradiction**: In early iterations, role switching in the frontend merely toggled tab visibility, while the backend accepted unauthenticated requests by defaulting missing tokens to `JUDGE_DEMO`.
- **Security Reality**: Anyone crafting an HTTP request via `curl` or Postman could invoke destructive sanitization or create cases without credentials.
- **Remediation**:
  - Implemented strict token decoding in `get_current_user` in `drex_server.py`, returning `401 Unauthorized` for missing, expired, or tampered tokens.
  - Created granular `require_permission(perm)` and `require_any_permission([...])` dependencies enforcing server-side `403 Forbidden` responses for unauthorized roles.

### Issue 3.2: Role Separation Violation (Analyst vs Operator)
- **Contradiction**: `FORENSIC_ANALYST` was originally granted `sanitization:execute`.
- **Forensic Duty Separation**: Forensic investigators and evidence analysts must *never* have write/erase authority over physical storage to prevent evidence destruction or spoliation claims in court.
- **Remediation**: Removed `sanitization:execute` from `FORENSIC_ANALYST`. Only `ADMIN`, `OPERATOR`, and `JUDGE_DEMO` (simulation mode) have execution permissions.

---

## 4. PWA Offline Capabilities vs Forensic Reality

### Issue 4.1: The "Full Offline PWA" Contradiction
- **Contradiction**: Product documentation claimed the mobile companion PWA supported "complete offline operational capability".
- **Physical & Legal Reality**:
  - Web browsers (especially mobile WebKit / Chromium) run inside strict OS sandboxes and cannot access raw block devices (`\\.\PhysicalDriveX`).
  - Offline execution of destructive operations creates unverified, detached audit events that cannot be cryptographically bound to the central evidence vault.
- **Remediation**: Added an explicit offline safety gate in `webui/sw.js`. Offline capability is strictly restricted to cached static UI assets and non-sensitive metadata. Any attempt to invoke destructive sanitization, recovery scans, or audit verification offline is intercepted by the Service Worker and returns `503 Service Unavailable (Offline Gated)`.

---

## 5. API Schema, Field Mismatches & Runtime Exceptions

### Issue 5.1: `AttributeError: 'MethodQualificationRecord' object has no attribute 'status'`
- **Error Location**: `drex_server.py:300` in endpoint `GET /api/devices/{device_id}/qualification`.
- **Root Cause**: `hardware_storage.py` defines the dataclass attribute as `qualification_status: QualificationStatus`, but the endpoint attempted to read `rec.status`.
- **Stack Trace**:
  ```python
  status = rec.status.value if hasattr(rec.status, "value") else str(rec.status)
  AttributeError: 'MethodQualificationRecord' object has no attribute 'status'
  ```
- **Remediation**: Updated endpoint to read `rec.qualification_status.value` and formatted `explanation` using `rec.blocking_reasons` / `rec.limitations`.

### Issue 5.2: Missing Required Fields in Test Payloads (HTTP 422)
- **Error Location**: `test_complete_rbac_permission_matrix` in `test_phase10_final_validation.py`.
- **Root Cause**:
  - `POST /api/cases`: Test payload omitted the mandatory `examiner` field defined in `models.ForensicCaseCreate`.
  - `POST /api/recovery/scan`: Test payload omitted the mandatory `destination_dir` field defined in `models.RecoveryScanRequest`.
- **Remediation**: Added `examiner="Lead Analyst"` and `destination_dir="test_output"` to the test fixtures.

---

## 6. Frontend JavaScript Scope & DOM Binding Errors

### Issue 6.1: `ReferenceError: triggerRecoveryScan is not defined`
- **Error Location**: `webui/index.html` and `webui/app.js:296`.
- **Root Cause**: The HTML template used inline `onclick="triggerRecoveryScan()"`, but `triggerRecoveryScan` was not defined or exported to `window` scope in `app.js`.
- **Browser Error**:
  ```javascript
  ReferenceError: triggerRecoveryScan is not defined at HTMLButtonElement.onclick
  ```
- **Remediation**: Implemented `triggerRecoveryScan()` in `webui/app.js` and explicitly attached all inline onclick handlers to `window` (`window.triggerRecoveryScan = triggerRecoveryScan`, `window.closeModal = closeModal`, etc.).

### Issue 6.2: Python Raw String Syntax in JavaScript
- **Error Location**: `webui/app.js:564`.
- **Root Cause**: Accidental insertion of Python raw string literal `r'\\.\PhysicalDrive99'` inside JavaScript code, resulting in syntax parsing issues.
- **Remediation**: Corrected to standard JavaScript escaped string: `'\\\\.\\\\PhysicalDrive99'`.

### Issue 6.3: Modal Close Event Trapping
- **Discrepancy**: The Judge Proof Loop modal could only be dismissed by clicking an inner button, leaving the user trapped if an error occurred.
- **Remediation**: Added global `Escape` key listener and click-outside overlay listener to dismiss the modal cleanly.

---

## 7. PyInstaller Packaging & Frozen Path Traps

### Issue 7.1: Missing Web Assets in PyInstaller Bundle
- **Contradiction**: `build/DREX.spec` had datas for `methods/` and `native_bin/`, but completely omitted `webui/`.
- **Impact**: Running `DREX.exe --server` from a packaged build failed to serve static assets or returned 404 for `index.html`.
- **Remediation**: Added `('D:/drex-v2-main/webui', 'webui')` to `datas` in `build/DREX.spec` and added hidden imports `uvicorn`, `fastapi`, `pydantic`.

### Issue 7.2: Frozen `__file__` Resolution
- **Contradiction**: `ROOT_DIR = pathlib.Path(__file__).resolve().parent` in `drex_server.py` assumes the source tree layout.
- **Impact**: In a PyInstaller onefile executable, files are unpacked to `sys._MEIPASS`, so `__file__` points to a temporary extract folder without repository siblings.
- **Remediation**: Updated to:
  `ROOT_DIR = pathlib.Path(getattr(sys, "_MEIPASS", pathlib.Path(__file__).resolve().parent))`.

---

## 8. Process Lifecycle & Socket Port Collisions

### Issue 8.1: Unhandled Socket Port Collisions (WinError 10048)
- **Error Behavior**: Starting a second instance of `python drex_app.py --server` when port 8765 is already bound produced an unhandled traceback from Uvicorn (`[WinError 10048] only one usage of each socket address is normally permitted`) and exited with return code 3.
- **Remediation**: Wrapped server and web startup in `drex_app.py` with explicit `try...except OSError` handling that prints:
  `DREX-V2 Port Collision Error: Port 8765 is already in use.` and cleanly exits with code 1.

---

## 9. Physical Hardware Qualification vs Truth States

### Issue 9.1: Falsely Marking USB-Attached Drives as Qualified for ATA/NVMe Sanitize
- **Contradiction**: Early mockups marked methods like ATA Secure Erase (Method 4) and NVMe Format/Sanitize (Method 5) as "SUPPORTED" on all external drives.
- **Hardware Reality**: Consumer USB-to-SATA/NVMe bridge controllers (e.g., JMicron, Realtek, ASMedia) filter out vendor-specific ATA Task File registers and NVMe Admin commands, dropping low-level sanitize opcodes.
- **Truth State Architecture**: Methods 3, 4, and 5 truthfully report `UNSUPPORTED` or `HARDWARE_REQUIRED` with diagnostic messages explaining the USB bridge limitation, rather than simulating false success.

---

## 10. Framework Deprecations & Runtime Warnings

### Issue 10.1: AnyIO HTTP 422 Deprecation Notice
- **Warning**:
  `C:\Users\NIRMAL KUMAR\Lib\site-packages\anyio\_backends\_asyncio.py:986: DeprecationWarning: 'HTTP_422_UNPROCESSABLE_ENTITY' is deprecated. Use 'HTTP_422_UNPROCESSABLE_CONTENT' instead.`
- **Classification**: Informational upstream deprecation warning in Python 3.14 / Starlette / AnyIO. The standard HTTP status code 422 continues to behave correctly across all test clients and browser fetch APIs.
