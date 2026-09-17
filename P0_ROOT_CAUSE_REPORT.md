# DREX V2 — P0 Root Cause Investigation Report

**Canonical Workspace**: `D:\drex-v2-main`  
**Baseline HEAD**: `d8fb4231689594accd9230b35196ec7307313d07`  
**Branch**: `main`  
**Remote**: `https://github.com/nirmal-max/drex-v2.git`  
**Baseline Pytest Metrics**: 996 passed, 21 warnings in 280.86s (0 failed, 0 errors, 0 skipped)  
**Untracked Files**: `package-lock.json` (auto-generated empty npm lockfile `{ "name": "drex-v2-main", "lockfileVersion": 3, "requires": true, "packages": {} }` from node script execution; documented for gitignore/tracking resolution).

---

## P0-01 — Drive Eraser Method Selection

- **P0 ID**: P0-01
- **Observed Video Symptom**: The Drive Eraser UI shows an active/preselected method banner, but does not provide a genuine method-selection workflow. Clicking "Plan Sanitization" executes with a hardcoded or fallback method (e.g., Method 8 CSPRNG overwrite rather than physical drive methods M01–M07).
- **Exact Source Files**:
  - `webui/app.js` (lines 3118–3162, 5563, 6015)
  - `drex_server.py` (lines 1950–2350)
- **Exact Functions/Components**:
  - `renderDriveEraser()` in `webui/app.js`
  - `openDestructiveConfirm()` / `submitSanitization()` in `webui/app.js`
  - `execute_sanitization()` / `_execute_worker()` in `drex_server.py`
- **Exact Faulty Code Path**:
  1. `renderDriveEraser()` reads `const activeMethodId = STATE.selectedDriveMethod || 1;` and renders a static summary card with no interactive method selector.
  2. Clicking "Plan Sanitization →" calls `openDestructiveConfirm(devicePath, model)` where `confirmBtn.onclick` executes `const selectedMethod = STATE.selectedDriveMethod || 8;` (defaulting to method 8, which is file shredder).
  3. `drex_server.py` `execute_sanitization()` checks `if "PhysicalDrive" in req.target_path` and executes a synthetic in-memory buffer (`exec_type = "IN_MEMORY_TEST_EXECUTION"`) instead of dispatching to `DeviceIntelligenceEngine.execute_hardware_sanitization()` or specific drive methods (M01 NIST Clear, M02 Smart, M03 Device-Native, M04 ATA Secure Erase, M05 NVMe Sanitize, M06 IEEE 2883 Purge, M07 Verified Overwrite).
- **Exact Faulty Logic**:
  - Lack of interactive M01–M07 selection matrix with live qualification status in Drive Eraser.
  - Hardcoded fallback `STATE.selectedDriveMethod || 8` inside modal closure.
  - Backend `execute_sanitization` bypassed real hardware sanitization engines for physical targets in favor of in-memory synthetic byte chunk simulation.
- **Upstream Caller**: User clicking "Plan Sanitization →" on a physical storage drive in Drive Eraser.
- **Downstream Consumer**: `/api/sanitization/execute`, background worker thread, `job_registry`, audit ledger, certificate generator.
- **Why Existing Tests Missed It**: Tests exercised `DeviceIntelligenceEngine.qualify_25_methods()` and `DeviceSafetyStateMachine.evaluate_safety()` in isolation using mock snapshots, but never validated that the HTTP API endpoint `/api/sanitization/execute` receives and dispatches M01–M07 dynamically based on frontend user selection.
- **Root Cause**: Missing method selection selector in the Drive Eraser UI, default method 8 fallback, and lack of backend hardware sanitization dispatch wiring in `execute_sanitization`.
- **Security/Safety Impact**: High risk of unintended method execution (e.g. running file shredder logic or synthetic test buffers on physical drives), failure to execute hardware-native commands (ATA/NVMe sanitize), and inaccurate audit trails.
- **Proposed Correction**:
  1. In `webui/app.js`: Render interactive M01–M07 method selection grid in Drive Eraser with live capability badges (`AVAILABLE`, `UNSUPPORTED`, `BLOCKED`, `BACKEND_UNAVAILABLE`, `HARDWARE_REQUIRED`, `NOT_APPLICABLE`).
  2. Bind user selection to `STATE.selectedDriveMethod`.
  3. In `openDestructiveConfirm()`: Ensure selected method matches `STATE.selectedDriveMethod || 1` and passes it to `/api/sanitization/execute`.
  4. In `drex_server.py`: In `execute_sanitization`, dispatch physical drive sanitization to `DeviceIntelligenceEngine.execute_hardware_sanitization()` or method-specific physical overwriters (M01, M02, M03, M04, M05, M06, M07), rejecting unsupported methods fail-closed.
- **Regression Test**: `tests/test_p0_01_drive_method_selection.py`
- **Browser Test**: Open Drive Eraser -> Verify M01–M07 selector -> Select M01 -> Switch to M04 -> Verify qualification badge -> Confirm API payload and operation card reflect M04.
- **Runtime Test**: Execute M01 on a disposable fixture -> Verify `job.method_id == 1` -> Verify audit and certificate reflect M01.
- **Expected Evidence**: API request payload contains exact chosen method ID; operation record, audit trail, and certificate reflect chosen method.

---

## P0-02 — Recovery Physical Device Access Denied

- **P0 ID**: P0-02
- **Observed Video Symptom**: Recovery scan against `\\.\PHYSICALDRIVE1` fails with error: `Error opening image file \\.\PHYSICALDRIVE1 Access denied`.
- **Exact Source Files**:
  - `drex_server.py` (lines 951–962, 1414–1655)
  - `webui/app.js` (lines 1816–1845, 1882–1940)
  - `hardware_storage.py` (lines 1464–1473)
- **Exact Functions/Components**:
  - `launch_recovery_scan()` in `drex_server.py`
  - `get_system_version()` in `drex_server.py`
  - `updateRecoverySourceDetailsCard()` in `webui/app.js`
  - `DeviceIntelligenceEngine.is_elevated()` in `hardware_storage.py`
- **Exact Faulty Code Path**:
  1. DREX was launched via standard Python (`python drex_app.py --web`) without Administrator privileges.
  2. UI showed "Senior Forensic Analyst" (RBAC application role), misleading the operator into believing the process had raw physical device access privileges.
  3. `launch_recovery_scan()` dispatched TSK `fls.exe` against `\\.\PHYSICALDRIVE1` directly without checking if the current Windows process possessed Administrator token privileges.
  4. Windows kernel denied handle creation to raw physical drive (`Access denied`).
- **Exact Faulty Logic**:
  - Conflation of application-level RBAC role ("Senior Forensic Analyst") with operating-system-level process elevation token.
  - Missing Windows elevation preflight check in `/api/recovery/scan` and recovery UI before invoking raw handle operations.
- **Upstream Caller**: User selecting `\\.\PhysicalDriveN` in Forensic Recovery and clicking "Launch Recovery Scan".
- **Downstream Consumer**: Recovery dispatcher, TSK `fls.exe`, PhotoRec, raw physical disk handles.
- **Why Existing Tests Missed It**: Automated tests ran against test fixture disk images (`sample_disk.img`) where standard user read privileges suffice, never testing physical drive path preflight under non-elevated tokens.
- **Root Cause**: Missing separation between RBAC Role and Windows Process Elevation; lack of preflight elevation check for physical disk targets.
- **Security/Safety Impact**: Process crashes, raw handle access failures, and operator confusion.
- **Proposed Correction**:
  1. Expose `is_windows_elevated: bool` in `/api/system/version` and `/api/auth/me`.
  2. In `webui/app.js`: Render distinct badges: RBAC Role (`Senior Forensic Analyst`) vs Windows Elevation (`ELEVATED` / `NOT ELEVATED`).
  3. In `launch_recovery_scan()`: For physical drive targets (`PhysicalDrive` / `\\.\`), verify `DeviceIntelligenceEngine.is_elevated()`. If not elevated, fail closed with HTTP 422: `WINDOWS ELEVATION REQUIRED: Direct raw physical-device access requires Windows Administrator privileges. Please run DREX with elevated privileges or launch the packaged DREX.exe binary.`
  4. In `webui/app.js`: If target is physical and process is not elevated, display `WINDOWS ELEVATION REQUIRED` and disable the launch button. For disk image files, permit execution without elevation.
- **Regression Test**: `tests/test_p0_02_elevation_access.py`
- **Browser Test**: Select physical drive -> Check elevation badge -> Verify `WINDOWS ELEVATION REQUIRED` banner when not elevated. Select disk image file -> Verify scan is permitted.
- **Runtime Test**: Query `/api/system/version` -> Assert `is_windows_elevated` accurately reflects process token.
- **Expected Evidence**: Non-elevated physical recovery returns truthful blocked state with guidance; disk images continue to scan properly.

---

## P0-03 — Recovery Stale Candidates

- **P0 ID**: P0-03
- **Observed Video Symptom**: A scan reports `0 candidates`, but old recovery candidates from an earlier scan or fixture remain visible in the candidates table.
- **Exact Source Files**:
  - `webui/app.js` (lines 1763–1779, 2020–2075)
  - `drex_server.py` (lines 1670–1715)
- **Exact Functions/Components**:
  - `renderRecoveryTable()` in `webui/app.js`
  - `loadRecoveryCandidates()` in `webui/app.js`
  - `handleRecoverySourceChange()` in `webui/app.js`
  - `get_recovery_candidates()` in `drex_server.py`
- **Exact Faulty Code Path**:
  1. In `webui/app.js` line 2041:
     ```javascript
     let cands = (STATE.recoveryCandidates && STATE.recoveryCandidates.length > 0)
       ? STATE.recoveryCandidates
       : (STATE.candidates || []);
     ```
  2. When a scan found 0 candidates, `STATE.recoveryCandidates` was set to `[]` (`length === 0`).
  3. The ternary evaluated to false, falling back to `STATE.candidates || []` (which held previous candidates from an earlier scan).
  4. In `drex_server.py`, `/api/recovery/candidates` listed all historical candidates added to the case without filtering by source.
- **Exact Faulty Logic**:
  - Fallback to stale `STATE.candidates` when `STATE.recoveryCandidates` was empty array.
  - Failure to clear all candidate caches upon source switch or zero-candidate scan completion.
- **Upstream Caller**: `executeRecoveryScan()` completion callback, `handleRecoverySourceChange()`, `loadRecoveryCandidates()`.
- **Downstream Consumer**: `renderRecoveryTable()`, `recoveryResultsContainer` DOM.
- **Why Existing Tests Missed It**: Tests ran single scans against positive fixtures in isolated test cases, never executing a sequential two-scan scenario (Scan A with candidates -> Scan B with 0 candidates) on the same UI instance.
- **Root Cause**: Faulty ternary fallback logic in frontend table rendering and lack of candidate state reset on zero-result scans.
- **Security/Safety Impact**: Forensic evidence contamination: presenting artifacts from previous media as having been recovered from the current target.
- **Proposed Correction**:
  1. In `webui/app.js`: Eliminate `STATE.candidates` fallback. Use `STATE.recoveryCandidates || []`. When empty, render: `NO RECOVERY CANDIDATES: No artifacts were discovered by this scan.`
  2. In `handleRecoverySourceChange()`: Clear `STATE.recoveryCandidates = []` and `STATE.carvingCandidates = []`.
  3. In `executeRecoveryScan()`: Clear existing candidate state before launching new scan, and reload strictly for the current scan/source.
- **Regression Test**: `tests/test_p0_03_stale_candidates.py`
- **Browser Test**: Scan fixture A (candidates populated) -> Select empty fixture B -> Scan fixture B (0 candidates) -> Assert candidate table displays zero rows and "NO RECOVERY CANDIDATES" message.
- **Runtime Test**: API call `/api/recovery/candidates` with source filtering returns 0 records.
- **Expected Evidence**: Empty table with "NO RECOVERY CANDIDATES" message when scan finds 0 artifacts.

---

## P0-04 — Case / Operation Context Isolation

- **P0 ID**: P0-04
- **Observed Video Symptom**: UI active case is `DEMO-1789392921`, but an active operation card displays `CASE-20260914-002CC4FB` without indicating that it belongs to a historical/different case.
- **Exact Source Files**:
  - `webui/app.js` (lines 3804–3924, 4100–4176)
  - `drex_server.py` (lines 1370–1378)
- **Exact Functions/Components**:
  - `loadActiveOperations()` in `webui/app.js`
  - `filterActiveOpsList()` in `webui/app.js`
  - `renderForensicOperationCard()` in `webui/app.js`
  - `get_active_jobs_endpoint()` in `drex_server.py`
- **Exact Faulty Code Path**:
  1. `loadActiveOperations()` requested `/api/jobs/active?case_id=...`. If case ID was omitted or all active jobs were returned, jobs from multiple cases entered `STATE.currentActiveJobsList`.
  2. `filterActiveOpsList()` did not strictly filter by `STATE.activeCase.case_id`.
  3. `renderForensicOperationCard()` rendered `job.case_id` directly without distinguishing current-case operations from historical cross-case operations.
- **Exact Faulty Logic**:
  - Lack of case-isolation enforcement in active operations dashboard view.
  - Lack of visual distinction (`HISTORICAL CASE`) for operations originating from other cases.
- **Upstream Caller**: `navigateTo('active_operations')`, periodic active jobs polling.
- **Downstream Consumer**: Active operations dashboard, forensic operation cards.
- **Why Existing Tests Missed It**: Tests verified case creation and single-case job registry, but did not test multi-case active operations dashboard rendering with case switching.
- **Root Cause**: Missing case filter in `filterActiveOpsList` and missing `HISTORICAL CASE` badge in `renderForensicOperationCard`.
- **Security/Safety Impact**: Cross-case data leakage and investigator confusion regarding which operation belongs to which case.
- **Proposed Correction**:
  1. In `loadActiveOperations()` and `filterActiveOpsList()`: Filter jobs strictly to `activeCase.case_id`.
  2. In `renderForensicOperationCard()`: If a job from a different case is explicitly rendered, display a prominent badge: `HISTORICAL CASE: ${job.case_id}`.
  3. Enforce strict invariant: `operation.case_id == job.case_id == evidence.case_id == certificate.case_id`.
- **Regression Test**: `tests/test_p0_04_case_context_isolation.py`
- **Browser Test**: Create Operation in Case A -> Switch to Case B -> Verify Operation A does not appear in Case B view -> Switch back to Case A -> Verify Operation A is present.
- **Runtime Test**: GET `/api/jobs/active?case_id=CASE-A` returns only Case A jobs.
- **Expected Evidence**: Complete case isolation with zero cross-case card leakage.

---

## P0-05 — Duplicate Physical Device Inventory

- **P0 ID**: P0-05
- **Observed Video Symptom**: Recovery source selector displays duplicate `\\.\PHYSICALDRIVE0` entries with identical model/serial/path but different capacity values.
- **Exact Source Files**:
  - `drex_app.py` (lines 163–258)
  - `drex_server.py` (lines 1033–1105)
  - `webui/app.js` (lines 1900–1903)
- **Exact Functions/Components**:
  - `discover_drives()` in `drex_app.py`
  - `list_devices()` in `drex_server.py`
  - `renderRecovery()` in `webui/app.js`
- **Exact Faulty Code Path**:
  1. `discover_drives()` in `drex_app.py` iterated over `Win32_LogicalDisk` (logical volume letters like C:, D:).
  2. If PhysicalDrive0 contained two partitions (e.g. C: 150GB and D: 800GB), it created two separate `DriveInfo` items, both having `device_path = "\\.\PHYSICALDRIVE0"`, with different volume capacities.
  3. In `drex_server.py` `list_devices()`, deduplication retained the capacity of the first volume encountered rather than true physical disk capacity.
- **Exact Faulty Logic**:
  - Device enumeration initiated from logical volumes rather than canonical physical drive hardware descriptors.
  - Emitting multiple `DriveInfo` records for the same physical disk with partition sizes instead of physical disk capacity.
- **Upstream Caller**: `drex_app.discover_drives()`, `/api/devices`.
- **Downstream Consumer**: Recovery target selector, Drive Eraser device list, device qualification engine.
- **Why Existing Tests Missed It**: Mock drive fixtures provided pre-deduplicated drive records with distinct IDs, bypassing the Windows CIM/WMI logical-to-physical aggregation path.
- **Root Cause**: Top-down logical disk iteration instead of bottom-up physical disk enumeration with partition extent aggregation.
- **Security/Safety Impact**: Targeting wrong physical drive or confusion over actual drive geometry; duplicate UI entries.
- **Proposed Correction**:
  1. Refactor `discover_drives()` to a 4-stage pipeline:
     - Stage 1: Enumerate physical `Win32_DiskDrive` hardware first (Index, DeviceID, Model, SerialNumber, Size, MediaType, InterfaceType).
     - Stage 2: Normalize device path to canonical `\\.\PhysicalDriveN`.
     - Stage 3: Map logical partitions via `Win32_LogicalDiskToPartition` into `mount_points`.
     - Stage 4: Emit exactly 1 canonical `DriveInfo` per physical drive with true physical disk capacity.
  2. Ensure `/api/devices` and recovery source dropdown consume this single canonical inventory.
- **Regression Test**: `tests/test_p0_05_device_deduplication.py`
- **Browser Test**: Open Recovery and Drive Eraser views -> Assert each `\\.\PhysicalDriveN` appears exactly once in dropdowns and card lists.
- **Runtime Test**: Call `/api/devices` -> Assert `[d.device_path for d in devices]` contains zero duplicate paths.
- **Expected Evidence**: Unique physical drive paths across all UI selectors with accurate total disk capacity.

---

## P0-06 — Evidence Vault Count Mismatch

- **P0 ID**: P0-06
- **Observed Video Symptom**: Evidence table displays rows of ingested objects, but header summary displays `Total Objects: 0`.
- **Exact Source Files**:
  - `webui/app.js` (lines 1252–1365)
- **Exact Functions/Components**:
  - `renderVault()` in `webui/app.js`
  - `loadVaultEvidence()` in `webui/app.js`
- **Exact Faulty Code Path**:
  1. `renderVault()` constructed the static page HTML with `itemsCount = (STATE.evidenceItems && STATE.evidenceItems.length) || 0;`.
  2. On initial page navigation, `STATE.evidenceItems` was `[]`, so the HTML string rendered `Total Objects: <strong>0</strong>`.
  3. `loadVaultEvidence()` was called asynchronously, fetched `/api/evidence?case_id=...`, populated `STATE.evidenceItems`, and rendered rows into `#vaultTableContainer`.
  4. It never updated the `Total Objects` header counter because the header span lacked an ID and was not updated upon API resolution.
- **Exact Faulty Logic**:
  - Asynchronous render mismatch: table container was updated on API fetch completion, but header stats were statically rendered before fetch and never refreshed.
- **Upstream Caller**: `navigateTo('vault')`.
- **Downstream Consumer**: Evidence Vault header badge, DOM `#vaultTableContainer`.
- **Why Existing Tests Missed It**: Headless tests queried table rows or API responses directly, without validating the synchronization between header badge text and rendered table row counts.
- **Root Cause**: Missing DOM element ID on header count span and missing update in `loadVaultEvidence()`.
- **Security/Safety Impact**: UI inconsistency causing audit confusion during forensic reviews.
- **Proposed Correction**:
  1. Add `id="vaultTotalObjectsCount"` to the header count element.
  2. In `loadVaultEvidence()`: After setting `STATE.evidenceItems`, update `document.getElementById('vaultTotalObjectsCount').textContent = STATE.evidenceItems.length`.
- **Regression Test**: `tests/test_p0_06_evidence_count.py`
- **Browser Test**: Open Evidence Vault for a case with N items -> Assert `#vaultTotalObjectsCount` text equals N and equals `document.querySelectorAll('#vaultTableContainer tbody tr').length`.
- **Runtime Test**: API count equals rendered row count equals header counter.
- **Expected Evidence**: Header `Total Objects: N` exactly equals visible table rows.

---

## P0-07 — Certificate Count and Digest Lifecycle

- **P0 ID**: P0-07
- **Observed Video Symptom**:
  1. Certificate table shows rows, but header displays `Total Certificates: 0`.
  2. An evidence object displays `SEALED & HASH-LOCKED` while SHA-256 displays `CALCULATING_DIGEST`.
- **Exact Source Files**:
  - `webui/app.js` (lines 1407, 1593–1700)
  - `drex_server.py` (lines 1287–1365)
- **Exact Functions/Components**:
  - `renderCertificates()` / `loadCertificates()` in `webui/app.js`
  - `openEvidenceDetailsDrawer()` in `webui/app.js`
  - `list_evidence()` in `drex_server.py`
- **Exact Faulty Code Path**:
  1. Certificate counter bug: `renderCertificates()` rendered `Total Certificates: ${certCount}` before `loadCertificates()` fetched `/api/certificates`, and `loadCertificates()` never updated the header counter.
  2. Digest lifecycle bug: In `drex_server.py` line 1333, `is_sealed` was set to `getattr(it, "read_only", True)` regardless of whether `sha256_hash` existed. If hash was empty, `openEvidenceDetailsDrawer()` displayed `✓ SEALED & HASH-LOCKED` while falling back to `CALCULATING_DIGEST` for the hash field.
- **Exact Faulty Logic**:
  - Header count element was not updated dynamically upon API resolution.
  - Setting `is_sealed = True` without verifying that a valid 64-character SHA-256 digest is present and verified.
- **Upstream Caller**: `navigateTo('certificates')`, `openEvidenceDetailsDrawer()`, `/api/evidence`.
- **Downstream Consumer**: Certificate registry, Evidence details drawer, audit verification engine.
- **Why Existing Tests Missed It**: Tests verified certificate generation and digest calculation on sealed items, but did not assert the negative invariant: an item with empty hash MUST NOT have `is_sealed == True`.
- **Root Cause**: Premature `is_sealed` assignment in `/api/evidence` without digest verification; missing dynamic counter update in `loadCertificates()`.
- **Security/Safety Impact**: Critical forensic integrity violation: claiming an object is sealed and hash-locked when no hash exists.
- **Proposed Correction**:
  1. In `drex_server.py`: In `list_evidence()`, compute `is_sealed = bool(h and len(h) == 64 and read_only)`.
  2. In `webui/app.js`: In `openEvidenceDetailsDrawer()`, enforce lifecycle: `CREATED` -> `HASHING` -> `HASH VERIFIED` -> `AUDIT SEALED` -> `FINAL / VERIFIED`. Never display "SEALED & HASH-LOCKED" if hash is missing.
  3. Add `id="certificatesTotalCount"` and update it dynamically in `loadCertificates()`.
- **Regression Test**: `tests/test_p0_07_certificate_lifecycle.py`
- **Browser Test**: Open Certificates view -> Assert header count matches rows. Open Evidence details -> Assert no object with missing hash shows "SEALED & HASH-LOCKED".
- **Runtime Test**: GET `/api/evidence` -> Assert every record where `is_sealed == True` has `len(sha256_hash) == 64`.
- **Expected Evidence**: Header count matches rows; zero instances of SEALED + CALCULATING_DIGEST.

---

## P0-08 — Authentication Error UX

- **P0 ID**: P0-08
- **Observed Video Symptom**: When an unauthenticated or expired request occurs, the UI displays a raw FastAPI error JSON: `{"detail":"Authentication required: missing Authorization Bearer header"}`.
- **Exact Source Files**:
  - `webui/app.js` (lines 324–339)
- **Exact Functions/Components**:
  - `api()` fetch wrapper in `webui/app.js`
  - Global error notification handlers in `webui/app.js`
- **Exact Faulty Code Path**:
  1. Unauthenticated request to protected endpoint returned HTTP 401 with JSON `{"detail":"Authentication required: missing Authorization Bearer header"}`.
  2. `api()` wrapper parsed the JSON and threw `new Error(err.detail)`.
  3. Caller catch blocks passed `ex.message` to `showNotification()` or rendered it into error boxes, exposing the raw backend JSON string.
- **Exact Faulty Logic**:
  - Missing HTTP 401 interceptor in `api()` fetch wrapper to convert authentication errors into a proper user-facing session dialog.
- **Upstream Caller**: All frontend API calls.
- **Downstream Consumer**: UI notification system, modal dialogs, error banners.
- **Why Existing Tests Missed It**: Backend API tests asserted HTTP 401 status code and detail string; frontend automated tests always provided valid JWT tokens and did not test unauthenticated UI flow.
- **Root Cause**: Lack of HTTP 401 interception in frontend API client.
- **Security/Safety Impact**: Raw internal API error leakage, poor investigator UX, confusion over session lifecycle.
- **Proposed Correction**:
  1. In `webui/app.js` `api()`: Intercept `res.status === 401`.
  2. Trigger `handleSessionExpired()`: Show a clean modal/banner:
     `SESSION / AUTHENTICATION REQUIRED: Your authenticated session is missing or expired. [Authenticate / Sign In]`
  3. Retain backend HTTP 401 semantics (do not weaken backend security).
  4. Intercept HTTP 403 separately for permission-denied UI.
- **Regression Test**: `tests/test_p0_08_auth_ux.py`
- **Browser Test**: Send unauthenticated request -> Verify clean Auth Required dialog is displayed; verify zero raw JSON appears in UI.
- **Runtime Test**: Unauthenticated curl returns HTTP 401 JSON; browser UI handles it gracefully.
- **Expected Evidence**: User-friendly authentication prompt without raw JSON.

---

## P0-09 — Recovery Operation Card Semantics

- **P0 ID**: P0-09
- **Observed Video Symptom**: Recovery operation card displays `Verified Sanitized 100%`. Recovery operations are not sanitization operations.
- **Exact Source Files**:
  - `webui/app.js` (lines 3690–3802, 3804–3924)
- **Exact Functions/Components**:
  - `getAuthoritativeProgress()` in `webui/app.js`
  - `renderForensicOperationCard()` in `webui/app.js`
- **Exact Faulty Code Path**:
  1. `getAuthoritativeProgress()` line 3726: `statusMessage = (verState === 'VERIFIED') ? 'Verified Sanitized' : 'Completed (Unverified)';`.
  2. Lines 3744, 3757: `statusMessage = (realPercentage >= 100.0) ? 'Write Complete' : '${displayPercentage} written'`.
  3. These strings were hardcoded for sanitization and executed unconditionally for all job types, including recovery, carving, and analysis jobs.
- **Exact Faulty Logic**:
  - Single monolithic progress message generator without operation-type awareness (`SANITIZATION` vs `RECOVERY` vs `CARVING` vs `ANALYSIS`).
- **Upstream Caller**: `renderForensicOperationCard()`, active operation polling, WebSocket job updates.
- **Downstream Consumer**: Operation card status headers, accessibility `aria-valuenow`, progress messages.
- **Why Existing Tests Missed It**: Telemetry and progress truth tests verified numerical progress values (0.00% to 100.00%) and monotonic byte counting, but did not check domain-specific string semantics across different operation types.
- **Root Cause**: Hardcoded sanitization terminology in shared `getAuthoritativeProgress()` helper.
- **Security/Safety Impact**: Semantic confusion: claiming a disk was "Sanitized" when it was actually subject to read-only forensic recovery.
- **Proposed Correction**:
  1. Inspect `job.operation_type` (`SANITIZATION_EXECUTE`, `RECOVERY_SCAN`, `RECOVERY_EXTRACT`, `CARVING`, etc.) and `job.workflow_id`.
  2. For `RECOVERY`:
     - RUNNING: `Scanning Media...` / `Analyzing Inodes...`
     - VERIFYING: `Validating Candidate Signatures...`
     - COMPLETED (VERIFIED): `Recovery Complete (Candidates Cataloged)`
     - CANCELLED: `Recovery Cancelled`
  3. For `CARVING`:
     - RUNNING: `Carving Raw Sectors...`
     - COMPLETED (VERIFIED): `Raw Carving Complete`
  4. For `SANITIZATION`:
     - Retain: `Writing Pattern...`, `Verifying (Readback & Entropy)...`, `Verified Sanitized`.
- **Regression Test**: `tests/test_p0_09_operation_card_semantics.py`
- **Browser Test**: Launch recovery scan -> Inspect operation card -> Assert status message says "Recovery Complete" or "Scanning Media...", and never contains "Sanitized".
- **Runtime Test**: Job completion event for recovery returns `verification_state == 'VERIFIED'` and UI displays recovery-specific verdict.
- **Expected Evidence**: Clear semantic separation between sanitization and recovery cards.

---

## P0-10 — M25 Forensic Recovery Routing & Diagnostics

- **P0 ID**: P0-10
- **Observed Video Symptom**: User selects `M25 — Forensic Recovery`, but on error the diagnostic reports: `Quick Recovery scan failed.`
- **Exact Source Files**:
  - `recovery_adapter.py` (lines 1365–1445, 1454–1485)
  - `drex_server.py` (lines 1442–1515)
- **Exact Functions/Components**:
  - `ForensicRecoveryAdapter.scan()` in `recovery_adapter.py`
  - `QuickRecoveryAdapter.scan()` in `recovery_adapter.py`
  - `launch_recovery_scan()` in `drex_server.py`
- **Exact Faulty Code Path**:
  1. `launch_recovery_scan()` mapped `engine="25"` to `resolved_method="forensic"`.
  2. `RecoveryDispatcher.get("forensic")` returned `ForensicRecoveryAdapter`.
  3. `ForensicRecoveryAdapter.scan()` called `QuickRecoveryAdapter.scan()` directly:
     ```python
     def scan(self, source: str, cancel: Callable[[], bool] | None = None, timeout: int = 86400) -> RecoveryScan:
         quick = QuickRecoveryAdapter(self.root, self.meipass)
         return quick.scan(source, cancel=cancel, timeout=timeout)
     ```
  4. When `fls.exe` failed, `QuickRecoveryAdapter.scan()` raised: `RecoveryError(f"Quick Recovery scan failed: {res.stderr or 'non-zero exit code'}")`.
  5. The error propagated to the job record without identifying that the active operation was Method M25 Forensic Recovery.
- **Exact Faulty Logic**:
  - Sub-adapter delegation did not preserve parent method identity in diagnostic messages.
- **Upstream Caller**: `RecoveryDispatcher.get("forensic").scan()`, `launch_recovery_scan()`.
- **Downstream Consumer**: Job error message, operation card diagnostic container.
- **Why Existing Tests Missed It**: Tests tested M25 ledger hashing and verification in happy-path scenarios, but never asserted that error diagnostics from M25 retain M25 method identity.
- **Root Cause**: Direct sub-adapter delegation without error wrapping and attribution.
- **Security/Safety Impact**: Diagnostic ambiguity: misleading operators into thinking M17 was executed instead of M25.
- **Proposed Correction**:
  1. In `ForensicRecoveryAdapter.scan()`: Catch sub-stage exceptions and re-raise with explicit hierarchy: `RecoveryError(f"M25 Forensic Recovery -> Quick Recovery sub-stage failed: {err}")`.
  2. Ensure candidate records and scan metadata retain `method_id = "M25"` / `method_id = 25`.
  3. Add regression tests verifying method identity and routing across all M17–M25 methods.
- **Regression Test**: `tests/test_p0_10_m25_routing_diagnostics.py`
- **Browser Test**: Trigger M25 recovery on invalid path -> Assert diagnostic reads `M25 Forensic Recovery -> ...` and operation card reflects Method 25.
- **Runtime Test**: Dispatch every recovery method (M17 through M25) and assert `job.method_id` matches requested method.
- **Expected Evidence**: Explicit M25 method attribution in all diagnostics, job records, and audit logs.

---

## P0-11 — Certificate Page Workflow/Record Context Mismatch

- **P0 ID**: P0-11
- **Observed Video Symptom**: Certificate page context bar displays `METHOD 25 — CRYPTO CERTIFICATE`, while certificate records in the table show `Method M01 Logical Target JUDGE_DEMO`.
- **Exact Source Files**:
  - `webui/app.js` (lines 1593–1628)
- **Exact Functions/Components**:
  - `renderCertificates()` in `webui/app.js`
  - `renderOperationalContextBar()` in `webui/app.js`
- **Exact Faulty Code Path**:
  1. Line 1599 of `webui/app.js`: `renderOperationalContextBar('CERTIFICATES', 'TAMPER_EVIDENT_ATTESTATION', 'METHOD 25 · CRYPTO CERTIFICATE', 'ISSUED')`.
  2. The page context bar statically hardcoded `'METHOD 25 · CRYPTO CERTIFICATE'` for the entire certificates page, regardless of whether the user was viewing case-wide certificates (which may contain M01, M08, M17, etc.) or a specific operation.
- **Exact Faulty Logic**:
  - Hardcoded method subtitle in page-level context bar.
- **Upstream Caller**: `navigateTo('certificates')`.
- **Downstream Consumer**: Certificate page header, context bar.
- **Why Existing Tests Missed It**: Tests validated certificate table contents and PDF download endpoints, not the contextual alignment between header subtitles and table records.
- **Root Cause**: Static subtitle string in `renderCertificates()`.
- **Security/Safety Impact**: Misleading court/judicial presentation context.
- **Proposed Correction**:
  1. Update `renderCertificates()` context bar to display: `CASE ATTESTATION REGISTER (MULTI-METHOD)` when viewing the case certificate register.
  2. If navigated from a specific operation (e.g. M01 or M25), display that specific operation's method ID and target.
  3. Ensure historical records are clearly labeled.
- **Regression Test**: `tests/test_p0_11_certificate_context.py`
- **Browser Test**: Navigate to Certificates view -> Verify context bar displays `CASE ATTESTATION REGISTER (MULTI-METHOD)`. Issue M01 cert -> Verify table row shows M01. Issue M25 cert -> Verify table row shows M25.
- **Runtime Test**: Verify context bar updates appropriately based on navigation state.
- **Expected Evidence**: Consistent context bar matching the active case and attestation register.

---

## P0-12 — Destructive Execution Gating

- **P0 ID**: P0-12
- **Observed Video Symptom**: File/Folder Eraser and Drive Eraser confirmation dialogs enable the "Execute" button as soon as the confirmation phrase is typed, even when `Active Case Binding: NONE` and the operation cannot actually execute.
- **Exact Source Files**:
  - `webui/app.js` (lines 3423–3481, 5535–5566)
- **Exact Functions/Components**:
  - `updateFileShredderPreflight()` in `webui/app.js`
  - `openDestructiveConfirm()` in `webui/app.js`
- **Exact Faulty Code Path**:
  1. In `openDestructiveConfirm()` lines 5557–5559:
     ```javascript
     input.addEventListener('input', () => {
       confirmBtn.disabled = input.value.trim() !== phrase;
     });
     ```
  2. The modal button only checked `input.value === phrase`. It did NOT check `getActiveCaseId()`, system disk safety, or preflight validation state.
  3. If a user had no active case, typing the phrase enabled the button, only for click to fail with an error toast.
- **Exact Faulty Logic**:
  - Button enable condition only validated confirmation phrase string match, bypassing authoritative preflight gate checks (active case, system drive tripwire, elevation, target validity).
- **Upstream Caller**: Confirmation modal input events, preflight update listeners.
- **Downstream Consumer**: Destructive execution buttons (`#confirmEraseBtn`, `#executeFileShredderBtn`).
- **Why Existing Tests Missed It**: Backend tests verified that `/api/sanitization/execute` rejects unassigned cases with HTTP 400/422 (fail-closed), but UI unit tests did not test modal button disabled states under missing case context.
- **Root Cause**: Incomplete enable conditions in modal event listeners.
- **Security/Safety Impact**: Dangerous UX: presenting an actionable destructive button when the operation is not executable; risk of operator confusion.
- **Proposed Correction**:
  1. In `openDestructiveConfirm()` and `updateFileShredderPreflight()`:
     - Check: `!caseId` -> `EXECUTE = DISABLED` with `WHY BLOCKED: NO ACTIVE OPERATIONAL CASE`
     - Check: `isSystem` -> `EXECUTE = DISABLED` with `WHY BLOCKED: SYSTEM DISK PROTECTED`
     - Check: `targetInvalid` -> `EXECUTE = DISABLED` with `WHY BLOCKED: INVALID TARGET`
     - Check: `phraseMismatch` -> `EXECUTE = DISABLED` with `WHY BLOCKED: CONFIRMATION PHRASE PENDING`
     - Check: `!elevated && isPhysical` -> `EXECUTE = DISABLED` with `WHY BLOCKED: WINDOWS ELEVATION REQUIRED`
  2. Only enable the destructive button when ALL gates pass.
- **Regression Test**: `tests/test_p0_12_destructive_button_gates.py`
- **Browser Test**: Open modal with no case -> Type phrase -> Assert Execute button remains disabled with warning -> Select case -> Assert Execute button enables.
- **Runtime Test**: Verify fail-closed behavior at both UI and API layers.
- **Expected Evidence**: Destructive buttons are disabled whenever any safety gate fails.

---

## Summary of Changes

1. **`webui/app.js`**: P0-01, P0-02, P0-03, P0-04, P0-06, P0-07, P0-08, P0-09, P0-11, P0-12
2. **`drex_server.py`**: P0-01, P0-02, P0-03, P0-04, P0-05, P0-07, P0-10
3. **`drex_app.py`**: P0-05
4. **`recovery_adapter.py`**: P0-10
5. **`hardware_storage.py`**: P0-01, P0-02
6. **Regression Tests**: `tests/test_p0_01_drive_method_selection.py` through `tests/test_p0_12_destructive_button_gates.py`
