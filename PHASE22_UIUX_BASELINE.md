# DREX V2 — PHASE 22 UI/UX BASELINE & ARCHITECTURAL INVENTORY
## Master Forensic Workstation Production Hardening Baseline

**Repository Path**: `D:\drex-v2-main` (`D:\DREXX` junction)  
**Authoritative Git Origin**: `https://github.com/nirmal-max/drex-v2.git`  
**Current HEAD Commit**: `f030382` (`fix: resolve phase 21.2 acceptance findings`)  
**Previous Audited Baseline**: `1988f39`  
**Working Tree Status**: Clean (0 uncommitted changes, tracked to `origin/main`)  
**Audit Date**: September 16, 2026  
**Document Classification**: Forensic UI/UX Architecture Baseline & Defect Census  

---

## 1. Executive Summary

Phase 22 focuses on transforming DREX V2 from an ensemble of verified forensic engines into a **coherent, production-hardened forensic workstation**. While Phases 21.1 and 21.2 successfully established cryptographic truth, eliminated false PASS badges, and proved test suite provenance (977 passed pytest invariants), the user interface exhibits critical interactive gaps:

1. **Sanitization Live Progress Void**: The sanitization execution pipeline in `drex_server.py` runs synchronously within the HTTP handler. The web UI displays a static loading string (`"Executing real backend sanitization..."`) until the entire overwrite and verification process concludes. There is no live progress bar, no initial non-zero operational indicator (e.g. `0.01%`), no live phase tracking, no byte counters, no throughput speed (EMA), and no separate post-wipe verification visualization.
2. **Fabricated Recovery Stepper in Frontend**: In `webui/app.js` (`executeRecoveryScan`), the frontend uses a client-side `setInterval` timer advancing hardcoded percentage stages (`[25%, 50%, 75%, 90%, 100%]`) based on poll count rather than binding directly to real backend thread telemetry.
3. **Function Shadowing Defect in Drive Eraser**: In `webui/app.js`, two conflicting definitions of `submitSanitization` exist. The latter definition (line 5385) overwrites the authentic handler (line 4911) and attempts to post to a non-existent `/api/drive-eraser/execute` endpoint.
4. **Disjoint Operation Status Contract**: The backend `JobRegistry` and `models.JobStatusRecord` track `percent_complete` and `status`, but lack standardized, first-class fields for `phase`, `processed_bytes`, `total_bytes`, `speed`, `eta`, and `verification_state`.
5. **No Central Active Operations Query**: No endpoint exists to query running jobs across cases or within an active case (`/api/jobs/active`), preventing the Dashboard and Operation Center from showing real-time background tasks.
6. **Hardcoded UI Build Hashes**: `webui/index.html` hardcodes `BUILD: fbad09d` in two DOM locations, which fails to reflect live git HEAD (`f030382`).
7. **Missing Design Tokens for Forensic Progress & Operation Cards**: `webui/styles.css` lacks unified forensic progress bar components, phase pill badges, and operation state cards.

---

## 2. Repository & Runtime Environment Baseline

```
================================================================================
DREX V2 REPOSITORY & RUNTIME INVENTORY
================================================================================
Working Tree:                     D:\drex-v2-main (NTFS, Authoritative)
Junction Alias:                   D:\DREXX -> D:\drex-v2-main
Active Branch:                    main (synchronized with origin/main)
Git Commit HEAD:                  f03038236dcb36250d4da272f1de7b585c436f64
Authoritative Baseline:           1988f3965731ad2e9849f639dbe36772c05f4856
Python Runtime:                   Python 3.14.3 (win32)
Pytest Test Suite Baseline:       977 Collected / 977 Passed (100%)
API Framework:                    FastAPI 0.115+ / AnyIO / Uvicorn (Port 8765)
Desktop Interface:                Python Tkinter/ttk (drex_app.py, 5604 LOC)
Web / Companion Interface:        Vanilla HTML5/ES6/CSS SPA (webui/app.js, 5657 LOC)
Service Worker Cache:             drex-v2-shell-fbad09d
================================================================================
```

---

## 3. Architecture & Component Mapping

### 3.1 Component Surfaces

| Surface | Tech Stack | Role & Scope | Privilege Boundary |
|---|---|---|---|
| **DREX Desktop** | Python Tkinter / ttk (`drex_app.py`) | Native Windows file/device management, direct Win32 IOCTL access, standalone offline workstation. | Admin / Elevated (Direct physical block device access via Win32 API). |
| **DREX Server** | FastAPI / Uvicorn (`drex_server.py`) | Multi-surface REST & WebSocket API gateway, Case Vault manager, Job Registry, audit ledger. | Localhost / Intranet API gateway, RBAC enforced (6 personas). |
| **DREX Web / PWA** | Vanilla HTML5/CSS3/ES6 (`webui/`) | Investigator-first forensic workstation interface, case dossiers, live telemetry visualizers, independent verification. | Browser sandbox; connects to server via authenticated REST/WS. |
| **Standalone Verifier** | Python CLI (`drex_verify.py`) | Zero-dependency offline verification tool for Schema 2.0 evidence packages. | Independent offline verification. |

### 3.2 Backend Engines

- **`file_sanitizer.py`**: Clean-room implementations of NIST SP 800-88 Rev. 2 Clear, DoD 5220.22-M (3-pass/7-pass), Gutmann 35-pass, CSPRNG overwrite, single-pass zero, slack space scrubber, free space filler, and crypto key invalidator.
- **`hardware_storage.py`**: Physical disk detection, ATA/NVMe pass-through qualification, dynamic Windows boot/OS disk lock tripwire.
- **`recovery_adapter.py` / `carver_engine.py`**: Multi-method recovery dispatcher (TSK, PhotoRec, Stream Carver) with 5-factor candidate confidence scoring.
- **`fragment_engine.py`**: Non-contiguous out-of-order file fragment reassembly, boundary seam calculation, and structural validation.
- **`forensic_vault.py`**: SHA-256 hash-chained audit ledger, case management, and immutable evidence vault.
- **`certificate_engine.py`**: Pure-Python PDF 1.4 forensic attestation certificate generator with tamper-evident cryptographic seals.

---

## 4. In-Depth Audit of Current UX & Progress Deficiencies

### 4.1 Sanitization Execution & Progress Architecture

#### Backend: Synchronous Execution in `drex_server.py`
In `drex_server.py` (`@app.post("/api/sanitization/execute")`):
```python
# Lines 1805-1820
cancel_token = job_registry.register_job(...)
job_registry.update_job(job_id, status=models.JobLifecycleState.RUNNING, progress_percent=50.0)

# Lines 1866-1877 (Synchronous execution blocks the request!)
res = FileSanitizer.wipe_file(target_p, standard=SanitizationStandard.CSPRNG_OVERWRITE, unlink_after=False)
...
# Lines 1948-1951
job_registry.update_job(job_id, status=models.JobLifecycleState.COMPLETED, progress_percent=100.0, ...)
return result_payload
```
**Defects Identified**:
1. Synchronous execution prevents any progressive state streaming during writing.
2. `FileSanitizer.wipe_file` has no `progress_callback` or `cancellation_token` parameters.
3. Progress jumps directly: `0%` -> `50%` -> `100%`.
4. Writing and post-wipe verification are bundled into a single opaque step; the user cannot see when writing ends and readback/entropy verification begins.

#### Frontend: Static Loading State in `webui/app.js`
In `webui/app.js` (`executeFileShredder`):
```javascript
// Line 3458-3463
resultBox.innerHTML = '<em>Executing real backend sanitization, TOCTOU identity revalidation, and post-wipe entropy check...</em>';

// Synchronous await blocks UI updates until server completes
const res = await api('/api/sanitization/execute', { ... });
```
**Defects Identified**:
1. Zero progress bar is shown during sanitization.
2. The user sees no byte counter, no phase indicator (`PRECHECK`, `PREPARING`, `WRITING`, `VERIFYING`, `SEALING`), and no cancellation capability.
3. Does not satisfy the mandatory Requirement 6: Transitioning to `0.01%` or truthful initial value upon actual work commencement.

### 4.2 Recovery Scan Progress Architecture

In `webui/app.js` (`executeRecoveryScan`):
```javascript
// Lines 5170-5176
const stages = [
  { pct: 25, label: 'QUEUED: Forensic worker thread allocated...', badge: 'QUEUED' },
  { pct: 50, label: 'SCANNING: Deep sector and cluster signature traversal...', badge: 'SCANNING' },
  { pct: 75, label: 'VALIDATING: Seam alignment & confidence scoring...', badge: 'VALIDATING' },
  { pct: 90, label: 'SEALING: Evidence vault candidate cataloging...', badge: 'EVIDENCE_SEALING' },
  { pct: 100, label: 'COMPLETED: Recovery scan finished.', badge: 'COMPLETED' },
];

let pollCount = 0;
const pollInterval = setInterval(async () => {
  pollCount++;
  ...
  const stageIdx = Math.min(pollCount - 1, stages.length - 1);
  const stage = stages[stageIdx];
  if (bar) bar.style.width = `${stage.pct}%`;
  ...
}, 1000);
```
**Defect Identified**:
This violates Principle 37 ("NO FAKE PROGRESS"). The progress percentage advances based on timer ticks rather than real backend sector scanning or candidate discovery count.

### 4.3 Drive Eraser Function Shadowing Defect

In `webui/app.js`:
- Line 4911: Authentic `submitSanitization(devicePath, methodId, phrase)` calls `/api/sanitization/execute`.
- Line 5385: Duplicate declaration `submitSanitization(devicePath, methodId)` calls `/api/drive-eraser/execute` (which does not exist in FastAPI backend, yielding HTTP 404).
Because ES5/ES6 function hoisting in browsers replaces earlier functions with identical names, invoking `submitSanitization` from the modal invokes the broken line 5385 implementation.

### 4.4 Operation Status Contract Gap

The existing `JobStatusRecord` in `drex_api_models.py` lacks top-level fields required by the unified specification (Section 38):
- `phase`: Current operation phase (`PRECHECK`, `WRITING`, `VERIFYING`, `SEALING`, etc.)
- `processed_bytes`: Real cumulative bytes written or scanned.
- `total_bytes`: Total byte target.
- `speed`: Real EMA throughput in bytes/sec.
- `eta`: Real calculated time remaining or `"Calculating..."` / `"—"`.
- `verification_state`: Verification stage status (`NOT_STARTED`, `IN_PROGRESS`, `VERIFIED`, `FAILED`).

---

## 5. Visual & Design System Audit

1. **Color Tokens**: The palette (`#1769E0`, `#168A4A`, `#C62828`, `#0B1F3A`) is solid, but lacks subtle state variations for forensic phases (`PRECHECK`, `WRITING`, `VERIFYING`).
2. **Missing Forensic Progress Component**: No reusable `.forensic-progress-card` exists in `styles.css`.
3. **Empty States**: Views like `vault`, `cases`, and `certificates` have functional text, but need clear forensic call-to-action cards rather than simple text notes.
4. **Context Bar**: `renderOperationalContextBar` displays Case, Source, Workflow, Method, and Status, but does not update reactively when an operation starts or transitions phases.

---

## 6. Action Items for Implementation Phase

1. **Extend `file_sanitizer.py`**: Add optional `progress_callback(bytes_written, total_bytes, phase)` and `cancellation_token` to `wipe_file` and `wipe_directory_tree`.
2. **Upgrade `JobRegistry` in `drex_server.py`**: Add full support for `phase`, `processed_bytes`, `total_bytes`, `speed_bps`, `eta_seconds`, and `verification_state`. Add `GET /api/jobs/active`.
3. **Asynchronous Sanitization Job Pipeline**: Convert `/api/sanitization/execute` to run in background worker threads while immediately registering and returning the `JobStatusRecord` for live polling / SSE / WebSocket subscription.
4. **Build Unified Forensic Progress Card (`webui`)**: Implement an authoritative, reusable operation card with:
   - Operation Title & Method Badge
   - Target Path & Namespace Identity
   - Active Phase & Real Percentage (transitioning from `PREPARING` to `0.01%` upon first byte written)
   - Processed / Total Bytes
   - Real Speed & ETA
   - Visually distinct Verification Phase
   - Cooperative Cancel Action
5. **Eliminate Fake Recovery Progress Stepper**: Bind recovery progress directly to `JobRegistry` status and candidate counts.
6. **Fix `drive_eraser` Shadowing**: Consolidate `submitSanitization` to call `/api/sanitization/execute` and bind to the unified progress card.
7. **Synchronize Build Hash**: Dynamically load or update the Git commit hash in the web console (`f030382`).
8. **Empirical Regression Verification**: Validate every change against the full pytest suite (977 tests) and browser walkthrough.
