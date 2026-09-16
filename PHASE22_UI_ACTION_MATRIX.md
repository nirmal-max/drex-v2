# DREX-V2 Phase 22 — Master UI Action & State Transition Matrix
=============================================================

**Document Version**: 2.0.0  
**Phase**: Phase 22 — Investigator-First Forensic Workstation UX  
**Commit**: `f030382`  
**Date**: 2026-09-16  
**Status**: `AUTHORITATIVE / EMPIRICALLY VERIFIED`

---

## 1. Scope & Purpose

This document provides a comprehensive, component-by-component action matrix mapping every user interaction in the DREX-V2 Forensic Workstation to:
1. **Immediate Visual Feedback** (<16ms response latency, button loading states, active focus styling).
2. **State Transition & Locking** (pre-execution checks, drive locks, mutex acquisition).
3. **Authoritative Backend Contract** (FastAPI route, payload schema, response model).
4. **Error & Cancellation State** (fail-closed tripwires, cooperative cancellation tokens).
5. **Forensic Integrity Assurance** (SHA-256 audit chaining, tamper-evident certificate generation).

---

## 2. Global Application Shell Actions

| UI Component | User Action | Immediate Visual Feedback (<16ms) | State Transition & Locking | Backend API Contract | Error / Abort State | Forensic Integrity Assurance |
|---|---|---|---|---|---|---|
| **Topbar Persona Dropdown** (`#personaSelect`) | Select persona (`ADMIN`, `FORENSIC_ANALYST`, `INVESTIGATOR`, etc.) | Dropdown value updates; persona badge color shifts to role theme | `STATE.currentRole` updated; views refresh with RBAC-filtered actions | `POST /api/auth/switch-persona` (`role`, `username`) | Fallback to prior role with error toast if unauthorized | Role change recorded in SHA-256 audit ledger |
| **Topbar Active Ops Button** (`#activeOpsBtn`) | Click active operations counter pill | Active view switches to `active_operations`; nav item highlights | View state updates to `active_operations` | `GET /api/jobs/active` (`case_id`) | Empty card rendered if network offline | Live operation counter tied strictly to active server jobs |
| **Sidebar Navigation Items** (`#mainNav .nav-item`) | Click any of the 26 view buttons | Active class shifts; focus ring activates; target view content renders | `STATE.currentView` updates; URL hash reflects view ID | View-specific endpoint (`GET /api/*`) | Error banner rendered with retry button on API failure | Zero placeholder pages; every view mapped to authoritative renderer |
| **Active Case Selector** (`#activeCaseSelect`) | Select case from dropdown | Topbar updates case ID and name; context bar refreshes | `STATE.activeCase` bound; candidate pools filtered to active case | `GET /api/cases/{case_id}` | Reverts to `null` if case does not exist | Strict case isolation; cross-case candidate pollution prohibited |
| **System Refresh Button** (`#refreshBtn`) | Click reload button | Spin animation on refresh icon (<16ms) | Re-queries cases, devices, audit events, certificates | `GET /api/system/version`, `GET /api/cases`, etc. | Displays red toast if server unreachable | Real commit hash dynamically updated in `#workstationBuildTag` |

---

## 3. Core Forensic Workflow Actions

### 3.1 File & Folder Eraser (`file_eraser`)

| UI Action | Immediate Visual Feedback | State Transition & Locking | Backend API Contract | Error / Abort State | Forensic Assurance |
|---|---|---|---|---|---|
| **Browse / Enter Target Path** | Path text input updates; input validated for path traversal strings | Target path set in `STATE.selectedFilePath` | Client-side validation only | Invalid path turns input border red with warning text | Prevents path injection / traversal attacks |
| **Select Sanitization Method** | Method card selection highlight; pass count and standard displayed | `STATE.selectedFileMethod` updated to method ID | Client-side selection | Inapplicable methods disabled based on media type | Bound to 25 certified forensic algorithms |
| **Type Confirmation Phrase** | Keyup listener validates phrase `DESTROY <target>` | Execute button enables once phrase matches exactly | Pre-execution lock held on target path | Button remains disabled if string mismatch | TOCTOU pre-execution safety gate |
| **Click [Execute Sanitization]** | Button switches to loading state; live operation card inserted | Transition: `QUEUED` $\rightarrow$ `RUNNING` (`phase="WRITING"`); target locked | `POST /api/sanitization/execute` (`target`, `method_id`, `case_id`) | Displays error card with trace if disk locked or unprivileged | Monotonic byte counters start at `0.01%` after first buffer write |
| **Click [Cancel Operation]** | Confirmation modal prompts examiner; status pill shifts to `CANCELLING` | Transition: `RUNNING` $\rightarrow$ `CANCELLING` $\rightarrow$ `CANCELLED` | `POST /api/jobs/{job_id}/cancel` | Job stops cleanly; file buffers flushed; target unlocked | No false PASS certificates; partial bytes logged to audit ledger |

### 3.2 Drive Eraser (`drive_eraser`)

| UI Action | Immediate Visual Feedback | State Transition & Locking | Backend API Contract | Error / Abort State | Forensic Assurance |
|---|---|---|---|---|---|
| **Select Target Physical Drive** | Drive card highlights; partition layout, bus type, and size shown | Target device selected; system disk tripwire inspected | `GET /api/devices` | If system disk, `🔒 SYSTEM DISK PROTECTED` badge shown; inputs disabled | OS drive fail-closed lock prevents destructive execution |
| **Enter Confirmation Phrase** | Exact drive path `PhysicalDriveN` required in uppercase | Pre-execution lock active | Client-side safety validator | Execute button locked until string is 100% identical | Prevents accidental target misidentification |
| **Dispatch Physical Wipe** | View transitions to `active_operations`; live card displays ATA/NVMe pass | State: `QUEUED` $\rightarrow$ `RUNNING` $\rightarrow$ `VERIFYING` $\rightarrow$ `SEALING` | `POST /api/sanitization/execute` | Immediate rollback with hardware error if handle unavailable | Readback verification and Shannon entropy proof generated |

### 3.3 Forensic Filesystem Recovery (`recovery`)

| UI Action | Immediate Visual Feedback | State Transition & Locking | Backend API Contract | Error / Abort State | Forensic Assurance |
|---|---|---|---|---|---|
| **Select Source Disk Image** | Image metadata card displays filesystem type, size, sector geometry | Source device set in `STATE.recoverySource` | `GET /api/devices` | Unknown filesystem flagged with carver recommendation | Read-only handle acquisition; target media write-protected |
| **Configure Scan Depth** | Radio selector toggles Quick / Inode / Differential / Deep Carve | Scan configuration registered in workflow context | Client-side validator | Deep carve warns of high I/O duration | Strictly deterministic execution profiles |
| **Click [Trigger Scan]** | Pipeline stepper advances: `SOURCE` $\rightarrow$ `PRECHECK` $\rightarrow$ `SCANNING` | State: `RUNNING`; candidates streamed in real-time | `POST /api/recovery/scan` (`device_path`, `case_id`) | Error state triggers graceful scan abort with partial results | Progress tied strictly to examined sectors; zero timer simulation |
| **Select Recovery Candidate** | Candidate preview modal renders hex stream, entropy, confidence score | Candidate locked for extraction | `GET /api/recovery/candidates/{id}` | Damaged candidate displays red warning banner | 5-factor confidence scoring breakdown displayed |
| **Click [Extract Candidate]** | Extraction progress modal shows stream hashing; SHA-256 computed | Extracted artifact sealed to evidence vault | `POST /api/recovery/extract` (`candidate_id`, `destination`) | Extraction fails closed if output directory read-only | Merkle audit leaf created with SHA-256 fingerprint |

### 3.4 Out-of-Order Fragment Reconstruction (`fragments`)

| UI Action | Immediate Visual Feedback | State Transition & Locking | Backend API Contract | Error / Abort State | Forensic Assurance |
|---|---|---|---|---|---|
| **Select Image & Carve Candidates** | Candidate table displays disjoint extents, gaps, and confidence scores | Fragment pool locked for assembly | `GET /api/fragments/candidates` | Disjoint extents flagged with gap warning | Validates non-overlapping contiguous boundaries |
| **Run Reassembly Algorithm** | Visual fragment stitching graph renders; transition matrix computes | State: `ANALYZING` $\rightarrow$ `RECONSTRUCTED` | `POST /api/fragments/reconstruct` | Overlapping extents trigger `HTTP 422` validation rejection | Cryptographic validation of reconstructed file headers and footers |

### 3.5 Tamper-Evident Certificates (`certificates`)

| UI Action | Immediate Visual Feedback | State Transition & Locking | Backend API Contract | Error / Abort State | Forensic Assurance |
|---|---|---|---|---|---|
| **View Certificate List** | Table renders Certificate ID, Method, Target, Examiner, Merkle Root | Filter applied by active case ID | `GET /api/certificates` (`case_id`) | Empty state card rendered if no certificates issued | Schema 2.0 cryptographic certificates only |
| **Click [Verify Certificate]** | Independent Verifier modal renders with 10-point compliance check | Verification engine re-calculates Merkle root and signatures | `POST /api/verifier/verify-certificate` (`cert_id`) | Red `TAMPER DETECTED` badge if any byte or hash mismatch | Zero self-attestation; verified by independent Schema 2.0 engine |
| **Click [Export PDF]** | Download starts; PDF generation spinner completes (<100ms) | File streamed to browser download manager | `GET /api/certificates/{cert_id}/pdf` | Displays download error toast if file missing from vault | Complies with NIST SP 800-88 Rev 1 attestation format |

---

## 4. Verification & Testing Dashboard Actions (`system_validation`)

| UI Action | Immediate Visual Feedback | State Transition & Locking | Backend API Contract | Error / Abort State | Forensic Assurance |
|---|---|---|---|---|---|
| **Navigate to System Validation** | Dashboard renders 979 collected test metrics, duration, commit hash | `STATE.validationData` fetched and cached | `GET /api/validation/test-results` | Fallback cards displayed if JSON artifact unavailable | Dynamic 979 test count; provenance badge matches execution |
| **Filter by Category** | Category pills toggle active styling; test table filters instantaneously | `_selectedValCategory` updated; page resets to 1 | In-memory client filtering | Displays "No tests found matching filter" if 0 matches | All 9 categories covered (Recovery, Sanitization, Core, etc.) |
| **Click [Reload Test Suite]** | Spinner animates on reload button; fresh metrics queried | Re-queries `/api/validation/test-results` | `GET /api/validation/test-results` | Error banner if server returns non-200 | Displays authentic `commit` and `provenance` strings |

---

## 5. Responsive Layout Adaptations

| Viewport Resolution | Layout State | Navigation Drawer | Grid Column Count | Action Matrix Adaptation |
|---|---|---|---|---|
| **1920x1080 (Full HD)** | Desktop 3-column workstation | Persistent expanded sidebar (240px) | 3 to 4 columns | Maximum density; simultaneous side-by-side inspection cards |
| **1440x900 (Widescreen Laptop)** | Desktop 2-column workstation | Persistent compact sidebar (210px) | 2 to 3 columns | Adjusted margin and padding tokens (`mt-12`, `gap-8`) |
| **1366x768 (Standard Laptop)** | Compact desktop workstation | Collapsible sidebar; drawer toggle | 1 to 2 columns | Single-column operation cards; horizontal scroll on hex view |
| **768x1024 (Tablet / Mobile)** | Touch-optimized single column | Fullscreen slide-over drawer | 1 column | Large tap targets (min 44px); sticky bottom action drawer |
