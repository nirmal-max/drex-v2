# DREX Forensic Workstation UX 2.0 &middot; UI Component Inventory

**Document Reference:** `PHASE19_UI_INVENTORY.md`  
**Phase:** Phase 19 &mdash; Forensic Workstation UX 2.0 (100&times; UI/UX Optimization)  
**Classification:** Forensics & Defense Workstation Design  
**Standards:** ISO/IEC 27037:2012, NIST SP 800-88 Rev. 2, NIST SP 800-86  

---

## 1. Executive Summary

This inventory catalogs the complete set of user interface components, views, context controllers, drawers, and modal state machines built into the **DREX Forensic Workstation UX 2.0**. All components strictly adhere to authentic truth states, zero data fabrication, clear provenance boundaries, and defensive UX guardrails.

---

## 2. Global Shell & Navigation Architecture

### 2.1 Navigation Structure (`webui/index.html`, `webui/styles.css`, `webui/app.js`)

| Navigation Group | Views Contained | Purpose & Investigator Value |
|:---|:---|:---|
| **WORKSPACE** | `overview`, `cases`, `vault` | Active case context, high-level operational metrics, immutable object registry |
| **INVESTIGATE** | `recovery`, `carving`, `fragments`, `damaged_media`, `hex_inspector` | Live file & inode recovery, raw sector carving, out-of-order reassembly, byte-stream analysis |
| **SANITIZE** | `sanitization_planner`, `drive_eraser`, `file_eraser`, `residue_analyzer` | NIST SP 800-88 policy planning, privileged physical erasure, CSPRNG file shredding, slack scrubber |
| **VERIFY** | `verifier`, `verification`, `validation_lab`, `performance_lab` | Independent Schema 2.0 verifier, 64-sector Shannon entropy visualizer, KAT test suites, memory profiling |
| **REPORT** | `certificates`, `reports`, `audit` | Tamper-evident PDF certificates, case chain-of-custody dossiers, SHA-256 Merkle audit ledger |
| **SYSTEM** | `methods`, `device_intelligence`, `device_manager`, `backend_manager`, `diagnostics`, `settings` | Canonical 25-method matrix, IOCTL hardware intelligence, physical storage manager, backend registry, diagnostics |

---

## 3. Global Context & Drawer System

### 3.1 Topbar Active Case Switcher Bar (`.case-switcher-bar`)
- **Visual Location:** Pinned below the workstation header.
- **Components:**
  - Active Case Badge (`.case-active-tag`): Shows `Active Case: DREX-2026-001` or `No Case Selected`.
  - Organization Badge: Displays unit context (`NTRO Forensic Lab`).
  - Active Mode Badge: Distinguishes operational vs evaluation mode.
  - Interactive Action Trigger: `[ Switch Active Case ]` button opening the Case Switcher Modal.

### 3.2 Operation Context Bar (`.operation-context-bar`)
- **Visual Location:** Injected at the top of every operational view (`recovery`, `carving`, `sanitization_planner`, `drive_eraser`, `file_eraser`, `vault`, `audit`, `certificates`, etc.).
- **5-Tuple Global Binding:**
  1. `CASE`: Active Case Number and short title.
  2. `SOURCE`: Selected physical drive (`\\.\PhysicalDrive1`), disk image (`triage.img`), or test stream.
  3. `WORKFLOW`: Current operational pipeline (`FORENSIC RECOVERY`, `RAW CARVING`, `FILE SHREDDER`, etc.).
  4. `METHOD`: Canonical method designation (e.g. `[M17] Quick Recovery`, `[M08] CSPRNG Random Overwrite`).
  5. `STATUS`: Operational status badge (`READY`, `RUNNING`, `PASS`, `BLOCKED`, `SEALED`).

### 3.3 Forensic Slide-Out Details Drawer (`#drawerOverlay`, `#drawerBox`)
- **Behavior:** Slides smoothly from the right viewport margin (540px width, max 92vw).
- **Triggers:**
  - Case Dossier (`openCaseDetailsDrawer(caseId)`)
  - Evidence Vault Object (`openEvidenceDetailsDrawer(evidenceId)`)
  - Discovered Candidate (`openCandidateDetailsDrawer(candidateId)`)
  - Audit Ledger Event (`openAuditDetailsDrawer(eventId)`)
  - Forensic Certificate (`openCertificateDetailsDrawer(certId)`)

---

## 4. Provenance & Classification System

The UI enforces strict three-way badge differentiation across all views:

| Badge Type | CSS Class | Label | Usage Rule |
|:---|:---|:---|:---|
| **Operational** | `badge-operational` | `🔍 OPERATIONAL` / `🔍 CASE EVIDENCE` | Live investigation data, real disk images, authentic case records |
| **Evaluation** | `badge-evaluation` | `🎯 EVALUATION` / `🎯 EVAL ARTIFACT` | Closed-loop judge demonstration flow (`< 60s`), deterministic demo archives |
| **Test Fixture** | `badge-test-fixture` | `🧪 TEST FIXTURE` / `🧪 SAMPLE DATA` | Synthetic test disk images (`sample_disk.img`), unit test artifacts, mock byte streams |

---

## 5. View-by-View Component Matrix

| View ID | Primary UI Components | Guardrails & Safety Controls |
|:---|:---|:---|
| `overview` | Active case hero, 4 primary metric cards, operational launchers, secondary evaluation card | Evaluation loop demoted from hero to secondary inspection card |
| `cases` | Segmented filter control (`[ 🔍 Operational ] [ 🎯 Evaluation ] [ 🧪 Test ] [ All ]`), search input, grid cards | Operational filter selected by default, preventing test case confusion |
| `vault` | 8-column data table, provenance tags, immutable SHA-256 digests, action buttons, drawer | Actionable empty state with `[ Launch Recovery Scan ]` when empty |
| `recovery` | 6-step workflow stepper, target selector, method selector, detected source details card, candidate table | Source change detection alert unlinks stale candidate tables |
| `carving` | Target selector, signature profile picker, sector alignment (512B/4096B), candidate table | Explicit `🧪 TEST FIXTURE` badge when sample disk is selected |
| `fragments` | Preset selector (PNG/JPEG/PDF), input chunk cards with header/quantization/footer extents, seam slider | Visualizes discontinuities and validates 5-factor reassembly formula |
| `damaged_media` | Hardware requirement alert, 3-phase readback diagram (Copying, Trimming, Scraping) | Truthful capability disclosure: Win32 userspace pass-through blocked |
| `hex_inspector` | Preset selector (`🧪 SAMPLE DATA`), native file picker, Shannon entropy gauge, hex dump | Real-time byte reading, dynamic Shannon entropy calculation |
| `sanitization_planner` | Media tech detector, security objective selector (Clear/Purge/Destroy), plan status card | Plan status: `PLAN STATUS: READY`; Execution: `NOT STARTED` |
| `drive_eraser` | Physical drive cards, OS boot extent tripwire badges, privileged execution CTA | System disks permanently locked (`🔒 SYSTEM DISK PROTECTED`) |
| `file_eraser` | Target type toggle (File/Folder), native file/folder picker, selected target metadata card, preflight badge | Dynamic phrase generator: `ERASE-<PATH>-PERMANENT` |
| `residue_analyzer` | Slack tip scrubber card, free-space wiper card, temp cache purge card, 64-sector block grid | Visual representation of unallocated vs wiped slack blocks |
| `verifier` | Operational evidence archive browser, evaluation demo runner, exit code verification card | Independent offline execution without server dependency |
| `audit` | Human-readable event table, sequence numbers, SHA-256 digests, details drawer with raw JSON | Cryptographic verification modal re-evaluates Merkle roots |
| `certificates` | Issued certificate table, method badges, SHA-256 hashes, PDF download link, drawer | Instant cryptographic re-verification against audit chain |
