# DREX-V2 Phase 22 — UI/UX Implementation & Architectural Hardening Specification
================================================================================

**Document Version**: 2.0.0  
**Phase**: Phase 22 — Investigator-First Forensic Workstation UX  
**Release Target**: DREX-V2 Production Release  
**Commit**: `f030382`  
**Date**: 2026-09-16  
**Status**: `APPROVED / IMPLEMENTED / PRODUCTION-HARDENED`

---

## 1. Executive Summary

Phase 22 transforms DREX-V2 from an assembled suite of certified forensic backend tools into a unified, production-hardened forensic workstation. The primary engineering imperative of Phase 22 is **Runtime Truth, Investigator Ergonomics, and Zero-Simulated Telemetry**.

Every user action, progress percentage, phase transition, byte counter, throughput rate, and time-to-completion estimate displayed in the workstation interface derives directly and authoritatively from kernel I/O, low-level block devices, and filesystem drivers.

---

## 2. Core Architectural Pillars

### Pillar 1: Zero-Simulated Progress & Truthful Positive Floor
- **Elimination of Simulated Timers**: All `setInterval` and `setTimeout` loops previously simulating percentage advancements (e.g., `stages = [25, 50, 75, 90, 100]`) have been completely excised.
- **Truthful Positive Work Floor (`0.01%`)**: Pre-execution phases (`QUEUED`, `PRECHECK`, `PREPARING`) strictly report `0.0%`. Only when the low-level write or read loop processes its first measurable block of data (e.g., first 256 KB buffer) does progress advance to `0.01%` or higher.
- **Decoupled Verification**: The write phase advances from `0.01%` to `100.0%` under `phase="WRITING"`. Upon physical write completion, the operation transitions to a visually and semantically distinct `phase="VERIFYING"` (`verification_state="IN_PROGRESS"`), preventing premature success verdicts before cryptographic validation (Shannon entropy calculation, pattern readback verification).
- **Sealing Phase**: Cryptographic audit ledger logging and tamper-evident certificate issuance execute under `phase="SEALING"` before achieving terminal `phase="COMPLETED"`.

### Pillar 2: Unified Operation State Model & EMA Telemetry
- **Authoritative State Fields**: Every background operation registered in `JobRegistry` exposes:
  - `status`: Lifecycle state (`QUEUED`, `RUNNING`, `CANCELLING`, `CANCELLED`, `COMPLETED`, `FAILED`).
  - `phase`: Forensic sub-state (`PRECHECK`, `WRITING`, `VERIFYING`, `SEALING`, `COMPLETED`, `CANCELLED`, `FAILED`).
  - `processed_bytes`: Exact monotonic byte count processed by the active worker thread.
  - `total_bytes`: Total byte target (file size $\times$ pass count, or partition capacity).
  - `percent_complete`: Quantized percentage ($0.0 \rightarrow 0.01 \rightarrow 100.0$).
  - `speed_bps`: Exponential Moving Average ($\alpha = 0.25$) smoothed throughput in bytes per second.
  - `eta_seconds`: Dynamic remaining time estimate derived strictly from EMA speed and remaining bytes.
  - `verification_state`: `NOT_STARTED` $\rightarrow$ `IN_PROGRESS` $\rightarrow$ `VERIFIED` / `MISMATCH_DETECTED`.
- **EMA Speed Smoothing Formula**:
  $$\text{Speed}_{\text{instant}} = \frac{\Delta \text{bytes}}{\Delta t}$$
  $$\text{Speed}_{\text{EMA}} = \alpha \times \text{Speed}_{\text{instant}} + (1 - \alpha) \times \text{Speed}_{\text{prior}} \quad (\alpha = 0.25)$$
  $$\text{ETA} = \frac{\text{Bytes}_{\text{remaining}}}{\text{Speed}_{\text{EMA}}}$$

### Pillar 3: Cooperative Cancellation Semantics
- **Atomic Cancellation Tokens**: Each registered job instantiates a `threading.Event` cancellation token passed into backend workers (`FileSanitizer.wipe_file`, `FileSanitizer.wipe_directory_tree`, recovery scanners).
- **Non-Destructive Abort & Target Unlocking**:
  - The worker checks `cancel_token.is_set()` before every buffer write and between passes.
  - When set, buffers are flushed, file handles closed, target locks released from `_target_locks`, and the job transitions cleanly to `CANCELLED`.
  - Zero false certificates or fake PASS attestations are issued on cancelled jobs.
  - The SHA-256 audit ledger records the exact byte offset reached prior to cancellation.

### Pillar 4: Active Operations Center & Global Navigation
- **Top-Bar Indicator**: Displays dynamic active operations counter (`Active Ops (N)`) with pulse indicator when background tasks are running.
- **Dedicated View (`active_operations`)**: Provides multi-tab filtering:
  - `ALL`: Complete audit history of operations.
  - `RUNNING`: Active streaming operations with live cards, progress bars, throughput gauges, and cancel actions.
  - `QUEUED`: Operations awaiting resource or drive locks.
  - `COMPLETED`: Verified finished operations with links to certificates and audit logs.
  - `CANCELLED`: Audited aborted operations with partial byte counts.

### Pillar 5: Fail-Closed Destructive Operation Safety
- **System Disk Tripwire**: Physical drives containing boot or system partitions (e.g. `PhysicalDrive0` hosting `C:\`) are strictly locked against destructive operations.
- **Pre-execution TOCTOU Target Inspection**: Prior to executing any wipe or overwrite, the workstation performs dynamic device inspection (model, serial, bus type, partition table, volume mount points) and requires exact confirmation phrase input matching the target identifier.
- **Duplicate Function Shadowing Resolution**: Fixed defect `DEF-P22-003` where duplicate `submitSanitization` declarations in `webui/app.js` caused dispatch routing failures.

---

## 3. Implementation Component Map

| Subsystem / File | Component | Phase 22 Modifications |
|---|---|---|
| `drex_api_models.py` | `JobStatusRecord` | Added `phase`, `processed_bytes`, `total_bytes`, `speed_bps`, `eta_seconds`, `verification_state`. |
| `drex_api_models.py` | `TestResultsResponseModel` | Added `provenance` field for authentic test provenance attestation. |
| `drex_server.py` | `JobRegistry` | Added EMA speed calculation, dynamic ETA estimation, terminal state transition locks, target lock cleanup on cancel. |
| `drex_server.py` | `/api/jobs/active` | Added unified active operations endpoint with optional `case_id` filtering. |
| `drex_server.py` | `/api/sanitization/execute` | Rewrote to asynchronous worker dispatch with `0.01%` positive work floor and verification phase decoupling. |
| `file_sanitizer.py` | `FileSanitizer.wipe_file` | Added `progress_callback` and `cancel_token` support for fine-grained byte streaming and cooperative abort. |
| `file_sanitizer.py` | `FileSanitizer.wipe_directory_tree` | Added recursive byte tallying and cooperative cancellation across file hierarchies. |
| `webui/styles.css` | Forensic Design System | Added `.forensic-op-card`, `.forensic-progress-bar`, `.phase-pill`, `.tripwire-badge`, and responsive rules. |
| `webui/app.js` | `renderForensicOperationCard` | Standardized live operation card with phase pills, byte gauges, EMA speed, ETA, and cancellation triggers. |
| `webui/app.js` | `trackOperationJob` | Unified polling engine (350ms active polling, responsive callback dispatch). |
| `webui/app.js` | `executeFileShredder` | Replaced legacy synchronous blocking call with asynchronous job dispatch and live forensic card streaming. |
| `webui/app.js` | `triggerRecoveryScan` | Eliminated fake timer-based percentage steppers (`stages = [25, 50, ...]`); bound strictly to server candidate events. |
| `webui/app.js` | `submitSanitization` | Eliminated duplicate shadowing function on line 5385; unified routing to `/api/sanitization/execute`. |
| `webui/index.html` | Application Shell | Added dynamic `workstationBuildTag` container, Active Operations topbar button, and responsive viewport meta. |
| `scripts/generate_test_results.py` | Test Provenance | Implemented `PytestExecutionRecorderPlugin` with `--collect-only` dry run labeling and authentic execution recording. |

---

## 4. State Transition Verification Table

| Initial State | Event / Trigger | Intermediate Phase | Terminal Phase | Post-Condition Assertions |
|---|---|---|---|---|
| `UNINITIALIZED` | Worker dispatched | `QUEUED` / `PRECHECK` | `RUNNING` | Percent = `0.0%`, Target locked, Lock count +1 |
| `RUNNING` | First 256 KB written | `WRITING` | `WRITING` | Percent $\ge 0.01\%$, Monotonic byte counter active |
| `RUNNING` | Final write pass complete | `VERIFYING` | `VERIFYING` | Percent = `100.0%`, Entropy calculated, Readback verified |
| `RUNNING` | Verification passed | `SEALING` | `COMPLETED` | Certificate generated, Audit chained, Target unlocked |
| `RUNNING` | User clicks Cancel | `CANCELLING` | `CANCELLED` | I/O aborted, Target unlocked, Zero false PASS certificate |
| `RUNNING` | Device disconnection / I/O error | `ERROR` | `FAILED` | Error logged in ledger, Target unlocked, Failure status |

---

## 5. Architectural Invariants Enforced

1. **No Simulated Timers**: Grep for `setInterval` and `setTimeout` in UI logic verifies zero percentage increments.
2. **Case Isolation**: Case boundaries are strictly checked. No silent cross-case candidate or evidence leakage.
3. **Hardware Protection**: Win32 physical disk handle write operations on OS volumes fail closed before I/O dispatch.
4. **Authentic Provenance**: `pytest execution == JSON artifact == API == UI` (979 collected, 979 passed).
