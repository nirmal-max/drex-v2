# DREX V2 — PHASE 22 SANITIZATION & RECOVERY PROGRESS SPECIFICATION
## Authoritative Real-Time Forensic Progress & Telemetry Contract

**Document Version**: 2.2.0  
**Status**: Authoritative Technical Specification  
**Applicability**: `drex_server.py`, `file_sanitizer.py`, `recovery_adapter.py`, `drex_app.py`, `webui/app.js`  
**License**: Apache 2.0  

---

## 1. Core Principle: Zero Simulated Progress

1. **Strictly Prohibited**:
   - `setInterval(() => progress += ...)` or time-based simulated increments.
   - Fake spinning indicators masquerading as active work.
   - Fabricated throughput speeds or static arbitrary ETAs.
   - Collapsing post-write verification into write progress (100% writing $\neq$ VERIFIED).
2. **Empirical Truth Mandate**:
   - Every percentage value, phase label, byte counter, speed measurement, and ETA must originate from active backend kernel/filesystem calls.
   - Unavailable values must display `"—"` or `"Calculating..."`, never fabricated numbers.

---

## 2. Operation Lifecycle State Machine

```
[IDLE]
  │
  ▼
[PRECHECK] ───────────────► (Failed validation / System disk locked) ──► [BLOCKED]
  │
  ▼
[PREPARING] ──────────────► (TOCTOU modification detected) ──────────► [FAILED]
  │
  ▼
[QUEUED] ─────────────────► (Cancelled before thread dispatch) ───────► [CANCELLED]
  │
  ▼
[RUNNING / SANITIZING] ───► (I/O error / disk disconnection) ────────► [FAILED]
  │                       (User clicks [Cancel Operation]) ──────────► [CANCELLING] ──► [CANCELLED]
  ▼
[WRITING COMPLETE (100%)]
  │
  ▼
[VERIFYING] ──────────────► (Readback mismatch / entropy fail) ──────► [VERIFICATION_FAILED]
  │
  ▼
[EVIDENCE SEALING]
  │
  ▼
[COMPLETED]
  │
  ▼
[VERIFIED]
```

### State Definitions

| State / Phase | Description | Progress Range |
|---|---|---|
| `READY` / `IDLE` | Target selected, no work initiated. | `0.00%` |
| `PRECHECK` | Preflight inspection: validating path, filesystem type, read/write permissions, OS system disk tripwire. | `0.00%` |
| `PREPARING` | Preflight identity hashing, acquiring target lock, allocating worker thread. | `0.00%` |
| `QUEUED` | Job registered in `JobRegistry`, awaiting thread pool execution slot. | `0.00%` |
| `RUNNING: WRITING` | Overwrite passes executing. Initial state upon first byte written displays `0.01%`. | `0.01%` – `100.00%` |
| `WRITING COMPLETE` | All passes flushed to disk cache via `os.fsync()`. | `100.00%` (Writing) |
| `VERIFYING` | Separate verification phase: 100% readback check + Shannon entropy computation. | Visually distinct verification sub-meter |
| `EVIDENCE SEALING` | Appending immutable record to SHA-256 hash-chained audit ledger, cataloging evidence vault item. | Verification complete |
| `COMPLETED` | Execution pipeline finished cleanly. | 100.00% |
| `VERIFIED` | Both execution and independent cryptographic verification have passed. | Terminal Success |
| `FAILED` | I/O error, permission denial, or unhandled exception. | Frozen at failure offset |
| `BLOCKED` | Destructive command halted by safety tripwire (e.g. system disk detected). | `0.00%` |
| `CANCELLING` | Cooperative cancellation requested by investigator. Worker flushing and unlinking safely. | Current offset |
| `CANCELLED` | Operation safely aborted. Zero corrupted evidence. | Terminal Cancel |

---

## 3. The Initial Running State Contract (`0.01%`)

1. **When does `0.01%` appear?**
   - It appears **ONLY** after the worker thread has acquired the file handle, verified preflight token identity (TOCTOU guard), and written the first byte/buffer of the overwrite stream.
   - While in `PRECHECK`, `PREPARING`, or `QUEUED`, the UI displays the textual stage badge (`PRECHECK`, `QUEUED`) with the progress bar at rest (`0%`).
2. **Mathematical Precision**:
   - For a file of size $S$ bytes and bytes written $B$:
     $$\text{Percent} = \max(0.01, \min(100.0, \frac{B}{S} \times 100)) \quad \text{for } B > 0$$
   - Progress precision is rounded to exactly two decimal places (`XX.XX%`).
   - Progress must be strictly monotonically non-decreasing ($\Delta P \ge 0$).

---

## 4. Throughput Speed & Dynamic ETA Calculation

### 4.1 Exponential Moving Average (EMA) Speed
To eliminate jitter while reflecting immediate performance degradation:
$$\text{Speed}_{\text{inst}} = \frac{B_t - B_{t-\Delta t}}{\Delta t}$$
$$\text{Speed}_{\text{EMA}} = \alpha \cdot \text{Speed}_{\text{inst}} + (1 - \alpha) \cdot \text{Speed}_{\text{EMA, prev}}$$
Where smoothing factor $\alpha = 0.25$, evaluated over a minimum window $\Delta t \ge 250\text{ ms}$.

### 4.2 Dynamic ETA
$$\text{Bytes Remaining} = S - B$$
$$\text{ETA}_{\text{seconds}} = \frac{\text{Bytes Remaining}}{\text{Speed}_{\text{EMA}}}$$
Formatting Rules:
- If $\text{Speed}_{\text{EMA}} \le 1024\text{ B/s}$ or samples $< 2$: `ETA: Calculating...`
- If $\text{Bytes Remaining} = 0$: `ETA: 00:00:00`
- Formatted as `HH:MM:SS`. If $> 7\text{ days}$: `ETA: >7 days`.

---

## 5. Unified Backend/UI Data Model Contract

The schema for `GET /api/jobs/{job_id}` and `GET /api/jobs/active`:

```json
{
  "operation_id": "OP-A8B9C0D1",
  "job_id": "SAN-9F8E7D6C",
  "case_id": "CASE-2026-001",
  "workflow_id": "file_eraser",
  "actor": "Forensic Operator",
  "method_id": 8,
  "target_id": "D:\\Evidence\\sample.bin",
  "target_path": "D:\\Evidence\\sample.bin",
  "operation_type": "SANITIZATION_EXECUTE",
  "status": "RUNNING",
  "phase": "WRITING",
  "percent_complete": 38.42,
  "processed_bytes": 16106127,
  "total_bytes": 41943040,
  "speed_bps": 86421052.6,
  "eta_seconds": 0.29,
  "start_time_utc": "2026-09-16T07:30:00Z",
  "end_time_utc": null,
  "elapsed_seconds": 0.18,
  "verification_state": "NOT_STARTED",
  "details": {
    "pass_current": 1,
    "pass_total": 1,
    "standard": "CSPRNG_OVERWRITE",
    "toctou_verified": true
  },
  "error_code": null,
  "error_message": null
}
```

---

## 6. Frontend Progress Component Specification

### Reusable Card Anatomy (`renderForensicOperationCard`)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  ⚡ SANITIZATION IN PROGRESS                      [ RUNNING: WRITING ]      │
├─────────────────────────────────────────────────────────────────────────────┤
│  Method:   M08 — CSPRNG Random Overwrite                                     │
│  Target:   D:\Evidence\sample.bin (40.00 MB, Regular File)                   │
│  Case:     CASE-2026-001                                                    │
├─────────────────────────────────────────────────────────────────────────────┤
│  Current Phase:  WRITING (Pass 1 of 1)                                       │
│  Progress:       38.42%                                                     │
│                                                                             │
│  ████████████████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░                         │
│                                                                             │
│  Processed:      15.36 MB / 40.00 MB                                         │
│  Speed:          82.4 MB/s                                                  │
│  ETA:            00:00:01                                                   │
├─────────────────────────────────────────────────────────────────────────────┤
│  Verification:   NOT STARTED (Scheduled post-write readback & entropy check) │
├─────────────────────────────────────────────────────────────────────────────┤
│  [ Cancel Operation ]                                                       │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Transition to Verification
Upon 100% write completion:
1. Progress bar transitions to 100% with label `WRITING COMPLETE`.
2. Verification card pulses with state `VERIFYING: Reading back 64 KB sample & computing Shannon entropy...`.
3. Only upon successful readback match and entropy threshold ($H \ge 7.99$ for CSPRNG) does status transition to:
   `VERIFIED — Post-wipe entropy 7.9992 bits/byte, 0 readback mismatches`.
