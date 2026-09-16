# DREX V2 — PHASE 22 OPERATION STATE MACHINE
## Formal Operation Lifecycle, Transition Invariants, & Telemetry Contract

**Document Version**: 2.2.0  
**Status**: Authoritative Architectural Standard  
**Applicability**: `drex_server.py`, `drex_api_models.py`, `webui/app.js`, `drex_app.py`  
**License**: Apache 2.0  
**Gate Status**: `GATE 2 VERIFIED`  

---

## 1. Formal State Lifecycle

Every long-running operation within DREX V2 (Sanitization, Forensic Recovery, Deep Carving, Fragment Reconstruction, and Media Verification) follows a strict deterministic state lifecycle managed by `JobRegistry`.

```
                    ┌──────────────┐
                    │   CREATED    │
                    └──────┬───────┘
                           │
                           ▼
                    ┌──────────────┐
                    │   PRECHECK   │──► (Validation failure / OS system lock) ──► [BLOCKED]
                    └──────┬───────┘
                           │
                           ▼
                    ┌──────────────┐
                    │  PREPARING   │──► (TOCTOU modification detected) ─────────► [FAILED]
                    └──────┬───────┘
                           │
                           ▼
                    ┌──────────────┐
                    │    QUEUED    │──► (Cancelled while awaiting worker slot) ──► [CANCELLED]
                    └──────┬───────┘
                           │
                           ▼
                    ┌──────────────┐
                    │   RUNNING    │──► (I/O error / device detachment) ───────► [FAILED]
                    └──────┬───────┘    (User requests cancellation) ────────────► [CANCELLING]
                           │                                                            │
                           │                                                            ▼
                           │                                                       [CANCELLED]
                           ▼
                 ┌───────────────────┐
                 │ WRITING COMPLETE  │  (100% written, synced via os.fsync)
                 └─────────┬─────────┘
                           │
                           ▼
                 ┌───────────────────┐
                 │    VERIFYING      │──► (Readback mismatch / entropy anomaly) ─► [VERIFICATION_FAILED]
                 └─────────┬─────────┘
                           │
                           ▼
                 ┌───────────────────┐
                 │ EVIDENCE SEALING  │
                 └─────────┬─────────┘
                           │
                           ▼
                 ┌───────────────────┐
                 │    COMPLETED      │
                 └─────────┬─────────┘
                           │
                           ▼
                 ┌───────────────────┐
                 │     VERIFIED      │
                 └───────────────────┘
```

---

## 2. Legal Transitions & Terminal Immutability

### 2.1 State Transition Matrix

| Current State | Permitted Next States | Guard Conditions |
|---|---|---|
| `QUEUED` | `RUNNING`, `CANCELLED`, `INTERRUPTED`, `FAILED` | Worker thread allocated; target lock retained. |
| `RUNNING` | `COMPLETED`, `FAILED`, `CANCELLING`, `CANCELLED`, `DEVICE_DISCONNECTED`, `VERIFICATION_FAILED`, `INTERRUPTED` | Cooperative token polled during loop; exceptions caught. |
| `CANCELLING` | `CANCELLED`, `FAILED`, `DEVICE_DISCONNECTED` | Partial buffers flushed; target left in safe unverified state. |
| `COMPLETED` | *None (Terminal)* | Terminal state immutability enforced. |
| `FAILED` | *None (Terminal)* | Diagnostic error code and message sealed in ledger. |
| `CANCELLED` | *None (Terminal)* | Cancellation reason recorded; zero false certificates issued. |
| `BLOCKED` | *None (Terminal)* | Protected target tripwire triggered; 0 bytes written. |
| `VERIFICATION_FAILED` | *None (Terminal)* | Post-write readback mismatch or low entropy threshold. |

### 2.2 Terminal State Immutability
Once a job enters a terminal state (`COMPLETED`, `FAILED`, `CANCELLED`, `INTERRUPTED`, `BLOCKED`, `VERIFICATION_FAILED`), calling `update_job` with a different state raises `ValueError`. Re-running requires a new deterministic operation ID.

---

## 3. Sub-Phase Hierarchy & Presentation Rules

| Phase Name | Progress Percent Floor | Verification State | Description |
|---|---|---|---|
| `PRECHECK` | `0.00%` | `NOT_STARTED` | Validating path syntax, filesystem type, read/write locks, and system volume safety. |
| `PREPARING` | `0.00%` | `NOT_STARTED` | Calculating preflight SHA-256 identity hash for TOCTOU protection. |
| `QUEUED` | `0.00%` | `NOT_STARTED` | Job recorded on disk; awaiting execution thread. |
| `WRITING` | `0.01%` (Positive Floor) | `NOT_STARTED` | Active kernel overwrite passes executing. Displays real mathematical progress. |
| `WRITING_COMPLETE` | `100.00%` | `IN_PROGRESS` | All bytes flushed to non-volatile media. Writing meter concludes. |
| `VERIFYING` | `100.00%` | `IN_PROGRESS` | Reading back 64 KB sector sample and computing Shannon entropy $H$. |
| `SEALING` | `100.00%` | `VERIFIED` | Appending immutable audit record to SHA-256 chain and registering in case vault. |
| `COMPLETED` | `100.00%` | `VERIFIED` | Operation closed with full provenance. Certificate available for issuance. |

---

## 4. Authoritative Telemetry Attributes (`models.JobStatusRecord`)

```json
{
  "operation_id": "OP-7B4F92A1",
  "job_id": "SAN-6E2A10F3",
  "case_id": "CASE-2026-001",
  "workflow_id": "file_eraser",
  "evidence_id": null,
  "actor": "Forensic Operator",
  "method_id": 8,
  "target_id": "D:\\Evidence\\disk_sample.bin",
  "target_path": "D:\\Evidence\\disk_sample.bin",
  "operation_type": "SANITIZATION_EXECUTE",
  "status": "RUNNING",
  "phase": "WRITING",
  "percent_complete": 42.15,
  "processed_bytes": 17678336,
  "total_bytes": 41943040,
  "processed_units": 17678336,
  "total_units": 41943040,
  "unit_type": "BYTES",
  "speed_bps": 85124000.0,
  "eta_seconds": 0.28,
  "verification_state": "NOT_STARTED",
  "cancellation_supported": true,
  "cancellation_requested": false,
  "started_at": "2026-09-16T07:45:00.123456Z",
  "updated_at": "2026-09-16T07:45:00.325120Z",
  "completed_at": null,
  "start_time_utc": "2026-09-16T07:45:00.123456Z",
  "end_time_utc": null,
  "elapsed_seconds": 0.20,
  "details": {
    "pass_current": 1,
    "pass_total": 1,
    "standard": "CSPRNG_OVERWRITE"
  },
  "error_code": null,
  "error_message": null
}
```

---

## 5. Active Operations Query API

### `GET /api/jobs/active`
- **Query Parameters**: `case_id` (optional string).
- **Authentication**: Requires `jobs:read` permission.
- **Behavior**: Returns an array of `JobStatusRecord` objects whose status is currently `QUEUED`, `RUNNING`, `CANCELLING`, `PRECHECK`, or `PREPARING`.
- **Case Isolation**: If `case_id` is supplied, strictly filters out any jobs belonging to other cases.
