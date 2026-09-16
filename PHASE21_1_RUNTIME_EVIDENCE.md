# DREX V2 — Phase 21.1 Runtime Evidence & Forensic Proof

## 1. System Version & Build Truth
- **Endpoint**: `GET /api/system/version`
- **Output**:
  ```json
  {
    "build_id": "fbad09d",
    "commit": "fbad09d",
    "asset_version": "fbad09d",
    "version": "2.0.0",
    "server_timestamp": "2026-09-16T06:07:34.530676+00:00",
    "environment": "Windows 11 (AMD64)"
  }
  ```

## 2. Test Validation Dashboard Data
- **Endpoint**: `GET /api/validation/test-results`
- **Collected Tests**: 977
- **Passed Tests**: 977
- **Failed Tests**: 0
- **Category Breakdown**:
  - `Core Engines & Security`: 273
  - `Sanitization & Erasure`: 162
  - `Forensic Recovery`: 189
  - `Evidence Vault & Audit`: 148
  - `Hardware Storage`: 74
  - `UI & Multi-Surface`: 62
  - `Performance Benchmarks`: 28
  - `Integration & Pipeline`: 24
  - `Phase 21 Runtime Truth`: 17
  - **Sum of Categories**: 977 ($= \text{Total Collected}$)

## 3. Operational Judge Demonstration Execution
- **Endpoint**: `POST /api/demo/operational-flow`
- **Execution Output**:
  ```json
  {
    "status": "SUCCESS",
    "verdict": "PASS",
    "case_number": "OP-DEMO-20260916-4EC2",
    "entropy_h": 7.9969,
    "certificate_id": "CERT-DREX-D0793CF920CA",
    "environment": "LIVE ISOLATED WORKSTATION",
    "steps_completed": 5
  }
  ```

## 4. PDF Attestation Certificate Download
- **Endpoint**: `GET /api/certificates/{id}/pdf?case_id={case_id}`
- **Verification**: Streams valid binary starting with `%PDF-1.4` (3601 bytes).

## 5. TOCTOU Attack Defense
- **Endpoint**: `POST /api/sanitization/execute`
- **Attack Vector**: Modified payload hash between preflight inspection and execution.
- **Defense Result**: `409 Conflict` — `TOCTOU VIOLATION: Target file was modified after preflight inspection. Operation aborted for evidence protection.`
