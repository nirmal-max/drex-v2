# DREX V2 — CASE BINDING & CONTEXT ISOLATION FINAL AUDIT
============================================================
**Authoritative Forensic Case Boundary, Multi-Tenant Isolation, & Endpoint Audit**

- **Project**: DREX V2 — Integrated Secure Data Erasure & Advanced File Recovery Tool
- **SIH Problem Statement**: SIH26149 / PS149
- **Release Lineage**: `f030382` (Historical Baseline) $\to$ `3fbf60c` (Historical Implementation) $\to$ `0dc8207` (Current Release Head)
- **Audit Date**: 2026-09-16
- **Release Authority**: Forensic Compliance & Integrity Assurance Directorate
- **Status**: EMPIRICALLY VERIFIED — ZERO SILENT SELECTION OF ACTIVE CASES

---

## 1. Executive Forensic Policy Statement

In digital forensic science and legal admissibility standards (ISO/IEC 27037, NIST SP 800-86), **Case Context Binding** is an absolute, non-negotiable architectural boundary.
- An operation launched in the context of `CASE-A` must never record events, write artifacts, issue certificates, or modify ledgers belonging to `CASE-B`.
- **The Absolute Zero-Silent-Selection Invariant**: When an operation is submitted with an omitted or null `case_id`, the system **MUST NEVER silently select an active forensic case** (e.g., defaulting to `existing_cases[0]`).
- Any silent binding to an active forensic case risks cross-contamination of digital evidence, invalidating chain-of-custody, and causing severe legal failure in judicial proceedings.

---

## 2. Definitive Case-Binding Specification Across All Endpoints

The DREX V2 architecture implements strictly two acceptable behaviors for missing `case_id`:

1. **Destructive Operations & Recovery Workbenches** (`POST /api/sanitization/execute`, `POST /api/recovery/scan`):
   - **Explicit `case_id` provided**: Validated against `case_manager`. Empty/whitespace strings or non-existent IDs return `HTTP 400 Bad Request`. If valid, the operation is immutably bound to that specific case.
   - **Omitted `case_id` (`None`)**: Intentionally unassigned ad-hoc operation. The backend **allocates a fresh, isolated `DREX-TRIAGE-{uuid}` case** with its own sandboxed directory, audit chain, and evidence vault. Active cases (`CASE-A`, `CASE-B`) remain 100% pristine and untouched.
2. **Sensitive Forensic Disclosure & Retrieval Endpoints** (`GET /api/evidence`, `GET /api/certificates`, `GET /api/audit/ledger`, `GET /api/recovery/candidates`):
   - **Missing or null `case_id` MUST FAIL CLOSED**: The endpoint returns an empty list (`[]`). Zero artifacts, certificates, or audit records are disclosed without an explicit case scope.

### Endpoint-by-Endpoint Case Binding Census:

| Endpoint | Method | Forensic Domain | Case Binding Rule | Behavior on Missing `case_id` | Verdict |
|---|---|---|---|---|---|
| `/api/sanitization/execute` | `POST` | Destructive Sanitization | **Strict / Isolated Triage** | Allocates fresh isolated `DREX-TRIAGE-{uuid}` case. **NEVER** touches active cases. Empty string returns HTTP 400. | **VERIFIED** |
| `/api/sanitization/plan` | `POST` | Sanitization Preflight | Case-Aware | Evaluates device/file safety; no persistent case modification. | **VERIFIED** |
| `/api/recovery/scan` | `POST` | Forensic Recovery Scan | **Strict / Isolated Triage** | Allocates fresh isolated `DREX-TRIAGE-{uuid}` case. **NEVER** touches active cases. Empty string returns HTTP 400. | **VERIFIED** |
| `/api/recovery/candidates` | `GET` | Candidate Enumeration | **Fail Closed** | Missing `case_id` returns `[]`. Does not leak candidates across cases. | **VERIFIED** |
| `/api/recovery/reconstruct` | `POST` | Fragment Assembly | **Mandatory Explicit** | Requires valid `req.case_id`. Returns HTTP 404 if case does not exist. | **VERIFIED** |
| `/api/recovery/extract` | `POST` | Vault Ingestion | **Mandatory Explicit** | Ingests candidate strictly into specified case vault. | **VERIFIED** |
| `/api/evidence` | `GET` | Evidence Vault Listing | **Fail Closed** | Missing `case_id` (and `all_cases=False`) returns `[]`. | **VERIFIED** |
| `/api/evidence/export-bag` | `POST` | Evidence Bag Export | **Mandatory Explicit** | Requires valid `req.case_id`. Exports strictly bounded case archive. | **VERIFIED** |
| `/api/certificates` | `GET` | Certificate Ledger | **Fail Closed** | Missing `case_id` returns `[]`. Zero cross-case disclosure. | **VERIFIED** |
| `/api/certificates/{id}` | `GET` | Certificate Record | **Scoped Lookup** | Scoped to `case_id` when provided; exact `cert_id` lookup or 404. | **VERIFIED** |
| `/api/certificates/{id}/pdf` | `GET` | Certificate PDF | **Scoped Lookup** | Scoped to `case_id` when provided; exact `cert_id` lookup or 404. | **VERIFIED** |
| `/api/certificates/verify` | `POST` | Attestation Verify | **Mandatory Explicit** | Requires `req.case_id` and `req.certificate_id`. | **VERIFIED** |
| `/api/audit/ledger` | `GET` | Audit Chain Listing | **Fail Closed** | Missing `case_id` returns `[]`. Prevents ledger cross-read. | **VERIFIED** |
| `/api/audit/verify` | `POST` | Audit Chain Verification | **Fail Closed** | Missing `case_id` returns `ZERO RECORDS VERIFIED`. | **VERIFIED** |
| `/api/cases` | `GET`, `POST` | Case Administration | Top-Level Index | Authenticated role-based listing and creation of forensic cases. | **VERIFIED** |
| `/api/cases/{id}/timeline` | `GET` | Timeline Events | **Mandatory Explicit** | Path parameter `{case_id}` strictly required. Returns 404 if not found. | **VERIFIED** |

---

## 3. Elimination of the `existing_cases[0]` Anti-Pattern

In earlier baseline revisions, `launch_recovery_scan` and `execute_sanitization` contained an anti-pattern fallback:
```python
# ELIMINATED ANTI-PATTERN (PREVIOUS BASELINE):
existing_cases = case_manager.list_cases()
if existing_cases:
    target_case_id = existing_cases[0].case_id  # <-- DEFECT: SILENT BINDING TO ACTIVE CASE!
```

### Complete Eradication & Refactored Implementation:
The reachable fallback to `existing_cases[0]` has been completely purged from all operational routes:

```python
# CURRENT AUTHORITATIVE IMPLEMENTATION:
if req.case_id is not None:
    if not req.case_id.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing mandatory authoritative case_id. All forensic operations must explicitly bind to an active case.",
        )
    c = case_manager.get_case(req.case_id.strip())
    if not c:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid case ID: '{req.case_id}'. Case not found.",
        )
    target_case_id = req.case_id.strip()
else:
    # Intentionally unassigned ad-hoc operation: allocate fresh isolated triage case
    adhoc_case = case_manager.create_case(
        case_number=f"DREX-TRIAGE-{uuid.uuid4().hex[:6].upper()}",
        title="Ad-hoc Triage Operation",
        examiner=current_user.get("display_name", "Forensic Operator"),
        organization="DREX Triage Operations",
    )
    target_case_id = adhoc_case.case_id
```

---

## 4. Empirical Regression Proof

The invariant is continuously verified by `tests/test_phase22_p0_01_case_binding.py`:

```powershell
python -m pytest tests/test_phase22_p0_01_case_binding.py -v
```

### Verified Test Cases:
1. `test_p0_01_case_a_and_case_b_isolation`: Proves operations on `CASE-A` strictly bind to `CASE-A`; operations on `CASE-B` strictly bind to `CASE-B`; queries to `/api/jobs/active?case_id=CASE-A` return zero jobs from `CASE-B`.
2. `test_p0_01_backend_rejects_missing_or_invalid_case`: Proves invalid case IDs and empty strings return `HTTP 400 Bad Request`.
3. `test_p0_01_job_registry_invariant`: Proves `JobRegistry.register_job` raises `ValueError("CRITICAL INVARIANT VIOLATION")` if `case_id` is empty.
4. `test_p0_01_omitted_case_id_never_attaches_to_active_cases`: Creates active `CASE-A` and `CASE-B`. Dispatches recovery and sanitization with `case_id=None`. Empirically asserts that `job["case_id"]` is a freshly generated `DREX-TRIAGE-...` case, and neither `CASE-A` nor `CASE-B` are touched. Also asserts that `GET /api/evidence`, `GET /api/certificates`, and `GET /api/audit/ledger` return `[]` when `case_id` is omitted.

**Audit Status**: **PASSED — ZERO SILENT CASE SELECTION CONFIRMED**
