# DREX-V2 PHASE 2 ARCHITECTURE: CASE, EVIDENCE, TIMELINE & AUDIT

**Phase**: 2 / 12  
**Implementation Status**: `COMPLETED`  
**Test Coverage**: 322 / 322 Tests Passing (100%)  
**Module**: [`forensic_vault.py`](file:///d:/drex-v2-main/forensic_vault.py)  

---

## 1. Overview & Architectural Boundaries

Phase 2 establishes the cryptographic case management, evidence vault, forensic timeline, and hash-chained audit ledger foundation for DREX-V2. It bridges operational workflows (carving, fragment reconstruction, sanitization, and verification) with court-admissible chain of custody and tamper-evident audit records.

```
┌────────────────────────────────────────────────────────────────────────┐
│                        DREX-V2 APPLICATION LAYER                      │
│        (drex_app.py / ForensicCaseManager / CertificateManager)        │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
       ┌────────────────────────────┼────────────────────────────┐
       ▼                            ▼                            ▼
┌───────────────┐          ┌─────────────────┐          ┌──────────────────┐
│ Case Manager  │          │ Evidence Vault  │          │   Audit Engine   │
│ (ForensicCase)│          │ (EvidenceSource)│          │ (AuditChain/Ver.)│
└──────┬────────┘          └────────┬────────┘          └────────┬─────────┘
       │                            │                            │
       ├────────────────────────────┼────────────────────────────┤
       ▼                            ▼                            ▼
┌───────────────┐          ┌─────────────────┐          ┌──────────────────┐
│   Timeline    │          │Chain of Custody │          │ Package Manager  │
│ (Chronological│          │(Custodian/Action│          │ (Atomic Export & │
│ Typed Events) │          │ Pre/Post Hash)  │          │ Manifest Import) │
└───────────────┘          └─────────────────┘          └──────────────────┘
```

---

## 2. Core Subsystems

### A. Case Management (`ForensicCase` & `ForensicCaseManager`)
- **Identification**: Deterministic unique identifier `CASE-YYYYMMDD-HEX8` (e.g. `CASE-20260914-A1B2C3D4`).
- **Status Lifecycle**: `OPEN` -> `ACTIVE` -> `PAUSED` -> `CLOSED` -> `ARCHIVED`.
- **Examiner Attribution**: Tracks lead investigator, organization, classification, tags, and timestamps.
- **Persistence**: Crash-safe atomic JSON writes with `.tmp` staging, `flush`, `fsync`, and `os.replace`.

### B. Evidence Source & Categorized Vault (`EvidenceVault`)
- **Typed Sources**: Physical device, partition, filesystem, disk image, forensic image, file, folder, recovered artifact, synthetic validation fixture.
- **Categorized Directory Structure**:
  - `cases/<case_id>/source/`: Original seized disk images and source files.
  - `cases/<case_id>/derived/`: Transformed images, sector maps, bad block logs.
  - `cases/<case_id>/recovered/`: Extracted files, validated carves, reassembled fragments.
  - `cases/<case_id>/reports/`: Forensic reports, executive summaries, validation logs.
  - `cases/<case_id>/certificates/`: ECDSA P-256 / SHA-256 signed erasure/recovery certificates.
  - `cases/<case_id>/audit/`: Hash-chained audit ledgers (`audit_chain.json`).

### C. Streaming Cryptographic Hasher (`StreamingHasher`)
- Memory-bounded chunked computation (default 64 KB buffers) supporting SHA-256 and SHA-512.
- Handles multi-gigabyte disk images without unbounded memory allocation.
- Returns typed `HashRecord` with exact byte counts and timestamps.

### D. Hash-Chained Audit Ledger & Independent Verifier
- **Chaining Invariant**: $H_i = \text{SHA256}(H_{i-1} \parallel \text{canonical}(P_i))$, initialized with Genesis hash `"0"*64`.
- **Deterministic Serialization**: Canonical sort-keyed JSON bytes without whitespace.
- **Independent Audit Verifier (`IndependentAuditVerifier`)**: Inspects persisted audit chains independently of in-memory state. Detects payload tampering, sequence gaps, event insertions, deletions, or reordering.

### E. Chain of Custody (`ChainOfCustody`)
- Append-only immutable log tracking evidence transfer, access, analysis, sealing, and release.
- Pre-action and post-action SHA-256 digests.

### F. Case Package Export / Import (`CasePackageManager`)
- Atomic export into compressed `.tar.gz` archive with self-describing `manifest.json`.
- Strict path-traversal safety defense on import (intercepts `../`, absolute paths, drive letters, and symlinks).
- Full manifest hash recomputation and audit chain validation prior to accepting imported cases.
