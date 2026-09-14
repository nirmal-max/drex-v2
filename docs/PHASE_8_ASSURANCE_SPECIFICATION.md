# DREX-V2 — Phase 8 Assurance & Independent Verification Specification
## Architecture, Schema & Independent Verification Protocol

---

## 1. Scope & Objectives
DREX-V2 Phase 8 implements an **assurance, evidence packaging, and independent verification system**.

The system enables an external examiner or auditor who does not trust DREX's internal state to independently verify:
1. File digests and byte counts for all declared objects.
2. Cryptographically hash-linked audit chain continuity, sequence numbers, and full envelope digests.
3. Chain-of-custody integrity and synchronization with audit records.
4. Certificate SHA-256 integrity binding and referential cross-links.
5. Referential integrity between cases, operations, evidence items, and certificates.
6. Package completeness without missing or unexpected files.
7. Explicit distinction between software verification and physical qualification (`physical_execution = NOT_EXECUTED`, `physical_qualification = NOT_ESTABLISHED`).

---

## 2. Trust Model & Terminology
- **Integrity**: Mathematical guarantee of immutability provided by SHA-256 digests and linear hash chains.
- **Authenticity of Origin**: Requires asymmetric public-key cryptography and PKI. Phase 8 uses standard-library SHA-256 integrity binding and does not make unsupported identity claims.
- **Verification Verdict `PASS`**: Means that the package is complete, structural files conform to schema, all object hashes match, and audit/custody/certificate integrity chains recompute exactly. It does not imply creator real-world identity or physical destruction.
- **Strictly Prohibited Claims**:
  - Do NOT claim "ECDSA P-256 signed" or "digitally signed" when SHA-256 integrity binding is used.
  - Do NOT claim "Merkle tree" for the linear hash chain ($H_i = \text{SHA256}(H_{i-1} \parallel E_i)$).
  - Do NOT claim "NIST certified" or "tamper-proof".

---

## 3. Evidence Package Schema (Version 2.0)

### Directory Layout
```
evidence-package/
├── manifest.json              # Canonical JSON manifest describing all package objects
├── manifest.sha256            # Standalone SHA-256 root digest of manifest.json
├── README.txt                 # Package documentation and verifier instructions
├── case/                      # Case lifecycle metadata (case.json)
├── operations/                # Declared operations metadata (operations.json)
├── evidence/                  # Raw acquired evidence files and disk images
├── recovered/                 # Recovered files, carved candidates, reassembled fragments
├── sanitization/              # Sanitization run logs, entropy proofs, sector verification data
├── audit/                     # Cryptographically hash-linked audit ledger (audit_chain.json)
├── custody/                   # Chain of custody ledger (custody_ledger.json)
├── certificates/              # Structured JSON & PDF 1.4 forensic certificates
└── reports/                   # Human-readable summary verification and operation reports
```

### Manifest Format (`manifest.json`)
- Deterministic canonical JSON serialization with sorted keys and compact separators.
- Objects deterministically ordered by `relative_path` ascending.
- Schema version: `"2.0"`.

---

## 4. Standalone Independent Verifier (`drex_verify.py`)

### Architectural Isolation Guarantee
`drex_verify.py` is a standalone CLI tool and library with **zero imports of DREX runtime, GUI, or execution modules**.

### 8-Phase Verification Protocol
1. **Archive Safety & Container Resolution**: Pre-extraction inspection rejects path traversal (`..`), Windows drive letters (`C:`), UNC paths, reserved device names (`CON`, `PRN`, `AUX`, `NUL`), and symlinks/hardlinks.
2. **Structural File & Schema Validation**: 4-way deterministic schema model:
   - Schema `"2.0"` $\to$ Continue
   - Missing / malformed $\to$ `INVALID`
   - Historical (`"1.0"`) $\to$ `INVALID`
   - Future (`"3.0"`) $\to$ `INDETERMINATE`
3. **Manifest Root Hash Binding**: Validates `manifest.sha256` against `manifest.json`.
4. **Streaming Object Hash & Size Verification**: $64\text{ KB}$ chunked streaming SHA-256 for all declared objects. Rejects undeclared extra files.
5. **Audit Chain Recalculation**: Recomputes all canonical envelope hashes with genesis check `0*64` and sequence continuity.
6. **Custody Ledger Verification**: Validates individual record hashes and 1:1 synchronization with `CUSTODY_CHANGE` audit events.
7. **Certificate Integrity Verification**: Validates SHA-256 integrity token and checks audit event hash binding.
8. **Referential Cross-Link Validation**: Validates `case_id`, `evidence_id`, `operation_id`, and `certificate_id` across the package graph.

### Verdict Precedence & Exit Codes
```
INVALID (3) -> INCOMPLETE (2) -> TAMPERED (1) -> INDETERMINATE (4) -> PASS (0)
```

---

## 5. Truth Model Boundaries
Across all operations and certificates, physical boundaries remain truthful:
```python
physical_execution = "NOT_EXECUTED"
physical_qualification = "NOT_ESTABLISHED"
```
Independent verification proves recorded software evidence, never physical destruction.
