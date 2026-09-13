# DREX-V2 PHASE 2 ARCHITECTURE AUDIT

**Audit Date**: 2026-09-14T00:58:00+05:30  
**Phase**: Phase 2 — Case Management + Evidence Vault + Forensic Timeline + Audit Foundation  
**Target Repository**: `D:\drex-v2-main`  
**Current Phase-1 Baseline**: Commit `68c5322a`, 298/298 tests passing  

---

## 1. Existing System Architecture & Module Map

| Module | Role / Purpose | Existing Capabilities & Data Models | Integration Point for Phase 2 |
|---|---|---|---|
| [`drex_app.py`](file:///d:/drex-v2-main/drex_app.py) | Main controller, desktop UI, Store, and Certificate engine | `OperationContext`, `OperationResult`, `Store`, `CertificateManager`, `safe_json_write` | Extend `OperationContext` and `OperationResult` with `case_id` & `evidence_id`; connect `Store` with `ForensicVaultManager`. |
| [`recovery_adapter.py`](file:///d:/drex-v2-main/recovery_adapter.py) | Recovery dispatch & candidate normalization | `RecoveryCandidate`, `RecoveryDispatchResult`, `QuickRecoveryAdapter`, `DeepRecoveryAdapter`, `FragmentRecoveryAdapter` | Add `source_evidence_id`, candidate state transitions, and export metadata to Evidence Vault. |
| [`carver_engine.py`](file:///d:/drex-v2-main/carver_engine.py) | Raw sector carving & evidence scoring | `DeepCarverEngine`, `FormatValidator`, `EvidenceScores`, `CarvedCandidate` | Output candidate confidence scores and chunk offsets into recovered artifact provenance records. |
| [`fragment_engine.py`](file:///d:/drex-v2-main/fragment_engine.py) | Non-contiguous reassembly & ZIP streaming | `FragmentReassembler`, `JpegEntropyDecoder`, `ZipCarveStream`, `ZipMember` | Link fragmented runs and delta offsets into case evidence records. |
| [`entropy_engine.py`](file:///d:/drex-v2-main/entropy_engine.py) | Shannon entropy & sanitization verification | `calculate_shannon_entropy`, `scan_entropy_blocks`, `evaluate_sanitization_entropy` | Feed sanitization entropy profiles directly into case verification logs and timeline events. |
| [`hardware_storage.py`](file:///d:/drex-v2-main/hardware_storage.py) | Native ATA/NVMe controller & USB containment | `NativeHardwareEngine`, `HardwareDeviceCapabilities`, `HardwareOperationResult` | Record hardware capabilities, device identity, bus transport, and safety refusal reasons in case evidence. |
| [`vss_sanitizer.py`](file:///d:/drex-v2-main/vss_sanitizer.py) | VSS shadow copy discovery & purge gating | `VssSanitizer`, `VssShadowCopy`, `VssPurgePlan`, `VssPurgeResult` | Log VSS discovery and safety dry-run decisions into case audit timeline. |

---

## 2. Identified Architecture Gaps for Phase 2

1. **Case Management**: Current operations run as standalone tasks in `Store.history` without structured Case entity aggregation (`case_id`, `case_number`, `examiner`, `organization`, `status`, `classification`).
2. **Evidence Vault**: Evidence artifacts (source disks, disk images, carved files, certificates) currently reside in ad-hoc paths without categorized isolation (`SOURCE`, `DERIVED`, `RECOVERED`, `REPORT`, `CERTIFICATE`, `AUDIT`).
3. **Cryptographic Streaming Hasher**: `CertificateManager` and test fixtures compute hashes in memory. Need streaming chunked SHA-256/SHA-512 hashing that safely handles multi-gigabyte disk images without unbounded memory consumption.
4. **Forensic Timeline**: Application currently logs text to `history.json`. Need structured, typed timeline events with chronological ordering and integrity hashes.
5. **Hash-Chained Audit Ledger**: Need deterministic Merkle/hash-chained audit records ($H_i = \text{SHA256}(H_{i-1} \parallel \text{canonical}(P_i))$) with an independent verification routine that detects any payload tampering, sequence deletion, or insertion.
6. **Chain of Custody**: Need an immutable, append-only custody ledger tracking evidence transfers, custodial access, sealing, and analysis.
7. **Case Export & Import**: Need an atomic case packager producing a signed manifest of all artifacts, with rigorous validation and path-traversal protection on import.

---

## 3. Minimal Modular Solution Design

Create a dedicated module [`forensic_vault.py`](file:///d:/drex-v2-main/forensic_vault.py) housing:
- `ForensicCase` & `CaseManager`
- `EvidenceSource` & `EvidenceVault`
- `StreamingHasher`
- `ForensicTimeline` & `TimelineEvent`
- `AuditChain`, `AuditEvent`, and `IndependentAuditVerifier`
- `ChainOfCustody` & `CustodyRecord`
- `RecoveryArtifactRecord` & `SanitizationProvenanceRecord`
- `CasePackageManager` (Export / Import with manifest and path traversal safety)

Preserve atomic JSON persistence with `safe_json_write` and thread safety with `threading.RLock`. Zero external dependencies.
