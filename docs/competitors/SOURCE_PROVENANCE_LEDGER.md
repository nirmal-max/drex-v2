# DREX-V2 SOURCE PROVENANCE & INTEGRATION LEDGER

## 1. Provenance Architecture Overview
This ledger documents every external component selected for active code reuse, refactoring, or algorithmic adaptation into DREX-V2.

---

## 2. Reused & Adapted Component Entries

### 1. Fragment Reassembly & ZIP Parsing Engine
- **Source Repository**: `pulkit6732/AKHANDA`
- **Source File(s)**: `akhanda/src/recovery/reassemble.py`, `akhanda/src/recovery/zipcarve.py`
- **Class / Function**: `FragmentReassembler`, `zip_carve_stream()`, `validate_zip_central_dir()`
- **Original Purpose**: Reassembling split file fragments and validating corrupt ZIP containers.
- **DREX Purpose**: Powers DREX Method 22 (Fragment Recovery) and advanced raw carving.
- **License**: Apache-2.0
- **Provenance & Upstream Origin**: Pulkit & AKHANDA team (Smart India Hackathon 2026).
- **Attribution Obligation**: Preserve Apache-2.0 copyright header and include entry in `THIRD_PARTY_NOTICES.md`.
- **Dependencies**: Python standard library (`zipfile`, `struct`, `io`).
- **Code Reused**: 340 lines of pure-Python fragment evaluation logic.
- **Code Modified**: Adapted to yield `RecoveryCandidate` objects and connect to DREX progress queues.
- **DREX Location**: `fragment_engine.py` & `recovery_adapter.py`
- **Test Coverage**: `tests/test_phase1_competitor_integrations.py` & `tests/test_advanced_recovery_engines.py`
- **Integration Decision**: `REUSE_WITH_ADAPTATION`
- **Integration Status**: `VERIFIED`

---

### 2. Multi-Dimensional Explainable Evidence Scoring & Carving
- **Source Repository**: `forensec` & `Vigneshe247/Secure-Data-Erasure-Recovery` (DataShield) & `devil-net`
- **Source File(s)**: `backend/services/confidence.py`, `ConfidenceScoring.cs`, `carver/deep_carve.py`
- **Class / Function**: `EvidenceScores`, `DeepCarverEngine`, `FormatValidator`
- **Original Purpose**: Multi-dimensional structural verification and explainable confidence percentages for carved files.
- **DREX Purpose**: Computes recovery candidate confidence across all 9 DREX recovery methods based on 5 verified evidence dimensions (Signature match, Structural validity, Continuity, Metadata consistency, Size constraints).
- **License**: MIT
- **Provenance & Upstream Origin**: Vignesh, forensec, and DataShield teams.
- **Attribution Obligation**: MIT License notice.
- **Dependencies**: Python standard library (`math`, `struct`, `zlib`).
- **Code Reused**: 160 lines of scoring, structure-aware chunk parsing, and factor evaluation.
- **Code Modified**: Implemented in dedicated `carver_engine.py` module producing typed `CarvedCandidate` and `EvidenceScores`.
- **DREX Location**: `carver_engine.py` & `recovery_adapter.py`
- **Test Coverage**: `tests/test_phase1_competitor_integrations.py` & `tests/test_recovery_comprehensive.py`
- **Integration Decision**: `REUSE_WITH_ADAPTATION`
- **Integration Status**: `VERIFIED`

---

### 3. Out-of-Order JPEG MCU Entropy Stream Decoder
- **Source Repository**: `MithunRayakota07/resurgence-forensics`
- **Source File(s)**: `resurgence/carve.py`
- **Class / Function**: `JpegEntropyDecoder`, `reconstruct_out_of_order_jpeg()`
- **Original Purpose**: Finding out-of-order JPEG clusters using MCU stream validation and restart markers.
- **DREX Purpose**: Non-contiguous JPEG reconstruction in deep forensic recovery.
- **License**: MIT
- **Provenance & Upstream Origin**: Mithun Rayakota (Resurgence team).
- **Attribution Obligation**: MIT License notice.
- **Dependencies**: Python standard library (`struct`).
- **Code Reused**: 190 lines of JPEG entropy decoding.
- **Code Modified**: Isolated into `fragment_engine.py` with fail-closed structural scoring.
- **DREX Location**: `fragment_engine.py` & `recovery_adapter.py`
- **Test Coverage**: `tests/test_phase1_competitor_integrations.py` & `tests/test_advanced_recovery_engines.py`
- **Integration Decision**: `REUSE_WITH_ADAPTATION`
- **Integration Status**: `VERIFIED`

---

### 4. Post-Sanitization Shannon Entropy & 4-State Verification
- **Source Repository**: `K01SR/SecureForge` & `Vigneshe247/Secure-Data-Erasure-Recovery`
- **Source File(s)**: `src/audit/entropy.rs`, `backend/services/verification.py`
- **Class / Function**: `calculate_shannon_entropy()`, `scan_entropy_blocks()`, `evaluate_sanitization_entropy()`
- **Original Purpose**: Measuring block randomness and issuing scientific verification verdicts.
- **DREX Purpose**: Powers the DREX Verification Engine (`drex_app.py` / `VerificationEngine`).
- **License**: MIT
- **Provenance & Upstream Origin**: SecureForge & DataShield teams.
- **Attribution Obligation**: MIT License notice.
- **Dependencies**: Python `math` module.
- **Code Reused**: 110 lines of mathematical entropy calculation and profile evaluation.
- **Code Modified**: Modularized in `entropy_engine.py` with multi-block profiling and wired into `VerificationEngine.assess`.
- **DREX Location**: `entropy_engine.py` & `drex_app.py` (`VerificationEngine`)
- **Test Coverage**: `tests/test_phase1_competitor_integrations.py` & `tests/test_operation_result_and_verification.py`
- **Integration Decision**: `REFACTOR_INTO_DREX`
- **Integration Status**: `VERIFIED`

---

### 5. VSS Shadow Copy Discovery & Safety-Gated Purge
- **Source Repository**: `Prithiv04/EraseXperts` (ARGUS)
- **Source File(s)**: `app.py` (`kill_vss_shadows()`)
- **Class / Function**: `VssSanitizer`, `discover_shadows()`, `create_purge_plan()`, `execute_purge()`
- **Original Purpose**: Eliminating Volume Shadow Copies to prevent forensic recovery of deleted snapshots.
- **DREX Purpose**: Gated sanitization workflow with non-destructive discovery, preview planning, elevation detection, and dry-run safety simulation.
- **License**: MIT
- **Provenance & Upstream Origin**: Prithiv & EraseXperts team.
- **Attribution Obligation**: MIT License notice.
- **Dependencies**: Windows `vssadmin.exe` / Win32 API (`ctypes`, `subprocess`).
- **Code Reused**: 70 lines of VSS discovery and command formulation.
- **Code Modified**: Gated behind `confirm_destructive=True` and `dry_run=False` with elevation checks.
- **DREX Location**: `vss_sanitizer.py` & `drex_app.py`
- **Test Coverage**: `tests/test_phase1_competitor_integrations.py`
- **Integration Decision**: `REFACTOR`
- **Integration Status**: `VERIFIED`

---

### 6. Judge Demo Flow & Strategy Architecture
- **Source Repository**: `yasin-kazi/Integrated-Secure-Data-Erasure-amp-Advanced-File-Recovery-Tool`
- **Source File(s)**: `docs/21_DEMO_STRATEGY.md`, `docs/22_SIH_PRESENTATION_STRUCTURE.md`
- **Class / Function**: 3-minute judge demonstration sequence and risk register.
- **Original Purpose**: Structured live demonstration sequence for hackathon / technical evaluation.
- **DREX Purpose**: Powers the DREX "Judge Demo Flow" UI page and evaluation workflows.
- **License**: Creative Commons / Permissive Documentation
- **Provenance & Upstream Origin**: Yasin Kazi.
- **Attribution Obligation**: Documentation attribution.
- **Dependencies**: None.
- **Code Reused**: Flow structure adapted into GUI page controller.
- **DREX Location**: `drex_app.py` (`JudgeDemoFlowPage`)
- **Test Coverage**: `tests/test_ui_pages.py`
- **Integration Decision**: `REUSE_WITH_ADAPTATION`
- **Integration Status**: `VERIFIED`
