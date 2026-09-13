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
- **DREX Location**: `methods/Recovery/Module6_Fragment_Recovery_Production_Baseline_v0.1.0/` & `recovery_adapter.py`
- **Test Coverage**: `tests/test_advanced_recovery_engines.py`
- **Integration Decision**: `REUSE_WITH_ADAPTATION`
- **Integration Status**: `VERIFIED`

---

### 2. Explainable 5-Factor Recovery Confidence Formula
- **Source Repository**: `Vigneshe247/Secure-Data-Erasure-Recovery` (DataShield) & `devil-net`
- **Source File(s)**: `backend/services/confidence.py`, `ConfidenceScoring.cs`
- **Class / Function**: `calculate_confidence_score(candidate)`
- **Original Purpose**: Generating mathematical, explainable confidence percentages for carved files.
- **DREX Purpose**: Computes recovery candidate confidence across all 9 DREX recovery methods:
  $$\text{Confidence} = 0.35 \times \text{SigMatch} + 0.25 \times \text{Structure} + 0.20 \times \text{Continuity} + 0.15 \times \text{Metadata} + 0.05 \times \text{Size}$$
- **License**: MIT
- **Provenance & Upstream Origin**: Vignesh & DataShield team.
- **Attribution Obligation**: MIT License notice.
- **Dependencies**: Python standard library (`math`).
- **Code Reused**: 85 lines of scoring and factor evaluation.
- **Code Modified**: Integrated into `RecoveryCandidate.confidence` normalization.
- **DREX Location**: `recovery_adapter.py`
- **Test Coverage**: `tests/test_recovery_comprehensive.py`
- **Integration Decision**: `DIRECT_REUSE`
- **Integration Status**: `VERIFIED`

---

### 3. Out-of-Order JPEG MCU Entropy Stream Decoder
- **Source Repository**: `MithunRayakota07/resurgence-forensics`
- **Source File(s)**: `resurgence/carve.py`
- **Class / Function**: `JpegEntropyDecoder`, `reconstruct_out_of_order_jpeg()`
- **Original Purpose**: Finding out-of-order JPEG clusters using MCU stream validation.
- **DREX Purpose**: Non-contiguous JPEG reconstruction in deep forensic recovery.
- **License**: MIT
- **Provenance & Upstream Origin**: Mithun Rayakota (Resurgence team).
- **Attribution Obligation**: MIT License notice.
- **Dependencies**: Python standard library (`struct`).
- **Code Reused**: 190 lines of JPEG entropy decoding.
- **Code Modified**: Added fail-closed hypothesis labeling.
- **DREX Location**: `recovery_adapter.py`
- **Test Coverage**: `tests/test_advanced_recovery_engines.py`
- **Integration Decision**: `REUSE_WITH_ADAPTATION`
- **Integration Status**: `VERIFIED`

---

### 4. Post-Sanitization Shannon Entropy & 4-State Verification
- **Source Repository**: `K01SR/SecureForge` & `Vigneshe247/Secure-Data-Erasure-Recovery`
- **Source File(s)**: `src/audit/entropy.rs`, `backend/services/verification.py`
- **Class / Function**: `calculate_shannon_entropy()`, `evaluate_4state_verdict()`
- **Original Purpose**: Measuring block randomness and issuing scientific verification verdicts.
- **DREX Purpose**: Powers the DREX Verification Engine (`drex_app.py` / `VerificationEngine`).
- **License**: MIT
- **Provenance & Upstream Origin**: SecureForge & DataShield teams.
- **Attribution Obligation**: MIT License notice.
- **Dependencies**: Python `math` module.
- **Code Reused**: 110 lines of mathematical entropy calculation and 4-state verdict mapping.
- **Code Modified**: Implemented in Python with vector acceleration for 64-sector sample windows.
- **DREX Location**: `drex_app.py` (`VerificationEngine`)
- **Test Coverage**: `tests/test_operation_result_and_verification.py`
- **Integration Decision**: `REFACTOR_INTO_DREX`
- **Integration Status**: `VERIFIED`

---

### 5. VSS Shadow Copy Purging & Volume Residue Neutralizer
- **Source Repository**: `Prithiv04/EraseXperts` (ARGUS)
- **Source File(s)**: `app.py` (`kill_vss_shadows()`)
- **Class / Function**: `kill_vss_shadows()`, `vssadmin_purge()`
- **Original Purpose**: Eliminating Volume Shadow Copies to prevent forensic recovery of deleted snapshots.
- **DREX Purpose**: Integrated into DREX Method 11 (Filesystem Metadata Sanitization) and Method 16 (Temp/Cache Sanitization).
- **License**: MIT
- **Provenance & Upstream Origin**: Prithiv & EraseXperts team.
- **Attribution Obligation**: MIT License notice.
- **Dependencies**: Windows `vssadmin.exe` / Win32 API.
- **Code Reused**: 45 lines of subprocess VSS purging.
- **Code Modified**: Added administrative privilege safety check and fail-closed error handling.
- **DREX Location**: `methods/File-Folder Erasure/Module4_Filesystem_Metadata_Sanitization_Production_Baseline_v0.1.0/`
- **Test Coverage**: `tests/test_edge_cases.py`
- **Integration Decision**: `DIRECT_REUSE`
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
