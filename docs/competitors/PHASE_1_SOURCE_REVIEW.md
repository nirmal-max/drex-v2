# PHASE 1 SOURCE REVIEW & TECHNICAL AUDIT

## 1. Scope & Objective
This technical review analyzes the actual source code of competitor candidate implementations inspected during Phase 1. It details why specific algorithms were selected, how they were modified to adhere to DREX-V2 architectural standards, and why others were rejected or deferred.

---

## 2. Detailed Technical Evaluations

### 2.1 AKHANDA (`reassemble.py` & `zipcarve.py`)
- **Source Files**: `akhanda/src/recovery/reassemble.py`, `akhanda/src/recovery/zipcarve.py`
- **Class / Symbols**: `FragmentReassembler`, `ZipCarver`
- **License**: MIT License (Permissive, verified compatible)
- **Technical Analysis**:
  - *Strengths*: Implements an effective boundary seam scoring mechanism based on entropy differentials. Pure Python, fast, and does not require native external C bindings.
  - *Weaknesses in Original*: Had unbounded recursion in candidate permutation and assumed all ZIP files had contiguous local file headers.
  - *DREX Adaptation*: Refactored into `fragment_engine.py`. Added `max_candidate_size` bounding (default 10 MB) to eliminate memory exhaustion vectors. Corrected EOCD and local header extra field offsets.
  - *Status*: `REUSE_WITH_ADAPTATION` -> **INTEGRATED** into [fragment_engine.py](file:///d:/drex-v2-main/fragment_engine.py).

### 2.2 Resurgence (`jpeg_entropy.py`)
- **Source Files**: `engine/jpeg_entropy.py`
- **Class / Symbols**: `JpegEntropyDecoder`
- **License**: MIT License
- **Technical Analysis**:
  - *Strengths*: Correctly identifies SOS (Start of Scan), handles JPEG byte-stuffing (`0xFF 0x00`), and enumerates restart markers (`0xD0`..`0xD7`).
  - *Weaknesses in Original*: Did not validate structural marker sequencing (SOI < SOF < SOS < EOI).
  - *DREX Adaptation*: Implemented `structural_validity_score()` producing explainable metrics ($0.0$ to $1.0$) for forensic candidate ranking.
  - *Status*: `REUSE_WITH_ADAPTATION` -> **INTEGRATED** into [fragment_engine.py](file:///d:/drex-v2-main/fragment_engine.py).

### 2.3 SecureForge & devil-net (`entropy.py`)
- **Source Files**: `core/entropy.py`
- **Class / Symbols**: `shannon_entropy`
- **License**: MIT / Apache 2.0
- **Technical Analysis**:
  - *Strengths*: Exact mathematical implementation of Shannon entropy: $H(X) = -\sum_{i=1}^n P(x_i) \log_2 P(x_i)$.
  - *Weaknesses in Original*: Treated high entropy as conclusive proof of data sanitization, which is forensically invalid (encrypted files and compressed media also have high entropy).
  - *DREX Adaptation*: Refactored into `entropy_engine.py` as an *evidence signal* rather than a sole verdict. Implemented `evaluate_sanitization_entropy` with multi-block distribution profiling and specific profile validation (`zero`, `pattern`, `random`).
  - *Status*: `REFACTOR` -> **INTEGRATED** into [entropy_engine.py](file:///d:/drex-v2-main/entropy_engine.py).

### 2.4 ForensiX / SIH26 (`ntfs_bitmap.py`)
- **Source Files**: `forensics/ntfs_bitmap.py`
- **Class / Symbols**: `NtfsBitmap`
- **License**: MIT License
- **Technical Analysis**:
  - *Strengths*: Clean bitfield parsing of NTFS cluster allocation status.
  - *Weaknesses in Original*: Hardcoded policy to exclusively scan unallocated clusters, ignoring slack space and active cluster carving.
  - *DREX Adaptation*: Refactored into `fs_bitmap.py` with 4 selectable scan policies (`FREE_ONLY`, `FREE_FIRST`, `FULL_VOLUME`, `TARGETED`) and volume allocation statistics.
  - *Status*: `REUSE_WITH_ADAPTATION` -> **INTEGRATED** into [fs_bitmap.py](file:///d:/drex-v2-main/fs_bitmap.py).

### 2.5 EraseXperts (`vss_purge.py`)
- **Source Files**: `sanitization/vss_purge.py`
- **Class / Symbols**: `VssPurge`
- **License**: MIT License
- **Technical Analysis**:
  - *Weaknesses in Original*: Automatically invoked destructive `vssadmin delete shadows /all /quiet` without confirmation or elevation validation.
  - *DREX Adaptation*: Re-architected with strict separation: discovery -> reporting -> decision -> confirmation -> elevation check -> dry-run execution.
  - *Status*: `REFACTOR` -> **INTEGRATED** into [vss_sanitizer.py](file:///d:/drex-v2-main/vss_sanitizer.py).
