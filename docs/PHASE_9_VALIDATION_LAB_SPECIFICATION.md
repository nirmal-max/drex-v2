# DREX-V2 Phase 9 Specification: Validation Laboratory, Performance Engineering & Adversarial Validation

## Executive Overview

**Phase 9** introduces the comprehensive **Validation Laboratory**, establishing deterministic, mathematically verifiable ground-truth validation across all 25 canonical forensic recovery and media sanitization methods (M01–M25), dual-signal memory profiling, resource-bounded adversarial stress testing, and hardware qualification gates.

---

## Architecture & Core Modules

### 1. Synthetic Fixture Generator & 6-Stage Validity Gate (`fixture_generator.py`)
- **Deterministic Synthetic Images:** Generates bit-identical FAT32, NTFS, RAID 0, RAID 1, RAID 5, and RAID 10 images with known PRNG seeds.
- **Pre-Failure Ground-Truth Preservation:** Preserves original uncorrupted datasets for RAID and damaged media recovery, ensuring reconstructed datasets are verified bit-for-bit against the original dataset, not merely internal parity checksums.
- **6-Stage Fixture Validity Gate:**
  $$\text{GENERATE} \longrightarrow \text{PARSE} \longrightarrow \text{STRUCTURE VALIDATION} \longrightarrow \text{REFERENCE VALIDATION} \longrightarrow \text{CONTENT HASH VALIDATION} \longrightarrow \text{ACCEPT FIXTURE}$$
- Zero manufactured reference validation: Records `REFERENCE_UNAVAILABLE` when external tools are absent.

### 2. Dual-Signal Memory Profiler & Performance Lab (`performance_lab.py`)
- **Dual-Signal Telemetry:**
  - **`tracemalloc`**: Measures Python heap memory allocation and peak watermark.
  - **Process RSS / Working Set**: Measures operating system process physical resident memory (`GetProcessMemoryCounters`).
- **Bounded Streaming Verification:** Validates flat memory ceilings ($< 2\text{ MB}$ heap growth) when streaming multi-megabyte datasets through 64 KB chunk buffers.
- **Zero Arbitrary Timeouts:** Measures runtime purely as benchmark telemetry without arbitrary failure timeouts.

### 3. Validation Lab Core Orchestrator & CLI (`validation_lab.py`)
- **Headless & Programmatic Runner:** Runs all validation suites and benchmarks.
- **CLI Commands:**
  - `python validation_lab.py --all`
  - `python validation_lab.py --kat-recovery`
  - `python validation_lab.py --kat-sanitization`
  - `python validation_lab.py --hardware-safety`
  - `python validation_lab.py --stress`
  - `python validation_lab.py --benchmark`
  - `python validation_lab.py --json <path>`
  - `python validation_lab.py --report <path>`
- **UI Integration:** Integrated into `drex_app.py` via `drex_app.py --validation-lab`.

---

## Canonical 25-Method Coverage Matrix

| Method ID | Method Name | Category | Primary Verification Criterion | Secondary Telemetry |
|:---|:---|:---|:---|:---|
| **M01** | NIST SP 800-88 Policy Engine | Drive Erasure | Media Intelligence Match & Profile Selection | Hardware Capability Vector |
| **M02** | Smart Sanitization | Drive Erasure | Heuristic Multi-Tier Dispatch | Wear-leveling / Bus Matrix |
| **M03** | Device-Native Sanitize | Drive Erasure | Fail-closed USB containment & Pass-through IOCTL | Protocol status log |
| **M04** | ATA Secure Erase | Drive Erasure | Frozen/Locked state check & Password block | Security feature set |
| **M05** | NVMe Secure Erase | Drive Erasure | Admin Sanitize CDW10/CDW11 construction | SPROG / SSTAT polling |
| **M06** | IEEE 2883 Purge | Drive Erasure | Media purge compliance mapping | State qualification |
| **M07** | Verified Overwrite | Drive Erasure | 100% Deterministic pattern readback check | Multi-pass write timing |
| **M08** | CSPRNG Random Overwrite | File/Folder Erasure | Exact byte-for-byte readback verification | Shannon Entropy $H \ge 7.90$ |
| **M09** | Cryptographic Erasure | File/Folder Erasure | Key lifecycle invalidation & container overwrite | Scope verification |
| **M10** | File Slack / Cluster-Tip | File/Folder Erasure | Active $[0, file\_size)$ intact + Slack $[file\_size, alloc)$ zeroed | Extent boundary map |
| **M11** | Filesystem Metadata Sanitization | File/Folder Erasure | MFT records 0–15 protected + deleted records zeroed | Fixup array validation |
| **M12** | NIST SP 800-88 File Policy | File/Folder Erasure | File metadata inspection & standards profile mapping | Verification logs |
| **M13** | Secure Free-Space Wiping | File/Folder Erasure | Bounded temporary allocation + unallocated zeroing | Headroom reserve |
| **M14** | Single-Pass Zero Overwrite | File/Folder Erasure | 100% `0x00` readback verification | Shannon Entropy $H = 0.0$ |
| **M15** | Storage-Aware Sanitization | File/Folder Erasure | Media-aware fallback dispatch | Controller detection |
| **M16** | Temporary / Cache Sanitization | File/Folder Erasure | Full directory tree scrubbing & unlinking | Deletion verification |
| **M17** | Quick Recovery | Recovery | Inode & directory entry parsing (FAT32/NTFS) | Recovery duration |
| **M18** | Smart Recovery | Recovery | Heuristic signature & header structure check | Candidate classification |
| **M19** | Targeted Recovery | Recovery | Extension & MIME category filtering | Candidate filtering |
| **M20** | Filesystem Recovery | Recovery | Hierarchical directory tree reconstruction | Tree depth |
| **M21** | Deep Recovery | Recovery | Raw sector carving across all 16 format validators | Declared length & CRC32 |
| **M22** | Fragment Recovery | Recovery | Non-contiguous fragment reassembly & validation | Fragment boundary seam |
| **M23** | RAID / Storage Recovery | Recovery | Degraded XOR reconstruction vs pre-failure dataset | Parity rotation map |
| **M24** | Damaged Media Recovery | Recovery | GNU ddrescue mapfile parsing & block tracking | Rescued / Bad sector ratio |
| **M25** | Forensic Recovery | Recovery | SHA-256 cryptographically hash-linked audit chain verification & tamper detection | Audit event log |

---

## Adversarial & Safety Invariants

1. **Hardware Safety Tripwire:**
   - Destructive commands targeting `\\.\PhysicalDrive0` or `\\.\C:` are strictly refused with `RuntimeError` (`DestructiveHardwareTripwire`).
   - Dynamic device drift (serial, capacity, model, sector size, bus transport, or system disk relationship) triggers immediate `IDENTITY_CHANGED` fail-closed refusal.
2. **Software Qualification Truth Boundary:**
   - `physical_execution = NOT_EXECUTED`
   - `physical_qualification = NOT_ESTABLISHED`
3. **Entropy Invariant:**
   - Shannon entropy ($H$) is strictly **secondary statistical telemetry**, never proof of sanitization.
4. **Decompression-Bomb Defense:**
   - Expansion ratio monitors ($>50:1$) and recursive structures are bounded to prevent memory or CPU exhaustion.

---

## Test Suite Execution Results

- **Baseline Tests:** 612 passed
- **Phase 9 New Tests:** 56 passed
- **Total Repository Regression:** **668 passed, 0 failed, 0 skipped**
