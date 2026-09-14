# DREX-V2 — Phase 5 Forensic Qualification & Architecture Report

**Capability Area:** Advanced Fragment Recovery, Damaged Media Acquisition, Mapfile Engine & Virtual RAID Reconstruction  
**Phase:** Phase 5 Hardened  
**Reference Standards:** NIST SP 800-88 Rev. 1, GNU ddrescue v1.28 Specification, Linux mdadm Layout Specification  
**Report Date:** September 2026  

---

## 1. Baseline State (Before Phase 5)

Prior to Phase 5:
- Baseline passing test count: **445 tests** across Phase 1, Phase 2, Phase 3 (TSK differential validation), Phase 4 (advanced carving & forensic recovery engines), and Physical Hardware sanitization backend integration (`hardware_storage.py`).
- Damaged media acquisition was limited to an in-memory direct sector reader with basic map generation.
- Fragment candidate scoring reported a single heuristic float rather than auditable, explainable multi-factor evidence breakdown.
- Virtual RAID reconstruction was performed entirely in-memory without streaming buffer bounds or multi-layout support.

---

## 2. Proven-Source Selection & Architecture Hierarchy

In strict adherence to the proven-source hierarchy:
1. **GNU ddrescue** (v1.28): Primary reference for damaged-media acquisition, multi-pass copying/trimming/scraping, and `.map` mapfile serialization. GNU ddrescue is invoked strictly as an external CLI tool (`backend_adapters.py`) with zero bundled GPL C++ code.
2. **Linux mdadm** (v4.3): Primary algorithmic and layout reference for standard RAID 0, 1, 5 (left-symmetric, right-symmetric, dedicated-parity), and 10 reconstruction. DREX implements clean-room Python XOR mathematics and stripe sequencing.
3. **AKHANDA & Resurgence**: Retained proven Phase 4 engines for ZIP delta reconstruction (`PROV-001`), PNG structural validation (`PROV-002`), and JPEG restart marker entropy decoding (`PROV-003`).

---

## 3. Exact Proven Sources, Versions & Licenses

| Provenance ID | Project Name | Upstream Repository | Version / Baseline | Original License | DREX Adaptation Type | DREX Destination File |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **PROV-REC-001** | GNU ddrescue | `https://savannah.gnu.org/git/?group=ddrescue` | `v1.28` | GNU GPL v2+ | REFERENCE_ONLY & CLEAN_ROOM SPEC | [`damaged_media.py`](file:///D:/drex-v2-main/damaged_media.py), [`backend_adapters.py`](file:///D:/drex-v2-main/backend_adapters.py) |
| **PROV-REC-002** | Linux mdadm | `https://git.kernel.org/pub/scm/utils/mdadm/mdadm.git` | `v4.3` | GNU GPL v2 | REFERENCE_ONLY (Clean-Room XOR Math) | [`recovery_adapter.py`](file:///D:/drex-v2-main/recovery_adapter.py) |
| **PROV-HW-001** | DriveWipe | `https://github.com/KodyDennon/DriveWipe` | `v2.0.5` | MIT License | REUSE_WITH_SAFETY_ADAPTATION | [`hardware_storage.py`](file:///D:/drex-v2-main/hardware_storage.py) |
| **PROV-001** | AKHANDA | `https://github.com/akhanda-forensics/akhanda` | `6f8b2a1` | MIT License | REUSE_WITH_ADAPTATION | [`fragment_engine.py`](file:///D:/drex-v2-main/fragment_engine.py) |
| **PROV-002** | AKHANDA | `https://github.com/akhanda-forensics/akhanda` | `6f8b2a1` | MIT License | REUSE_WITH_ADAPTATION | [`carver_engine.py`](file:///D:/drex-v2-main/carver_engine.py) |
| **PROV-003** | Resurgence | `https://github.com/resurgence-forensics/resurgence` | `v1.2.0` | MIT License | REUSE_WITH_ADAPTATION | [`fragment_engine.py`](file:///D:/drex-v2-main/fragment_engine.py) |
| **PROV-010** | PhotoRec | `https://github.com/cgsecurity/testdisk` | `v7.2` | GNU GPL v2 | REFERENCE_ONLY (External CLI) | [`backend_adapters.py`](file:///D:/drex-v2-main/backend_adapters.py) |
| **PROV-011** | The Sleuth Kit | `https://github.com/sleuthkit/sleuthkit` | `v4.15.0` | IPL 1.0 / CPL 1.0 | REFERENCE_ONLY (External CLI) | [`backend_adapters.py`](file:///D:/drex-v2-main/backend_adapters.py) |

---

## 4. Newly Implemented & Adapted Components

### A. Clean-Room Damaged Media Mapfile Engine (`damaged_media.py`)
- Full support for all 5 GNU ddrescue mapfile status tokens:
  - `?` (`NON_TRIED`): Unattempted sector regions.
  - `*` (`NON_TRIMMED`): Sectors bordering error regions.
  - `/` (`NON_SCRAPED`): Trimmed bad areas awaiting 1-sector scraping.
  - `-` (`BAD_SECTOR`): Irrecoverable hardware read errors.
  - `+` (`FINISHED`): Successfully salvaged intact sector data.
- Capabilities:
  - Strict syntax parsing and serialization matching GNU ddrescue v1.28.
  - Multi-pass mapfile merge engine with priority coalescing (`FINISHED > BAD_SECTOR > NON_SCRAPED > NON_TRIMMED > NON_TRIED`).
  - Integrity and continuity validation (detecting boundary gaps, overlaps, negative sizes).
  - Deterministic SHA-256 calculation for forensic custody audit.

### B. Controlled GNU ddrescue CLI Backend Adapter (`backend_adapters.py`)
- Implements the 5-stage safety gate pipeline:
  1. *Discovery*: Locates official `ddrescue` executable.
  2. *Capability Qualification*: Inspects CLI options (`--version`, `--help`).
  3. *Operator Selection*: Requires explicit caller selection.
  4. *Safety Validation*: Read-only source enforcement (`READ_ONLY = True`), write-block verification, source/destination non-overlap check.
  5. *Execution*: Argument array subprocess execution with real-time stdout scraping (`rescued`, `errsize`, `bad areas`, `current pass`).

### C. Bounded-Memory Streaming Imager (`recovery_adapter.py`)
- Upgraded `DirectDamagedMediaImager` to stream disk blocks using bounded memory chunk buffers (64 KB).
- Source immutability guaranteed: zero write handles opened against source files or block devices.

### D. Advanced Fragment Recovery & Auditable Evidence Engine (`fragment_engine.py`)
- Expanded candidate lifecycle states: `DISCOVERED`, `CANDIDATE`, `GROUPED`, `ORDER_HYPOTHESIS`, `RECONSTRUCTING`, `STRUCTURALLY_VALID`, `CONTENT_VALIDATED`, `RECOVERED_ARTIFACT`, `REJECTED`, `AMBIGUOUS_RECONSTRUCTION`, `UNSUPPORTED`, `RESOURCE_LIMITED`.
- Explicit corruption outcomes: `RECOVERED`, `RECOVERED_WITH_GAP`, `STRUCTURALLY_VALID_ONLY`, `PARTIAL_RECOVERY`, `CANDIDATE_ONLY`, `REJECTED`.
- `AuditableEvidenceScore`: Captures *evidence confidence* (0.0 to 100.0) with granular scoring breakdown and raw verified facts dictionary (`crc32_matches`, `entropy_gradient`, `marker_offsets`, `chunk_counts`).

### E. Streaming Virtual RAID Reconstructor (`recovery_adapter.py`)
- Bounded memory streaming rebuild iterators: `reconstruct_raid0_stream` and `reconstruct_raid5_stream`.
- Supported and verified layouts:
  - RAID 0 (Striped volume)
  - RAID 1 (Mirrored volume)
  - RAID 5 (Left-Symmetric rotating parity, dedicated-parity / RAID 4) with bit-exact degraded single-disk XOR reconstruction.
  - RAID 10 (Striped mirror pairs)
- Unvalidated exotic layouts explicitly return `UNSUPPORTED`.

---

## 5. Empirical Memory Qualification Results (TEST-VERIFIED BOUNDED STREAMING)

### A. Measured Streaming Workload Results
Measured via `tests/test_phase5_performance_memory.py` using standard Python `tracemalloc`:

| Operation | Input Fixture Size | Buffer Chunk Size | Measured Peak Memory Delta | Workload Classification | Complexity Scaling |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Damaged Media Imaging** | 10.0 MB | 64 KB | **0.06 MB** | Sequential Stream I/O | $O(1)$ constant buffer |
| **Damaged Media Imaging** | 50.0 MB | 64 KB | **0.06 MB** | Sequential Stream I/O | $O(1)$ constant buffer |
| **RAID 5 Streaming Rebuild** | 10.0 MB | 64 KB | **0.03 MB** | 3-Disk Stripe Rebuild | $O(1)$ constant buffer |

### B. Qualification Scope & Limitations
- **Established Qualification:** `TEST-VERIFIED BOUNDED STREAMING`. Confirms that sequential sector-by-sector disk acquisition, bad-sector mapfile tracking, and multi-disk RAID streaming rebuilds operate strictly with $O(1)$ memory buffer overhead relative to total disk/image size.
- **NOT Established:** Universal memory qualification across unconstrained multi-fragment permutation search trees, unbounded external GUI processes (e.g. Autopsy), or non-streaming in-memory container expansions.

---

## 6. Testing & Regression Summary

- **Previous Baseline:** 445 passed (100%)
- **New Phase 5 Tests Added:** 28 tests across 4 test suites:
  - `tests/test_phase5_damaged_media.py` (9 tests)
  - `tests/test_phase5_fragment_reconstruction.py` (6 tests)
  - `tests/test_phase5_raid_reconstruction.py` (10 tests)
  - `tests/test_phase5_performance_memory.py` (3 tests)
- **Total New Test Count:** **473 passed**
- **Test Integrity:** 0 tests deleted, 0 weakened, 0 skipped, 0 failed.

---

## 7. Forensic Qualification Status

```yaml
upstream_hardware_validation: DOCUMENTED / VERIFIED
drex_backend_integration:    IMPLEMENTED / TESTED
drex_physical_execution:      NOT_EXECUTED
drex_physical_qualification:  NOT_ESTABLISHED
```

> [!IMPORTANT]
> **Forensic Qualification Truth Rule**:
> While upstream tools (GNU ddrescue, PhotoRec, TSK) have extensive physical hardware test history, DREX distinguishes upstream physical qualification from local DREX execution. In development and CI environments where no sacrificial physical drive is authorized via `DREX_PHYSICAL_TEST_DEVICE` and `DREX_PHYSICAL_TEST_AUTHORIZED=YES`, DREX records physical execution as `NOT_EXECUTED` and physical media qualification as `NOT_ESTABLISHED`.

---

## 8. Remaining Limitations

1. **Physical Qualification:** Requires authorized execution on dedicated disposable physical failing drives.
2. **RAID Layouts:** Limited strictly to verified layouts (RAID 0, 1, 5 left-symmetric & dedicated-parity, 10); RAID 6 and dual-parity Reed-Solomon layouts remain `UNSUPPORTED`.
3. **GPL Tool Bundling:** GNU ddrescue and mdadm are not distributed or bundled inside DREX binaries; they are detected and utilized as optional external CLI backends.
