# Phase 16 Baseline Architecture Audit: Advanced Forensic Recovery & Forensic Engine Depth

**Project**: DREX-V2 (SIH26149)  
**Baseline Commit**: `57ea7b6` (Phase 15 Accepted & Frozen)  
**Audit Purpose**: Rigorous architectural mapping of existing forensic recovery, raw carving, fragment reconstruction, confidence evaluation, candidate lifecycles, Evidence Vault, and audit integration before implementing Phase 16 depth.

---

## A. Existing Recovery Engines

1. **Native Filesystem Parsers (`fs_ntfs.py`, `fs_fat.py`, `fs_exfat.py`, `fs_ext.py`)**:
   - `NtfsParser`: Inodes/MFT record parsing ($MFT records 1024 bytes), attributes `$STANDARD_INFORMATION`, `$FILE_NAME`, `$DATA` (resident and non-resident data runs).
   - `FatParser`: FAT12/16/32 BPB parameter block parsing, FAT table traversal, root directory and subdirectories, deleted entry identification (0xE5 marker).
   - `ExfatParser`: Volume boot record, main FAT, cluster heap, stream extension directory entries, secondary directory entries, deleted entries.
   - `Ext4Parser`: Superblock, block group descriptors, inode tables, direct/indirect blocks, ext4 extent trees (`ext4_extent_header`, `ext4_extent`), directory entry parsing.
2. **Unified Filesystem Engine (`fs_recovery.py`)**:
   - `FilesystemRecoveryEngine`: Partition discovery via `PartitionTableParser` (MBR/GPT), filesystem kind detection via `FilesystemIdentifier`, candidate scanning, stream extraction, candidate recovery with format verification.
   - `DirectoryTreeReconstructor`: Path graph reconstruction from parent IDs, cycle detection guard (max depth 64), path sanitation, `_ORPHANED_FILES` fallback directory routing.
3. **External Forensic Tool Dispatcher (`recovery_adapter.py`, `recovery_backends.py`)**:
   - TSK 4.15.0 integration: `fls.exe` (directory/inode listing), `icat.exe` (inode stream extraction), `tsk_recover.exe`, `fsstat.exe`.
   - PhotoRec / TestDisk: Raw carving and partition table recovery.
   - Fail-closed binary verification with `BackendStatus` (`AVAILABLE` vs `NOT_INSTALLED`).

---

## B. Existing Filesystem Support

| Filesystem | Detection Engine | Parser Class | Metadata Handled | Deleted Entry Support | Extent Resolution |
|---|---|---|---|---|---|
| **NTFS** | `fs_identifier.py` | `NtfsParser` | MFT record, timestamps (MACB), attributes ($30, $80) | Deleted MFT record flag (in_use=0) | Non-resident data runs & Resident streams |
| **FAT12/16/32** | `fs_identifier.py` | `FatParser` | 8.3 filename, VFAT LFN entries, timestamps, start cluster | 0xE5 first-byte deleted marker | FAT chain + contiguous fallback extents |
| **exFAT** | `fs_identifier.py` | `ExfatParser` | Stream extension flags, secondary entries, NoFatChain flag | Deleted directory entries (flag & 0x80 == 0) | Direct cluster continuous extents |
| **ext2/3/4** | `fs_identifier.py` | `Ext4Parser` | Inode table, mode, uid/gid, size, timestamps, block pointers | Inodes with dtime > 0 or unlinked | Ext4 extent tree & direct block pointers |

---

## C. Existing Carving Support (`carver_engine.py`, `validators/`)

1. **`DeepCarverEngine` / `StreamingCarver`**:
   - Sliding window scanning (default 1 MB window with 64 KB overlap buffer).
   - Sector alignment filtering (512-byte / 4096-byte boundaries).
   - Signature matching (longest specific magic bytes first).
   - Candidate deduplication via `seen_ranges` intervals.
2. **Format Validators (`validators/`)**:
   - 15 format validators: `jpeg.py`, `png.py`, `pdf.py`, `zip.py`, `ooxml.py`, `sqlite.py`, `gif.py`, `riff.py`, `mp3.py`, `mp4.py`, `elf.py`, `pe.py`, `tiff.py`, `bmp.py`, `rar.py`, `sevenzip.py`.
   - Structural parsing: JPEG marker validation (SOI/SOF/SOS/EOI), PNG chunk CRC32 verification, PDF xref/trailer parsing, SQLite page header / B-tree cell counting, ZIP Central Directory / EOCD verification.

---

## D. Existing Fragment Support (`fragment_engine.py`)

1. **`FragmentReassembler`**:
   - Boundary seam continuity scoring via Shannon entropy difference across adjacent chunk boundaries (`seam_continuity_score`).
   - Header/footer chunk identification.
2. **`JpegEntropyDecoder` & `JpegRstStreamReassembler` (PROV-003)**:
   - JPEG restart marker sequence parsing (RST0..RST7).
   - Sequential alignment of out-of-order entropy segments across restart intervals.
3. **`ZipCarveStream` & `DeltaClusterReassembler` (PROV-001)**:
   - Central Directory member delta arithmetic: buffer offset minus declared local header offset.
   - Clustering of fragmented ZIP members into coherent continuous extents.
4. **`BoundedPermutationReconstructor`**:
   - Branch-and-bound combinatorial search with bounded depth (max depth 8, max evaluated branches 64).
   - Ambiguity containment: detects when multiple competing permutations pass structural validation (`CandidateState.AMBIGUOUS_RECONSTRUCTION`).

---

## E. Existing Confidence Model

1. **`EvidenceScores` / `AuditableEvidenceScore`**:
   - 5 explainable analytical factors:
     - `sig_match` (0.25–0.30): Magic byte header/footer presence.
     - `structure` (0.20–0.30): Internal chunk / table / container validity.
     - `continuity` (0.15–0.20): Boundary seam entropy gradient.
     - `metadata` (0.10–0.15): Header / dimension / timestamp consistency.
     - `size_bounded` / `filesystem_alignment` (0.10–0.15): Size plausibility & FS corroboration.
2. **Confidence Semantics**:
   - Confidence represents **EVIDENCE STRENGTH**, never "percentage of disk recovered".
   - Confidence scores are strictly analytical ranking metrics and cannot independently promote candidates to `RECOVERED_ARTIFACT` without passing deterministic structural validators.

---

## F. Existing Candidate Lifecycle

The canonical 4-tier lifecycle strictly separates unverified fragments from forensic evidence:
$$\text{CANDIDATE} \longrightarrow \text{VALIDATED\_CANDIDATE} \longrightarrow \text{RECONSTRUCTED\_CANDIDATE} \longrightarrow \text{RECOVERED\_ARTIFACT}$$

- `CANDIDATE`: Discovered signature or raw unvalidated filesystem/carving record.
- `VALIDATED_CANDIDATE`: Candidate that has passed format structural validation.
- `RECONSTRUCTED_CANDIDATE`: Candidate assembled across multiple fragments passing format-specific continuity and structure validation.
- `RECOVERED_ARTIFACT`: Fully extracted, SHA-256 hashed, format-verified artifact ingested into the Evidence Vault and sealed in the audit chain.

---

## G. Existing Evidence Vault Integration (`forensic_vault.py`)

- `CaseManager`: Case management with isolation in `drex_data/cases/<case_id>/`.
- `EvidenceVault`: Subdirectories `source/`, `derived/`, `recovered/`, `reports/`, `certificates/`, `audit/`.
- Cross-case isolation: Every read/write/extract operation enforces strict case ID scoping, blocking IDOR attacks.
- Immutable metadata: Candidate records are stored as `RecoveryArtifactRecord` with explicit `validation_state`, `output_hash`, `source_evidence_id`, and `evidence_confidence_score`.

---

## H. Existing Audit Integration (`forensic_vault.py:CaseManager`)

- **Audit Chain Structure**: Cryptographically linked sequential SHA-256 hash-chained ledger.
- Event structure: `event_id`, `sequence_number`, `timestamp`, `actor`, `event_type`, `canonical_payload`, `previous_hash`, `current_hash`.
- Real-time audit events emitted for `RECOVERY_SCAN`, `FRAGMENT_RECONSTRUCTED`, `CANDIDATE_EXTRACTED`, `VALIDATION_RUN`, `CERTIFICATE_GENERATED`.

---

## I. Existing Certificate Integration (`certificate_engine.py`)

- Dual NIST-profile certificate issuance bound to case audit chain.
- PDF 1.4 generation without external libraries (`PurePythonPDFWriter`).
- Cryptographic attestation token: HMAC-SHA256 signature binding certificate ID, case ID, method ID, post-wipe/extracted hash, and prior audit node hash.

---

## J. Existing Performance & Resource Controls (`performance_lab.py`)

- Dual-signal memory monitoring: Python heap via `tracemalloc` + OS Process RSS via `psutil`/Windows API.
- Bounded streaming invariant: Fixed 64 KB memory chunks for hash/verification operations.
- Resource safety limits: Max dataset size 100 MB, max iterations 50, max candidate caps.

---

## K. Current Method States

- **M21 (Deep Sector Carving)**: `PARTIAL / LIMITED` — Live Python `DeepCarverEngine` + PhotoRec adapter.
- **M22 (Fragment Recovery)**: `PARTIAL / LIMITED` — Non-contiguous seam reassembly, JPEG restart marker parser, ZIP delta clusterer.
- **M23 (RAID Array Reconstruction)**: `UNSUPPORTED / HARDWARE_REQUIRED` — Degraded XOR virtual reconstruction for disk images; physical arrays require hardware controller pass-through.
- **M24 (Damaged Media Recovery)**: `BACKEND_UNAVAILABLE / HARDWARE_REQUIRED` — GNU ddrescue clean-room mapfile parser/merger implemented; physical execution requires native backend and write-blocker hardware.

---

## L. Gaps Identified for Phase 16 Deepening

1. **Filesystem Metadata Provenance**: Need explicit `metadata_source` attribution (e.g. `NTFS_MFT`, `FAT_DIRECTORY_ENTRY`, `EXT_INODE`, `CARVED`, `INFERRED`, `UNKNOWN`) and distinction between available, inferred, and unknown metadata.
2. **Filesystem-Independent Stream Recovery Pipeline**: Direct block/sector stream signature & structure extractor decoupled from filesystem assumptions.
3. **Advanced Carving Format Profiles**: Explicit footer/end-marker extraction, format constraints, and malformed header rejection for JPEG, PNG, PDF, SQLite, ZIP.
4. **Fragment Graph Representation**: Explicit bounded graph with explainable edge evidence (`offset_distance`, `entropy_continuity`, `byte_boundary_continuity`, `format_constraint`) avoiding $O(n^2)$ combinatorial explosion on large fragment sets.
5. **Candidate Deduplication & Fusion**: Cryptographic identity (SHA-256 + source range + format) and multi-source corroboration without destroying individual provenance.
6. **Damaged Media Clean Architecture**: Clean adapter interface for future imaging backends with read-only source immutability guarantees.
7. **Resource Bounds**: Explicit `RESOURCE_LIMIT_REACHED` reporting when scan size, candidate count, fragment count, or processing time exceeds thresholds.

---

## M. Duplicate Functionality That Must NOT Be Rewritten

- DO NOT rewrite existing `validators/` (JPEG, PNG, PDF, SQLite, ZIP, etc.) — extend or consume them.
- DO NOT rewrite `forensic_vault.py` storage layout, case managers, or hashing engine.
- DO NOT rewrite `certificate_engine.py` or PDF generator.
- DO NOT rewrite `JobRegistry` or background job worker model.
- DO NOT rewrite the 25-method matrix or qualification evaluator.
- DO NOT modify frozen Phase 11–15 truth semantics.

---

## N. Exact Files Proposed for Phase 16 Deepening

1. **`fs_base.py` & `fs_recovery.py`**:
   - Add `MetadataSource` enum (`NTFS_MFT`, `FAT_DIRECTORY_ENTRY`, `EXT_INODE`, `CARVED`, `INFERRED`, `UNKNOWN`).
   - Add provenance annotations to `FsCandidateRecord`.
2. **`carver_engine.py`**:
   - Enhance `DeepCarverEngine` with explicit format-specific structural boundary extractors, resource limit guards (`CarveResourceLimits`), and candidate fusion metadata.
3. **`fragment_engine.py`**:
   - Add `FragmentGraph` representation with bounded edge weights and explainable edge evidence.
   - Add candidate deduplication and fusion utilities.
4. **`drex_server.py`**:
   - Connect recovery scan, carving, candidate listing, fragment graph reconstruction, and candidate promotion endpoints with enhanced provenance and candidate fusion.
5. **`damaged_media.py`**:
   - Add read-only adapter interface for future imaging backends while preserving `BACKEND_UNAVAILABLE / HARDWARE_REQUIRED` truth state.
6. **`tests/`**:
   - Create 5 dedicated Phase 16 test suites:
     - `tests/test_phase16_recovery_engine.py`
     - `tests/test_phase16_carving.py`
     - `tests/test_phase16_fragments.py`
     - `tests/test_phase16_provenance.py`
     - `tests/test_phase16_resource_limits.py`
7. **`docs/PHASE_16_IMPLEMENTATION_REPORT.md`**:
   - Comprehensive documentation of all Phase 16 forensic recovery implementations and validation results.
