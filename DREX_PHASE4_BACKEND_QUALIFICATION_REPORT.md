# DREX-V2 Phase 4 Hardening: Forensic Recovery Backend Qualification Report

**Document Version:** Phase 4 Hardened Evidence Baseline  
**Repository Branch:** `main`  
**Current Checkpoint:** `d147fb09`  
**Automated Regression Suite:** **430 / 430 PASS (100% GREEN, 0 FAILED, 0 SKIPPED)**  
**Runtime:** 115.87s  
**Authoritative Architectural Principle:**  
> **Mature Forensic Software is the Execution Engine.**  
> **DREX is the Independent Assurance, Validation & Provenance Engine.**

---

## 1. Existing Backend Inventory & Discovery

DREX strictly invokes verified, locally discovered native executables residing in `native_bin/` or the system PATH. Zero runtime package downloads or unverified external scripts are executed.

| Backend Identifier | Binary Path | Version | Detected | License / Provenance | Current DREX Role | Tested Live |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **The Sleuth Kit (TSK)** | `native_bin/fls.exe` | 4.15.0 | **YES** | IPL 1.0 / CPL 1.0 / GPL v2 | Directory metadata & deleted entry scan | **YES** |
| **The Sleuth Kit (TSK)** | `native_bin/icat.exe` | 4.15.0 | **YES** | IPL 1.0 / CPL 1.0 / GPL v2 | Targeted inode data stream extraction | **YES** |
| **The Sleuth Kit (TSK)** | `native_bin/fsstat.exe` | 4.15.0 | **YES** | IPL 1.0 / CPL 1.0 / GPL v2 | Filesystem geometry & cluster layout analysis | **YES** |
| **The Sleuth Kit (TSK)** | `native_bin/mmls.exe` | 4.15.0 | **YES** | IPL 1.0 / CPL 1.0 / GPL v2 | Volume layout & partition table inspection | **YES** |
| **The Sleuth Kit (TSK)** | `native_bin/tsk_recover.exe` | 4.15.0 | **YES** | IPL 1.0 / CPL 1.0 / GPL v2 | Batch allocated & deleted file export | **YES** |
| **PhotoRec / TestDisk** | `native_bin/fidentify_win.exe`| 7.2 (Feb 2024) | **YES** | GNU GPL v2 (CGSecurity) | 480+ format family reference identification | **YES** |
| **PhotoRec** | `native_bin/photorec_win.exe`| 7.2 (Feb 2024) | **YES** | GNU GPL v2 (CGSecurity) | Unallocated carving (`WinError 740` elevation-gated) | **DETECTED** |
| **TestDisk** | `native_bin/testdisk_win.exe`| 7.2 (Feb 2024) | **YES** | GNU GPL v2 (CGSecurity) | Partition table analysis (interactive only) | **DETECTED** |
| **DREX Custom Engine** | `recovery_adapter.py` / `carver_engine.py` | 2.0 Hardened | **YES** | Apache 2.0 | Assurance, format validation & vault persistence | **YES** |

---

## 2. Layered Architecture: Execution Engine vs. Assurance Engine

DREX never fabricates recovery attribution. When an external tool performs extraction, DREX attributes the backend truthfully and provides independent post-extraction validation.

```
                  ┌──────────────────────────────────────────────────────────┐
                  │                 DREX SAFETY & ORCHESTRATION              │
                  │  - Read-only source target verification                  │
                  │  - Destination path isolation & anti-traversal           │
                  │  - Source size & SHA-256 pre-execution recording         │
                  └─────────────────────────────┬────────────────────────────┘
                                                │
                                                ▼
                  ┌──────────────────────────────────────────────────────────┐
                  │          MATURE FORENSIC RECOVERY EXECUTION ENGINE       │
                  │  - The Sleuth Kit 4.15.0 (tsk_recover, icat, fls)        │
                  │  - PhotoRec 7.2 (fidentify, photorec)                    │
                  │  - DREX Native Filesystem Parser (FAT, NTFS, Ext4)       │
                  └─────────────────────────────┬────────────────────────────┘
                                                │ Recovered Artifacts
                                                ▼
                  ┌──────────────────────────────────────────────────────────┐
                  │           DREX INDEPENDENT STRUCTURAL VALIDATION         │
                  │  - FormatRegistry header & footer signature matching     │
                  │  - Structural parser (JPEG RST, PNG IDAT, PDF xref, ZIP) │
                  │  - SHA-256 digest calculation & extents computation      │
                  └─────────────────────────────┬────────────────────────────┘
                                                │ Validated Artifacts
                                                ▼
                  ┌──────────────────────────────────────────────────────────┐
                  │                 DREX FORENSIC ASSURANCE VAULT            │
                  │  - Categorized object isolation (RECOVERED, SOURCE)      │
                  │  - Cryptographically hash-linked audit chain             │
                  │  - Case attribution: "Recovered by backend; DREX-proven" │
                  └──────────────────────────────────────────────────────────┘
```

---

## 3. Authoritative 20-Format Evidence-Backed Capability Matrix

This matrix distinguishes **Format Identification**, **Structural Validation**, **Actual Carving**, **Filesystem Recovery**, and **Fragment Reconstruction** for all 20 Phase 4 formats.

| Format | DREX Magic Signature | DREX Structural Validator | DREX Actual Carving | TSK Filesystem Recovery | PhotoRec / fidentify Identification | PhotoRec Actual Carving | Fragment Reconstruction | DREX Independent Validation | Evidence & Test Reference | Final Status |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **JPEG** | `\xFF\xD8\xFF` | `JpegValidator` (SOI/DQT/SOF/SOS/EOI) | `DeepCarverEngine` | `tsk_recover` / `icat` | `fidentify` (`jpg`) | Elevation-gated | `JpegEntropyDecoder` (RST/MCU) | `FormatRegistry` (`RECOVERED_ARTIFACT`) | `test_phase4_carver_comprehensive.py`, `test_phase4_backend_qualification.py` | **TEST-VERIFIED** |
| **PNG** | `\x89PNG\r\n\x1a\n` | `PngValidator` (CRC32/Decompress) | `DeepCarverEngine` | `tsk_recover` / `icat` | `fidentify` (`png`) | Elevation-gated | Multi-IDAT stream reassembly | `FormatRegistry` (`RECOVERED_ARTIFACT`) | `test_phase4_carver_comprehensive.py`, `test_phase4_backend_qualification.py` | **TEST-VERIFIED** |
| **PDF** | `%PDF-` | `PdfValidator` (xref/trailer/%%EOF) | `DeepCarverEngine` | `tsk_recover` / `icat` | `fidentify` (`pdf`) | Elevation-gated | Bounded object permutation | `FormatRegistry` (`RECOVERED_ARTIFACT`) | `test_phase4_carver_comprehensive.py`, `test_phase4_backend_qualification.py` | **TEST-VERIFIED** |
| **ZIP** | `PK\x03\x04` | `ZipValidator` (Local/Central/EOCD) | `DeepCarverEngine` | `tsk_recover` / `icat` | `fidentify` (`zip`) | Elevation-gated | `ZipCarveStream` (AKHANDA delta) | `FormatRegistry` (`RECOVERED_ARTIFACT`) | `test_phase4_carver_comprehensive.py`, `test_fragment_engine.py` | **TEST-VERIFIED** |
| **DOCX** | `PK\x03\x04` | `OoxmlValidator` ([Content_Types].xml)| `DeepCarverEngine` | `tsk_recover` / `icat` | `fidentify` (`zip/docx`)| Elevation-gated | ZIP delta reassembly | `FormatRegistry` (`RECOVERED_ARTIFACT`) | `test_phase4_carver_comprehensive.py` | **TEST-VERIFIED** |
| **XLSX** | `PK\x03\x04` | `OoxmlValidator` (xl/workbook.xml) | `DeepCarverEngine` | `tsk_recover` / `icat` | `fidentify` (`zip/xlsx`)| Elevation-gated | ZIP delta reassembly | `FormatRegistry` (`RECOVERED_ARTIFACT`) | `test_phase4_carver_comprehensive.py` | **TEST-VERIFIED** |
| **PPTX** | `PK\x03\x04` | `OoxmlValidator` (ppt/presentation.xml)| `DeepCarverEngine`| `tsk_recover` / `icat` | `fidentify` (`zip/pptx`)| Elevation-gated | ZIP delta reassembly | `FormatRegistry` (`RECOVERED_ARTIFACT`) | `test_phase4_carver_comprehensive.py` | **TEST-VERIFIED** |
| **MP4** | `ftyp` (offset 4) | `Mp4Validator` (Box atom consistency)| `DeepCarverEngine` | `tsk_recover` / `icat` | `fidentify` (`mp4`) | Elevation-gated | Atom box sequence bounds | `FormatRegistry` (`RECOVERED_ARTIFACT`) | `test_phase4_carver_comprehensive.py` | **TEST-VERIFIED** |
| **MOV** | `ftypqt  ` / `moov` | `Mp4Validator` (QuickTime atoms) | `DeepCarverEngine` | `tsk_recover` / `icat` | `fidentify` (`mov`) | Elevation-gated | Atom box sequence bounds | `FormatRegistry` (`RECOVERED_ARTIFACT`) | `test_phase4_carver_comprehensive.py` | **TEST-VERIFIED** |
| **AVI** | `RIFF....AVI ` | `RiffValidator` (RIFF + AVI form) | `DeepCarverEngine` | `tsk_recover` / `icat` | `fidentify` (`avi`) | Elevation-gated | Chunk length bounds | `FormatRegistry` (`RECOVERED_ARTIFACT`) | `test_phase4_carver_comprehensive.py` | **TEST-VERIFIED** |
| **WAV** | `RIFF....WAVE` | `RiffValidator` (RIFF + WAVE form) | `DeepCarverEngine` | `tsk_recover` / `icat` | `fidentify` (`wav`) | Elevation-gated | Chunk length bounds | `FormatRegistry` (`RECOVERED_ARTIFACT`) | `test_phase4_carver_comprehensive.py` | **TEST-VERIFIED** |
| **MP3** | `ID3` / Sync `\xFF\xFB`| `Mp3Validator` (ID3v2 + MPEG Sync) | `DeepCarverEngine` | `tsk_recover` / `icat` | `fidentify` (`mp3`) | Elevation-gated | Frame sync sequence bounds | `FormatRegistry` (`RECOVERED_ARTIFACT`) | `test_phase4_carver_comprehensive.py` | **TEST-VERIFIED** |
| **GIF** | `GIF87a` / `GIF89a` | `GifValidator` (LSD + 0x3B trailer) | `DeepCarverEngine` | `tsk_recover` / `icat` | `fidentify` (`gif`) | Elevation-gated | Block terminator bounds | `FormatRegistry` (`RECOVERED_ARTIFACT`) | `test_phase4_carver_comprehensive.py` | **TEST-VERIFIED** |
| **BMP** | `BM` | `BmpValidator` (Header size + DIB) | `DeepCarverEngine` | `tsk_recover` / `icat` | `fidentify` (`bmp`) | Elevation-gated | Declared size bounds | `FormatRegistry` (`RECOVERED_ARTIFACT`) | `test_phase4_carver_comprehensive.py` | **TEST-VERIFIED** |
| **TIFF** | `II*\x00` / `MM\x00*` | `TiffValidator` (Endian + IFD0 table)| `DeepCarverEngine` | `tsk_recover` / `icat` | `fidentify` (`tif`) | Elevation-gated | IFD linked-list bounds | `FormatRegistry` (`RECOVERED_ARTIFACT`) | `test_phase4_carver_comprehensive.py` | **TEST-VERIFIED** |
| **SQLite** | `SQLite format 3\x00`| `SqliteValidator` (Page Size/B-Tree)| `DeepCarverEngine` | `tsk_recover` / `icat` | `fidentify` (`sqlite`)| Elevation-gated | B-Tree page traversal bounds | `FormatRegistry` (`RECOVERED_ARTIFACT`) | `test_phase4_carver_comprehensive.py` | **TEST-VERIFIED** |
| **ELF** | `\x7fELF` | `ElfValidator` (Header + Section table)| `DeepCarverEngine`| `tsk_recover` / `icat` | `fidentify` (`elf`) | Elevation-gated | Section table offset bounds | `FormatRegistry` (`RECOVERED_ARTIFACT`) | `test_phase4_carver_comprehensive.py` | **TEST-VERIFIED** |
| **PE** | `MZ` / `PE\0\0` | `PeValidator` (NT Header + Sections) | `DeepCarverEngine` | `tsk_recover` / `icat` | `fidentify` (`exe`) | Elevation-gated | SizeOfImage section bounds | `FormatRegistry` (`RECOVERED_ARTIFACT`) | `test_phase4_carver_comprehensive.py` | **TEST-VERIFIED** |
| **7Z** | `7z\xbc\xaf\x27\x1c` | `SevenZipValidator` (Header CRC/Offset)| `DeepCarverEngine` | `tsk_recover` / `icat` | `fidentify` (`7z`) | Elevation-gated | Next header offset bounds | `FormatRegistry` (`RECOVERED_ARTIFACT`) | `test_phase4_carver_comprehensive.py` | **TEST-VERIFIED** |
| **RAR** | `Rar!\x1a\x07\x00` | `RarValidator` (Block CRC + Header) | `DeepCarverEngine` | `tsk_recover` / `icat` | `fidentify` (`rar`) | Elevation-gated | Block header CRC chain | `FormatRegistry` (`RECOVERED_ARTIFACT`) | `test_phase4_carver_comprehensive.py` | **TEST-VERIFIED** |

---

## 4. TSK Differential Validation & Filesystem Recovery

### Differential Validation Status:
> **EXACT_MATCH on the tested FAT32 and EXT4 deterministic fixtures, for the allocated, unallocated, and orphan cases represented by those fixtures.**

- **FAT32 Image (`fat32.img`):**
  - Live `tsk_recover.exe -e`: Successfully extracted active files (`Forensic_Evid`, 610 B), deleted files (`deleted_audit`, 945 B), and fragmented chains (`fragmented.bi`, 4736 B).
  - Live `icat.exe 4`: Extracted active document stream byte-for-byte identical to DREX native parser (`EXPECTED_SHA256 == RECOVERED_SHA256`).
  - Live `fls.exe -r -p -d`: Discovered deleted directory entries with exact `*` deletion markers matching DREX.
- **EXT4 Image (`ext4.img`):**
  - Live `tsk_recover.exe -e`: Successfully recovered orphan extent files (`$OrphanFiles/OrphanFile-11`, `$OrphanFiles/OrphanFile-12`, `$OrphanFiles/OrphanFile-13`).
  - Live `icat.exe 11`: Extracted inode 11 data stream byte-for-byte identical to DREX native extent tree parser.
- **exFAT Image (`exfat.img`):**
  - Live TSK differential validation truthfully reports `REFERENCE_UNAVAILABLE` (standard TSK lacks native exFAT parser support; DREX native parser recovers exFAT active/deleted streams independently).

---

## 5. PhotoRec & TestDisk Qualification Status

- **`fidentify_win.exe` (PhotoRec 7.2 Format Identifier):**
  - **Status:** **TEST-VERIFIED**
  - Executable discovered at `native_bin/fidentify_win.exe`.
  - Version verified: `fidentify 7.2, Data Recovery Utility, February 2024 (Christophe GRENIER)`.
  - Tested live against JPEG, PNG, and PDF fixtures; correctly recognized format signatures matching DREX format identifiers.
- **`photorec_win.exe` (PhotoRec 7.2 File Carver):**
  - **Status:** **BACKEND_AVAILABLE / ELEVATION_REQUIRED (Unattended carving qualification pending)**
  - Executable discovered at `native_bin/photorec_win.exe`.
  - Windows application manifest embeds `requestedExecutionLevel=highestAvailable`. On non-elevated command prompts, Windows blocks execution with `WinError 740: The requested operation requires elevation`.
  - DREX handles this safely via fallback to DREX native structure-aware carver (`DeepCarverEngine`) and reports elevation requirements truthfully.
- **`testdisk_win.exe` (TestDisk 7.2):**
  - **Status:** **DETECTED / INTERACTIVE_ONLY**
  - Interactive ncurses console application; non-interactive unattended CLI automation is unsupported by upstream.

---

## 6. DREX Independent Assurance Pipeline

Every artifact recovered by a mature backend (`tsk_recover.exe`, `icat.exe`) or carved by `DeepCarverEngine` passes through DREX's validation pipeline:

1. **Byte Acquisition & Cryptographic Hashing:** Computes SHA-256 digest on extracted artifact.
2. **Format Identification:** Identifies format using magic bytes and file extensions via `FormatRegistry`.
3. **Structural & Semantic Validation:** Executes modular format validator (e.g. `JpegValidator`, `PngValidator`, `PdfValidator`, `ZipValidator`).
4. **Attribution & Categorized Isolation:** Stores artifact in `EvidenceVault` as `VaultObjectType.RECOVERED` with explicit attribution:
   `"Recovered by The Sleuth Kit 4.15.0 (tsk_recover.exe); independently validated by DREX."`
5. **Cryptographically Hash-Linked Audit Event:** Emits `RECOVERY_COMPLETED` event bound to the unbroken SHA-256 audit ledger:
   $$H_N = \text{SHA-256}(H_{N-1} \parallel \text{CanonicalJSON}(\text{Event}_N))$$

---

## 7. Source Immutability & Safety Enforcements

### A. Source Immutability ($\Delta \text{Hash} \equiv 0$, $\Delta \text{Size} \equiv 0$)
- Pre-execution source image SHA-256 and byte size are recorded before backend execution.
- Post-execution source image SHA-256 and byte size are verified after backend execution.
- **Result:** `source_sha256_before == source_sha256_after` and `source_size_before == source_size_after` across 100% of test runs (zero bytes altered on source images).

### B. Safety & Path Isolation
- Rejection of identical source/destination paths (`RecoveryError`).
- Rejection of destination directories nested inside source hierarchies.
- Rejection of source paths nested inside destination directories.
- Zero raw shell string construction (argument token lists passed directly to OS subprocess API).

---

## 8. Exact Automated Pytest Regression Results

```
============================= test session starts =============================
platform win32 -- Python 3.14.3, pytest-9.1.1, pluggy-1.6.0
rootdir: D:\drex-v2-main
configfile: pytest.ini
collected 430 items

........................................................................ [ 16%]
........................................................................ [ 33%]
........................................................................ [ 50%]
........................................................................ [ 66%]
........................................................................ [ 83%]
......................................................................   [100%]

430 passed in 115.87s (0:01:55)
```

- **Total Test Cases:** **430**
- **Passed:** **430 (100% PASS)**
- **Failed:** **0**
- **Skipped:** **0**
- **Regressions:** **0**

---

## 9. Final Defensible Qualification Statements

| Domain | Qualification Statement |
| :--- | :--- |
| **SOFTWARE IMPLEMENTATION** | **PROVEN within implemented scope** |
| **AUTOMATED ACCEPTANCE** | **430 / 430 PASS (100% GREEN)** |
| **FORENSIC IMAGE QUALIFICATION** | **PROVEN within the defined deterministic test matrix** |
| **TSK DIFFERENTIAL VALIDATION** | **EXACT MATCH for tested cases, with reference-unavailable limitations explicitly recorded** |
| **PHOTOREC QUALIFICATION** | **Backend available; reference format identification test-verified via fidentify; unattended batch carving qualification pending (elevation-gated on Windows)** |
| **DREX ASSURANCE** | **INDEPENDENT VALIDATION where the actual pipeline demonstrates it** |
| **PHYSICAL MEDIA QUALIFICATION** | **NOT ESTABLISHED (No physical drive hardware lab attached; software qualification maximized on deterministic forensic images)** |
| **UNIVERSAL RECOVERY** | **NOT CLAIMED** |
