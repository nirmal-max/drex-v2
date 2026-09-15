# DREX Phase 19.2 &middot; SIH26149 Repository UX Benchmark

**Document Reference:** `PHASE19_2_REPO_UX_BENCHMARK.md`  
**Phase:** Phase 19.2 &mdash; UX Fusion / Forensic Workstation UX MAX  
**Benchmark Date:** 2026-09-15  
**Standards:** ISO/IEC 27037:2012, NIST SP 800-88 Rev. 2, NIST SP 800-86  

---

## 1. Executive Summary

To elevate DREX into the definitive, most intuitive, trustworthy, and efficient forensic workstation, we conducted an in-depth UX audit of all available SIH26149 and upstream open-source forensic and sanitization codebases:
1. **AKHANDA** (`repo/AKHANDA-main`) &mdash; Custody console, ledger verification, Merkle tamper detection.
2. **BleachBit** (`repo/bleachbit-master`) &mdash; Deep clean tree traversal, file/folder shredding, preview/delete action separation.
3. **DriveWipe** (`repo/DriveWipe-main`) &mdash; Kernel ATA/NVMe sanitization, safety lockouts, live terminal progress.
4. **Eraser** (`repo/eraser-master`) &mdash; Windows context shredder, scheduler, multi-pass method configuration.
5. **The Sleuth Kit (TSK)** (`repo/sleuthkit-develop-4.1x`) &mdash; Inode analysis, directory tree reconstruction, partition tables.
6. **TestDisk / PhotoRec** (`repo/testdisk-master`) &mdash; Interactive terminal sector carving, file format magic recognition.
7. **NVMe-CLI** (`repo/nvme-cli-master`) &mdash; Low-level NVMe Format/Sanitize opcodes, namespace management.
8. **libfsntfs** (`repo/libfsntfs-main`) &mdash; NTFS $MFT parsing, alternate data streams, attribute parsing.

---

## 2. Detailed Repository UX Benchmarks

### 2.1 AKHANDA (`repo/AKHANDA-main`)
- **UI Framework:** Vanilla HTML/CSS/JS (`console-app`) & React/TypeScript Tailwind (`frontend`).
- **Navigation Approach:** Left rail navigation with keyboard shortcuts (`1` to `4`), pinned footer showing source and monotonic clock.
- **Dashboard Approach:** Status strip (`.strip`) with key-value cells (`.cell`): Chain, Entries, Head, Custody Tier, Witness status, Integrity LED.
- **Evidence UX:** Side-by-side hash comparison table (Original SHA-256 vs Carved SHA-256), high-density `.stats` grid (`630 tests pass`, `11/11 automation checks`).
- **Recovery UX:** Clean table with sequence numbers, operation, method, outcome, custody tier badge, entry hash, and timestamp.
- **Disk / File Selection:** Drag-and-drop `.json` chain dropzone with fallback file input.
- **Progress & Verification UX:** Live in-browser WebCrypto digest verification with interactive tamper demonstration (`[ Alter selected entry ]` &rarr; instant red hash chain break).
- **Error & Refusal UX:** Dedicated "Refused Entry" badge (`REFUSED`) for operations blocked by witness unreachability.
- **Visual Strengths:** High contrast, calm muted color palette (`--bg: #F1F2F0`, `--rail: #20241F`, `--ok: #1F6B45`), monospace tabular numbers.
- **Interaction Strengths:** Live interactive tamper sandbox that proves cryptographic integrity in real time.
- **Weaknesses:** Single monolithic file format (`chain.json`), lack of physical disk enumeration, lack of live disk imaging.
- **Reusable Ideas for DREX:**
  - Compact status strip with active case, evidence count, and integrity LED.
  - High-density stats box grid for test validation metrics.
  - Interactive cryptographic verification feedback.

---

### 2.2 BleachBit (`repo/bleachbit-master`)
- **UI Framework:** Python GTK3 desktop interface.
- **Navigation Approach:** Hierarchical category tree (System, Firefox, Chrome, Windows Explorer) with select-all checkboxes.
- **File / Folder Selection:** Dedicated menu actions for "Shred Files" (`<input type="file" multiple>`) and "Shred Folders" (`webkitdirectory`).
- **Progress UX:** Two-phase execution: **Preview** (Dry-run scan calculating recoverable space/file count) &rarr; **Clean** (Destructive wipe).
- **Error UX:** Non-modal log panel listing locked or in-use files without crashing the process.
- **Visual Strengths:** Clear separation between non-destructive analysis (Preview) and destructive action (Delete).
- **Interaction Strengths:** User always sees exact file count and total byte volume before confirming deletion.
- **Weaknesses:** Cluttered checkbox trees, lack of forensic hash chaining, no compliance certificates.
- **Reusable Ideas for DREX:**
  - Separate `○ File` vs `○ Folder` target selection.
  - Selected target metadata card showing Path, Type, File count, Total size, and Readability before execution.

---

### 2.3 DriveWipe (`repo/DriveWipe-main`)
- **UI Framework:** Rust CLI / Live Alpine Linux boot environment / TUI.
- **Disk Selection UX:** Comprehensive disk table displaying Device Path, Model, Serial, Bus Type, Capacity, System Disk status, and HPA/DCO hidden sector indicators.
- **Safety Lockouts:** Absolute exclusion of active boot and root volumes.
- **Progress UX:** High-resolution throughput counter (MB/s), elapsed/remaining time estimate, real-time sector block progress.
- **Error UX:** Detailed kernel IOCTL error diagnostics with fallback recommendations.
- **Visual Strengths:** Uncompromising danger semantics for disk-level destructive wiping.
- **Interaction Strengths:** Step-by-step confirmation gate before sending low-level ATA/NVMe sanitize opcodes.
- **Weaknesses:** Terminal/CLI only; no web or desktop UI.
- **Reusable Ideas for DREX:**
  - Device selection card displaying bus interface, sector size, and boot protection tripwires.
  - Explanatory danger dialogs with exact confirmation phrase typing.

---

### 2.4 Eraser (`repo/eraser-master`)
- **UI Framework:** C# / .NET Windows Forms desktop application.
- **Navigation Approach:** Tabbed interface (Erase Schedule, Preferences, Log).
- **Method Selection UX:** Grouped method picker (NIST 800-88, DoD 5220.22-M, Gutmann, Pseudorandom) with pass count and speed trade-off rating.
- **Visual Strengths:** Granular method customization and scheduling options.
- **Weaknesses:** Outdated Windows 98/XP aesthetic, complex nested modal dialogs.
- **Reusable Ideas for DREX:**
  - Purpose-grouped method selector with speed and coverage comparison indicators.

---

### 2.5 The Sleuth Kit & PhotoRec (`repo/sleuthkit-develop-4.1x`, `repo/testdisk-master`)
- **Navigation Approach:** Command-line tools (`fls`, `icat`, `mmls`, `photorec_win`).
- **Recovery UX:** Deep magic-byte header/footer matching across unallocated clusters, inode reconstruction.
- **Visual Strengths:** Uncompromising forensic accuracy and sector-level provenance.
- **Weaknesses:** No modern GUI; requires complex shell command syntax.
- **Reusable Ideas for DREX:**
  - Structured 6-step recovery pipeline abstracting complex TSK/Carver commands into clear UI steps.
  - Rich recovered artifact cards with 5-factor confidence decomposition.

---

## 3. Summary of Reusable UX Insights

| Feature Area | Source Repository | Best Pattern Identified | DREX Adaptation Strategy |
|:---|:---|:---|:---|
| **Top Status Strip** | AKHANDA | Compact key-value strip with integrity LED | Persistent Active Case Bar with Live Status LED |
| **System Validation** | AKHANDA | High-density `.stats` grid for test metrics | Real 949-Test Validation Dashboard with 8 Categories |
| **Target Selection** | BleachBit | Distinct File vs Folder picker with metadata preflight | Native File (`<input type="file">`) & Folder (`webkitdirectory`) cards |
| **Device Intelligence** | DriveWipe | Bus, capacity, media, and boot lock status | Storage target selector with automatic capability detection |
| **Method Comparison** | Eraser / DriveWipe | Speed, risk, and pass count comparison | Interactive `[ Compare Methods ]` matrix |
| **Recovery Provenance** | TSK / AKHANDA | Sector offsets, SHA-256 hashes, confidence | 5-Factor candidate scoring with slide-out drawer |
