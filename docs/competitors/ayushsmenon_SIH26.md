# COMPETITOR FORENSIC AUDIT: ForensiX (C++17)

## 1. Repository Identity & Metadata
- **Repository**: `ayushsmenon/SIH26`
- **Primary Language / Framework**: C++17 (MSVC / MinGW-w64) / Win32 API
- **License**: MIT
- **Provenance & Upstream Pedigree**: Original work by Ayush Menon & team
- **Reality Status**: `SOURCE_PROVEN`
- **Audit Confidence Level**: `VERY HIGH`

---

## 2. Architecture & Call-Flow Analysis
- **System Architecture**: Native C++17 Windows workstation interacting directly with Win32 storage APIs without middleware.
- **Core Algorithms & Techniques**: NTFS $Bitmap acceleration, NVMe IOCTL sanitize, bi-fragment gap recovery, HMAC-SHA256 parity vault, ReadDirectoryChangesW live watcher.

---

## 3. Technical Capabilities Breakdown

### A. Recovery Capabilities
- Raw sector scan with NTFS $Bitmap unallocated cluster skipping via `FSCTL_GET_VOLUME_BITMAP`, bi-fragment carving, $MFT and $UsnJrnl activity parsing.

### B. Sanitization Capabilities
- NVMe hardware sanitize via `IOCTL_STORAGE_PROTOCOL_COMMAND`, ATA pass-through, slack space scrubbing.

### C. Hardware & Storage Support
- Direct `\\.\PhysicalDrive` access with write-blocker verification.

### D. Evidence, Audit & Certification
- HMAC-SHA256 parity vault (`.forensic_parity.vault`), hash-chained audit log, dual SHA-256 + FNV-1a64 manifests.

### E. User Interface & Experience
- High-performance CLI.

### F. Testing & Quality Assurance
- C++ unit tests with mock sector buffers.

---

## 4. Forensic Evaluation

### Strengths
- Direct Win32 $Bitmap acceleration (fast unallocated scanning), native NVMe IOCTL, HMAC parity vault.

### Weaknesses & Limitations
- CLI only, Windows-specific Win32 dependencies.

---

## 5. DREX-V2 Lessons & Integration Strategy
- **Key Lessons for DREX-V2**: Incorporate NTFS $Bitmap acceleration and NVMe IOCTL into DREX native C++ modules.
- **Reusable Code / Components**: NTFS $Bitmap volume allocation skipping logic and NVMe IOCTL pass-through.
- **Integration Decision**: `REFACTOR_INTO_DREX`
