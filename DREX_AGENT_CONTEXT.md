# DREX-V2 AGENT CONTEXT & OPERATIONAL KNOWLEDGE BASE

## 1. Project Mission & Identity
**DREX-V2** is an integrated, government-grade platform for **Secure Storage Data Erasure** and **Advanced Forensic File Recovery** engineered for digital forensics, incident response, and media sanitization.

### Dual Core Mandates:
1. **Destructive Track (Secure Data Erasure)**: Complete, unrecoverable data elimination compliant with NIST SP 800-88 Rev. 2, DoD 5220.22-M, and IEEE 2883 standards, aware of Flash Translation Layers (FTL), overprovisioning, and wear-leveling reserves.
2. **Read-Only Track (Forensic File Recovery)**: Deep sector carving, filesystem reconstruction, fragment reassembly, and damaged media imaging without contaminating or altering the underlying suspect storage media.

---

## 2. Absolute Engineering Truth Model
DREX enforces strict, non-negotiable classification across every subsystem:
- **`REAL` / `SOURCE_PROVEN`**: Directly executed against live hardware or filesystem primitives with byte-for-byte readback verification.
- **`SYNTHETIC`**: Executed against synthetic virtual test disk images (`.img`, `.raw`, RAM-backed loopback) with controlled assertions.
- **`SIMULATED`**: Algorithmic decision engine or policy calculation; explicitly labeled and never represented as hardware write.
- **`PARTIAL`**: Operations where a subset of data or capabilities succeeded, with unrecovered or unverified sectors explicitly recorded.
- **`UNSUPPORTED`**: Hardware or OS capabilities unavailable (e.g., USB bridges blocking ATA/NVMe CDBs, missing RAID arrays).
- **`BACKEND_UNAVAILABLE`**: Missing official native binaries (e.g., ddrescue on Windows).
- **`FAILED`**: Explicit failure with recorded error code.
- **`FAIL CLOSED`**: When capability, destination safety, or verification cannot be established, the operation halts immediately.

---

## 3. The 25 DREX Methods Architecture

### Drive Sanitization (Methods 1–7)
1. **NIST SP 800-88 Rev.2**: Policy engine evaluating Clear/Purge requirements based on media type and target classification.
2. **Smart Sanitization**: Multi-tier heuristic evaluator selecting optimal sanitization routines based on device controller capabilities.
3. **Device-Native Sanitize**: Low-level controller Sanitize CDBs (`IOCTL_STORAGE_PROTOCOL_COMMAND`).
4. **ATA Secure Erase / Enhanced Erase**: Direct ATA command set pass-through for magnetic and legacy SATA media.
5. **NVMe Secure Erase / Cryptographic Purge**: Scrambles or purges AES media encryption keys via NVMe controller primitives.
6. **IEEE 2883 Purge**: Purge compliance policy for magnetic and solid-state storage.
7. **Verified Overwrite**: Multi-pass pattern overwrite with real readback byte verification.

### File & Folder Sanitization (Methods 8–16)
8. **CSPRNG Random Overwrite**: Cryptographic random byte stream overwrite via `os.urandom` / Win32 `BCryptGenRandom`.
9. **Cryptographic Erasure**: Envelope encryption key purging rendering ciphertext irrecoverable.
10. **File Slack / Cluster-Tip Zeroing**: Scrubs unallocated cluster residues between logical EOF and physical cluster boundary.
11. **Filesystem Metadata Sanitization**: Scrubs directory entries, MFT file record names, and timestamps.
12. **NIST SP 800-88 Policy Engine**: File-level Clear vs Purge decision matrix.
13. **Secure Free-Space Wiping**: Zeroes or scrambles unallocated volume blocks without altering active allocated files.
14. **Single-Pass Zero Overwrite**: High-speed single-pass zero fill.
15. **Storage-Aware Fallback**: Automated fallback matrix adapting file erasure strategies to detected storage geometry.
16. **Temporary / Cache Sanitization**: Discovery and shredding of browser caches, temp files, and OS swap residues.

### Forensic Recovery (Methods 17–25)
17. **Quick Recovery**: Rapid filesystem traversal leveraging TSK (`fls.exe` + `icat.exe`) for deleted directory entries.
18. **Smart Recovery**: Triaged analysis combining filesystem traversal (`fsstat`, `fls`) with automated file export.
19. **Targeted Recovery**: Specific inode / cluster extraction for targeted digital evidence artifacts.
20. **Filesystem Recovery**: Full partition file tree reconstruction via `tsk_recover.exe`.
21. **Deep Recovery**: Raw signature block carving bypassing corrupted filesystems via PhotoRec / pure-Python carvers.
22. **Fragment Recovery**: Non-contiguous out-of-order fragment reassembly (JPEG MCU stream decoder, bi-fragment gap search).
23. **RAID / Storage Recovery**: Multi-disk stripe reassembly and parity reconstruction.
24. **Damaged Media Recovery**: Multi-pass imaging with bad-sector mapfile tracking (ddrescue / adaptive readback).
25. **Forensic Recovery**: End-to-end chain of custody recovery with dual-hashing (SHA-256 / Blake3) and evidence ledger logging.

---

## 4. Reused Competitor Code & Provenance Strategy
DREX-V2 actively incorporates premier implementations from target SIH repositories:
- **AKHANDA** (*pulkit6732/AKHANDA* — Apache-2.0): Fragment reassembly (`reassemble.py`), ZIP container parsing (`zipcarve.py`), and witness node co-signing.
- **SecureForge** (*K01SR/SecureForge* — MIT): RFC 3161 digital timestamping token generation, Shannon entropy sector scanner ($0.000$ to $7.999$ b/B), and extensible chunk carver.
- **Resurgence** (*MithunRayakota07/resurgence-forensics*): Out-of-order JPEG MCU boundary reassembly and MFT resident residue detection.
- **ForensiX** (*ayushsmenon/SIH26* — C++17): Direct NTFS `$Bitmap` cluster skipping (`FSCTL_GET_VOLUME_BITMAP`) and NVMe IOCTL pass-through.
- **DataShield** (*Vigneshe247/Secure-Data-Erasure-Recovery*): 5-Factor mathematical confidence formula:
  $$\text{Confidence} = 0.35 \times \text{SigMatch} + 0.25 \times \text{Structure} + 0.20 \times \text{Continuity} + 0.15 \times \text{Metadata} + 0.05 \times \text{Size}$$
  and 4-state verification verdict (`PASSED`, `PASSED_WITH_WARNING`, `FAILED`, `INCONCLUSIVE`).
- **EraseXperts** (*Prithiv04/EraseXperts* — MIT): VSS shadow copy purging (`kill_vss_shadows()`) and quantum random entropy.

---

## 5. UI Architecture & Design Directives
- **Workstation Aesthetic**: Professional blue forensic workstation palette (`#007AFF`, `#111827`, `#F5F5F7`, `#FFFFFF`).
- **Layout**: Top workstation bar (case switcher, drive selector, role badge), persistent left navigation (25 specialized pages), breadcrumbs, technical cards, and live progress bars.
- **Evidence Language**: All pages use forensic terminology (Target LBA, Inode, Sector Offset, Entropy, SHA-256 Hash, Chain ID).
- **Safety Safeguards**: Confirmation modal with required confirmation phrase before executing destructive operations.
