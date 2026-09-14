# DREX-V2 — Phase 11 Authoritative 25-Method Qualification Matrix

**Platform:** DREX-V2 Forensic Workstation & Assurance Platform  
**Phase:** Phase 11 — Production Hardening & Reliability  
**Status:** Authoritative Evidence-Backed Qualification Matrix  
**Hardware Qualification Level:** **LIMITED / CONDITIONAL / HARDWARE_REQUIRED** (Zero Physical Drive Mutation)  
**Authoritative Plan Reference:** Phase 11 Implementation Plan Section 14  

---

## 1. Physical Hardware Qualification Reality & Boundaries

> [!IMPORTANT]
> In accordance with strict forensic integrity, scientific truthfulness, and Phase 11 Directive 2:
> **No method in this matrix is marked `HARDWARE_QUALIFIED`.**
> Physical hardware qualification requires empirical execution and oscilloscope/bus-analyzer verification on dedicated, sacrificed physical flash/magnetic storage drives.
> In the automated test and software harness, methods are classified based on empirical code and synthetic capability evidence:
> - **`SOFTWARE_QUALIFIED` / `AVAILABLE`**: Implemented, verified in software execution, but physical hardware remains `LIMITED` or `CONDITIONAL`.
> - **`PARTIAL`**: Heuristic or carving recovery without full directory-tree or multi-fragment reconstruction.
> - **`UNSUPPORTED` / `HARDWARE_REQUIRED`**: Firmware/controller native features (Device-Native Sanitize, ATA Secure Erase, NVMe Secure Erase, RAID Parser) require direct physical controller access and are not claimed as executable in software simulation.
> - **`BACKEND_UNAVAILABLE` / `HARDWARE_REQUIRED`**: External native binaries (e.g. GNU `ddrescue` on Windows) are not bundled.
> 
> System drives are permanently protected via dynamic Windows boot/system-volume tripwires (`SAFETY_BLOCKED`).

---

## 2. Canonical DREX 25-Method Qualification Matrix

| ID | Category | Canonical Method Name | Backend Engine / Component | Software Status | Physical Hardware Status | Physical Evidence in Repo | Failure Modes & Error Behavior |
|:---|:---|:---|:---|:---:|:---:|:---|:---|
| **M01** | Drive Erasure | NIST SP 800-88 Rev.2 | NIST SP 800-88r2 Policy Engine | `SOFTWARE_QUALIFIED` | `LIMITED` | None (Decision engine only) | `INVALID_MEDIA`, `POLICY_REJECT` |
| **M02** | Drive Erasure | Smart Sanitization | Multi-Tier Safety Evaluator | `SOFTWARE_QUALIFIED` | `LIMITED` | None (Policy evaluation) | `HEURISTIC_MISMATCH`, `BLOCKED` |
| **M03** | Drive Erasure | Device-Native Sanitize | Controller Native Sanitize CDB | `UNSUPPORTED` | `HARDWARE_REQUIRED` | None (USB bridge filtered) | `UNSUPPORTED_HARDWARE`, `BRIDGE_BLOCKED` |
| **M04** | Drive Erasure | ATA Secure Erase | ATA Controller 0xEF Security | `UNSUPPORTED` | `HARDWARE_REQUIRED` | None (Requires native SATA) | `FIRMWARE_LOCKED`, `SECURITY_FROZEN` |
| **M05** | Drive Erasure | NVMe Secure Erase | NVMe Format / Sanitize Admin Cmd | `UNSUPPORTED` | `HARDWARE_REQUIRED` | None (Requires native PCIe) | `NVME_UNSUPPORTED`, `ADMIN_QUEUE_TIMEOUT` |
| **M06** | Drive Erasure | IEEE 2883 Purge | IEEE 2883-2022 Policy Engine | `SOFTWARE_QUALIFIED` | `LIMITED` | None (Policy engine only) | `UNSUPPORTED_STORAGE_CLASS` |
| **M07** | Drive Erasure | Verified Overwrite | Multi-Pass Block Overwrite Engine | `SOFTWARE_QUALIFIED` | `LIMITED` | Synthetic test disks only | `READ_FAILURE`, `WRITE_FAULT`, `MISMATCH` |
| **M08** | File/Folder Erasure | CSPRNG Random Overwrite | `os.urandom` Cryptographic Stream | `SOFTWARE_QUALIFIED` | `LIMITED` | Logical file fixtures only | `BUFFER_STARVATION`, `IO_ERROR` |
| **M09** | File/Folder Erasure | Cryptographic Erasure | AES-256 Envelope Key Purge Engine | `SOFTWARE_QUALIFIED` | `CONDITIONAL` | Synthetic envelope tests | `KEY_INVALIDATION_FAILED`, `LEAK` |
| **M10** | File/Folder Erasure | File Slack / Cluster-Tip | Cluster-Tip Zeroing Engine | `SOFTWARE_QUALIFIED` | `LIMITED` | Synthetic cluster fixtures | `CLUSTER_UNMAPPED`, `LOCK_DENIED` |
| **M11** | File/Folder Erasure | Filesystem Metadata Sanitization | OS Metadata Scrub & Neutralizer | `SOFTWARE_QUALIFIED` | `CONDITIONAL` | File-backed NTFS/FAT | `MFT_LOCKED`, `DRIVER_BUSY` |
| **M12** | File/Folder Erasure | NIST SP 800-88 File Policy Engine | NIST SP 800-88 Decision Matrix | `SOFTWARE_QUALIFIED` | `LIMITED` | Policy matrix evaluation | `CLASSIFICATION_FAILURE` |
| **M13** | File/Folder Erasure | Secure Free-Space Wiping | Unallocated Filler Engine | `SOFTWARE_QUALIFIED` | `LIMITED` | Test file filler checks | `OUT_OF_SPACE`, `QUOTA_EXCEEDED` |
| **M14** | File/Folder Erasure | Single-Pass Zero Overwrite | Single-Pass Zero Engine | `SOFTWARE_QUALIFIED` | `LIMITED` | Synthetic file tests | `WRITE_FAULT`, `VERIFY_MISMATCH` |
| **M15** | File/Folder Erasure | Storage-Aware Sanitization Fallback | Controller Fallback Matrix | `SOFTWARE_QUALIFIED` | `LIMITED` | Decision matrix tests | `FALLBACK_EXHAUSTED` |
| **M16** | File/Folder Erasure | Temporary / Cache Sanitization | Temp Cache Scanner & Overwrite | `SOFTWARE_QUALIFIED` | `LIMITED` | Temp folder fixtures | `ACCESS_DENIED`, `PATH_LOCKED` |
| **M17** | Recovery | Quick Recovery | TSK 4.15.0 `fls.exe` + `icat.exe` | `SOFTWARE_QUALIFIED` | `LIMITED` | FAT/NTFS synthetic images | `CORRUPT_FS`, `INODE_NOT_FOUND` |
| **M18** | Recovery | Smart Recovery | TSK 4.15.0 `fsstat` + `fls` + `tsk_recover` | `SOFTWARE_QUALIFIED` | `LIMITED` | FAT/NTFS synthetic images | `PARTIAL_METADATA`, `FS_UNRECOGNIZED` |
| **M19** | Recovery | Targeted Recovery | TSK 4.15.0 `icat.exe` | `SOFTWARE_QUALIFIED` | `LIMITED` | Inode synthetic images | `INODE_DEALLOCATED`, `READ_ERROR` |
| **M20** | Recovery | Filesystem Recovery | TSK 4.15.0 `tsk_recover.exe` | `SOFTWARE_QUALIFIED` | `LIMITED` | Synthetic filesystem images | `RECOVER_ABORTED`, `TARGET_FULL` |
| **M21** | Recovery | Deep Recovery | PhotoRec 7.2 Raw Carver | `PARTIAL` | `LIMITED` | Elevated raw disk needed | `NO_SIGNATURE_MATCH`, `HIGH_ENTROPY` |
| **M22** | Recovery | Fragment Recovery | PhotoRec 7.2 + Resurgence Engine | `PARTIAL` | `LIMITED` | Bi-fragment fixtures only | `GAP_EXCEEDED`, `VALIDATION_FAILED` |
| **M23** | Recovery | RAID / Storage Recovery | TSK / TestDisk RAID Parser | `UNSUPPORTED` | `HARDWARE_REQUIRED` | Single disk tested only | `STRIPE_MISALIGNMENT`, `ARRAY_MISSING` |
| **M24** | Recovery | Damaged Media Recovery | GNU `ddrescue` Native Adapter | `BACKEND_UNAVAILABLE` | `HARDWARE_REQUIRED` | Linux native binary required | `BINARY_MISSING`, `BAD_SECTOR_TIMEOUT` |
| **M25** | Recovery | Forensic Recovery | TSK 4.15.0 + SHA-256 Vault | `SOFTWARE_QUALIFIED` | `LIMITED` | Synthetic evidence images | `VAULT_INTEGRITY_FAIL`, `HASH_MISMATCH` |

---

## 3. Disambiguated Failure Handling Semantics

All 25 methods adhere to the Phase 11 fail-closed error classification architecture:

1. **Physical Detachment Only on Code 1167:**  
   `ERROR_DEVICE_NOT_CONNECTED` (Win32 1167) is the **only** code that transitions a job to `DEVICE_DISCONNECTED`.
2. **Data Integrity Failure on Code 23:**  
   `ERROR_CRC` (Win32 23) represents a `READ_FAILURE` / `DATA_INTEGRITY_FAILURE` and transitions to `FAILED`. It is **never** reported as a physical drive detachment.
3. **Device Busy / Not Ready on Code 21:**  
   `ERROR_NOT_READY` (Win32 21) represents `DEVICE_NOT_READY` / `DEVICE_IO_FAILURE`. It fails closed without guessing detachment.
4. **Target Object Missing on Code 2:**  
   `ERROR_FILE_NOT_FOUND` (Win32 2) represents `TARGET_UNAVAILABLE`.
5. **Privilege Missing on Code 5:**  
   `ERROR_ACCESS_DENIED` (Win32 5) represents `INSUFFICIENT_PRIVILEGE`.
6. **Cooperative Cancellation:**  
   A job cancelled during execution transitions to `CANCELLING` and terminates in `CANCELLED`. It **never** reports `COMPLETED` or generates a valid sanitization certificate.
