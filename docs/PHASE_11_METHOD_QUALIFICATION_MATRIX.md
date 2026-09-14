# DREX-V2 — Phase 11 Authoritative 25-Method Qualification Matrix

**Platform:** DREX-V2 Forensic Workstation & Assurance Platform  
**Phase:** Phase 11 — Production Hardening & Reliability  
**Status:** Authoritative Evidence-Backed Qualification Matrix  
**Hardware Qualification Level:** **LIMITED / CONDITIONAL** (Simulated & Virtual IOCTL Descriptors; Zero Physical Drive Mutation)  
**Standard References:** NIST SP 800-88 Rev. 1/Rev. 2 draft, DoD 5220.22-M, IEEE 2883-2022, BSI-GS, CESG CPA Higher, CCOSS, NAVSO P-5239-26, AFSSI-5020.

---

## 1. Physical Hardware Qualification Reality

> [!IMPORTANT]
> In accordance with strict forensic integrity and scientific truthfulness:
> **No method in this matrix is marked `HARDWARE_QUALIFIED`.**
> Physical hardware qualification requires empirical execution and oscilloscope/bus-analyzer verification on dedicated, sacrificed physical flash/magnetic storage drives. In the automated test and simulation harness, all methods are qualified as **`AVAILABLE`**, **`LIMITED`**, or **`CONDITIONAL`** based on virtual/synthetic Windows IOCTL descriptors.
> System drives are permanently protected via dynamic Windows boot/system-volume tripwires (`SAFETY_BLOCKED`).

---

## 2. Complete 25-Method Qualification Matrix

| ID | Method Name | Category | Software Implementation | Hardware Status | Failure Modes & Error Behavior | Evidence Required |
|:---|:---|:---|:---|:---|:---|:---|
| **1** | NIST SP 800-88 Rev. 1 Clear (Single-Pass Zero) | Overwrite / Clear | Zero-fill buffer loop via direct block write | `LIMITED` | `READ_FAILURE`, `WRITE_FAULT` | Full readback match, Entropy $H = 0.000$ |
| **2** | NIST SP 800-88 Rev. 1 Purge (ATA Secure Erase) | Firmware Purge | `IOCTL_ATA_PASS_THROUGH` (Opcode 0xF3 / 0xF4) | `CONDITIONAL` | `FIRMWARE_LOCKED`, `SECURITY_FROZEN` | Bus response code 0x00, readback zero |
| **3** | NIST SP 800-88 Rev. 1 Purge (NVMe Format / Sanitize) | Firmware Purge | `IOCTL_STORAGE_PROTOCOL_COMMAND` (Opcode 0x80/0x84) | `CONDITIONAL` | `NVME_UNSUPPORTED`, `CONTROLLER_BUSY` | Admin queue completion status 0x00 |
| **4** | DoD 5220.22-M (3-Pass: Zero, One, Random) | Overwrite / Purge | 3-pass synchronous buffer fill with verify | `LIMITED` | `SECTOR_TIMEOUT`, `WRITE_MISMATCH` | Shannon entropy $H \ge 7.999$, zero residual |
| **5** | DoD 5220.22-M ECE (7-Pass Military Sanitization) | Overwrite / Purge | 7 alternating passes with complement verify | `LIMITED` | `THERMAL_THROTTLE`, `SECTOR_UNREADABLE` | Merkle hash chain across all 7 passes |
| **6** | IEEE 2883-2022 Clear (Block Overwrite) | Overwrite / Clear | IEEE 2883 conforming fixed-pattern overwrite | `LIMITED` | `WRITE_FAULT`, `DEVICE_NOT_READY` | Full sector verify, residual sampling |
| **7** | IEEE 2883-2022 Purge (Cryptographic Erase) | Cryptographic Purge | Media key destruction via SED/TCG Opal or NVMe Crypto | `CONDITIONAL` | `TCG_LOCKED`, `KEY_GEN_FAILED` | Key destruction certificate, entropy verify |
| **8** | CSPRNG Random Overwrite (Single Pass) | Overwrite / Clear | Cryptographically secure PRNG (`os.urandom`) stream | `AVAILABLE` | `BUFFER_STARVATION`, `IO_ERROR` | Entropy $H \ge 7.999$, Chi-square verify |
| **9** | Gutmann 35-Pass Complete Overwrite | Overwrite / Legacy | Full 35-pattern MFM/RLL encoding overwrite sequence | `LIMITED` | `EXECUTION_TIMEOUT`, `BUS_FATIGUE` | Pass-by-pass cryptographic log |
| **10** | Schneier 7-Pass Overwrite | Overwrite / Purge | Pass 1: 0x00, Pass 2: 0xFF, Passes 3-7: CSPRNG | `LIMITED` | `TIMEOUT`, `WRITE_MISMATCH` | Intermediate pass hashes |
| **11** | US Army AR 380-19 | Overwrite / Legacy | Random char, fixed char, complement, verify | `LIMITED` | `READ_FAILURE`, `WRITE_FAULT` | Full readback confirmation |
| **12** | US Air Force AFSSI-5020 | Overwrite / Purge | Zero, fixed byte, pseudo-random, verify | `LIMITED` | `SECTOR_TIMEOUT`, `CRC_ERROR` | Bit-level readback comparison |
| **13** | NAVSO P-5239-26 (Navy Staff) | Overwrite / Purge | Fixed character, complement, random, verify | `LIMITED` | `SECTOR_UNMAPPED`, `IO_FAILURE` | Readback mismatch count = 0 |
| **14** | German BSI-VSITR / BSI-GS | Overwrite / Purge | 7 alternating passes (0x00, 0xFF, CSPRNG) | `LIMITED` | `BUFFER_MISALIGNMENT`, `IO_ERROR` | BSI compliance log, entropy audit |
| **15** | British HMG Infosec Standard 5 (Higher) | Overwrite / Purge | 3 passes: Zero, One, Random with full verify | `LIMITED` | `DEVICE_NOT_READY`, `SECTOR_LOCK` | UK CESG compliance verification |
| **16** | Canadian CCOSS / RCMP TSSIT OPS-II | Overwrite / Purge | 6-pass alternation with CSPRNG termination | `LIMITED` | `WRITE_FAULT`, `TIME_LIMIT` | Readback verify of random pass |
| **17** | Australian ISM / ASD-NZS 5820 | Overwrite / Clear | Single-pass random pattern + zero verify | `LIMITED` | `IO_FAILURE`, `VERIFY_MISMATCH` | Zero-check verification pass |
| **18** | Russian GOST R 50739-95 | Overwrite / Clear | 2-pass: 0x00 followed by pseudo-random fill | `LIMITED` | `WRITE_TIMEOUT`, `BUS_HANG` | Final pass entropy $H \ge 7.999$ |
| **19** | ATA Enhanced Secure Erase | Firmware Purge | ATA command 0xF4 with enhanced bit set | `CONDITIONAL` | `SECURITY_FROZEN`, `NOT_SUPPORTED` | Drive status word 0x0050 |
| **20** | NVMe Sanitize (Crypto Scramble) | Cryptographic Purge | NVMe Sanitize Action 0x04 (Key Eviction) | `CONDITIONAL` | `OPERATION_DENIED`, `ADMIN_QUEUE_TIMEOUT` | NVMe Sanitize Status log page 0x81 |
| **21** | NVMe Sanitize (Block Erase) | Firmware Purge | NVMe Sanitize Action 0x02 (Low-level Flash Erase) | `CONDITIONAL` | `VOLTAGE_FAULT`, `FIRMWARE_REJECT` | NVMe Sanitize Status log page 0x81 |
| **22** | NVMe Sanitize (Overwrite) | Firmware Overwrite | NVMe Sanitize Action 0x01 with 32-bit pattern | `CONDITIONAL` | `SANITIZE_IN_PROGRESS`, `TIMEOUT` | NVMe Sanitize Status log page 0x81 |
| **23** | SCSI / SAS Sanitize (Block Overwrite) | Firmware Overwrite | SCSI `SANITIZE` command (Opcode 0x48) | `CONDITIONAL` | `CHECK_CONDITION`, `ILLEGAL_REQUEST` | SCSI Sense Key 0x00 (NO SENSE) |
| **24** | SCSI / SAS Cryptographic Erase | Cryptographic Purge | SCSI `SANITIZE` command with Crypto Erase bit | `CONDITIONAL` | `KEY_INVALID`, `UNSUPPORTED_FIELD` | SCSI Sense Key 0x00, readback check |
| **25** | Host-Guided Forensic Slack Wipe | Slack Erasure | Filesystem cluster slack CSPRNG overwrite | `AVAILABLE` | `FILE_LOCKED`, `UNPRIVILEGED_ACCESS` | Pre/post cluster slack zero entropy |

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
