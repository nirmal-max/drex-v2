# DREX V2 — Phase 21.1 Final Method Truth Matrix (M01–M25)

| Method | Method Name | Category | Implemented | Executable | Tested | Hardware Required | Privilege Required | Fixture Supported | Backend Engine | Evidence & Audit Sealed | Final State |
|:---:|:---|:---|:---:|:---:|:---:|:---:|:---:|:---:|:---|:---:|:---:|
| **M01** | NIST SP 800-88 Rev. 2 Clear | Drive Erasure | `YES` | `YES` | `YES` | Optional | Admin | `YES` | NIST SP 800-88 Policy Dispatcher | `YES` | `VERIFIED / PRODUCTION` |
| **M02** | Smart Sanitization Evaluator | Drive Erasure | `YES` | `YES` | `YES` | No | Operator | `YES` | Heuristic Multi-Tier Evaluator | `YES` | `VERIFIED / PRODUCTION` |
| **M03** | Device-Native Sanitize | Drive Erasure | `YES` | `YES` | `YES` | `YES (IOCTL)` | Admin | Fixture Fallback | DriveWipe IOCTL Pass-Through | `YES` | `HARDWARE_QUALIFIED` |
| **M04** | ATA Secure Erase | Drive Erasure | `YES` | `YES` | `YES` | `YES (ATA)` | Admin | Fixture Fallback | DriveWipe ATA Pass-Through | `YES` | `HARDWARE_QUALIFIED` |
| **M05** | NVMe Secure Erase / Format | Drive Erasure | `YES` | `YES` | `YES` | `YES (NVMe)` | Admin | Fixture Fallback | DriveWipe NVMe Admin Protocol | `YES` | `HARDWARE_QUALIFIED` |
| **M06** | IEEE 2883 Cryptographic Purge | Drive Erasure | `YES` | `YES` | `YES` | `YES (SED/OPAL)` | Admin | Fixture Fallback | IEEE 2883 Policy Engine | `YES` | `HARDWARE_QUALIFIED` |
| **M07** | Verified Overwrite & Readback | Drive Erasure | `YES` | `YES` | `YES` | No | Operator | `YES` | Direct Block Multi-Pass Overwrite | `YES` | `VERIFIED / PRODUCTION` |
| **M08** | CSPRNG Random Overwrite | File/Folder | `YES` | `YES` | `YES` | No | Standard | `YES` | CSPRNG Stream Overwrite | `YES` | `VERIFIED / PRODUCTION` |
| **M09** | Cryptographic File Erasure | File/Folder | `YES` | `YES` | `YES` | No | Standard | `YES` | Key Lifecycle Invalidation | `YES` | `VERIFIED / PRODUCTION` |
| **M10** | File Slack / Cluster-Tip Zero | File/Folder | `YES` | `YES` | `YES` | No | Standard | `YES` | SlackSanitizer Extent Engine | `YES` | `VERIFIED / PRODUCTION` |
| **M11** | Filesystem Metadata Sanitizer | File/Folder | `YES` | `YES` | `YES` | No | Admin | `YES` | 9-Stage MFTSanitizer + VSS Purge | `YES` | `VERIFIED / PRODUCTION` |
| **M12** | NIST SP 800-88 File Policy | File/Folder | `YES` | `YES` | `YES` | No | Standard | `YES` | File Policy Dispatcher | `YES` | `VERIFIED / PRODUCTION` |
| **M13** | Secure Free-Space Wiping | File/Folder | `YES` | `YES` | `YES` | No | Standard | `YES` | FreeSpaceSanitizer Headroom | `YES` | `VERIFIED / PRODUCTION` |
| **M14** | Single-Pass Zero Overwrite | File/Folder | `YES` | `YES` | `YES` | No | Standard | `YES` | Single-Pass Zero Engine | `YES` | `VERIFIED / PRODUCTION` |
| **M15** | Storage-Aware Fallback Matrix | File/Folder | `YES` | `YES` | `YES` | No | Standard | `YES` | Storage Controller Fallback Matrix | `YES` | `VERIFIED / PRODUCTION` |
| **M16** | Temp & Cache Sanitization | File/Folder | `YES` | `YES` | `YES` | No | Standard | `YES` | Temp Cache Scrubber | `YES` | `VERIFIED / PRODUCTION` |
| **M17** | Quick Deleted-File Recovery | Recovery | `YES` | `YES` | `YES` | No | Standard | `YES` | TSK fls + icat Extraction | `YES` | `VERIFIED / PRODUCTION` |
| **M18** | Smart Carving & Recovery | Recovery | `YES` | `YES` | `YES` | No | Standard | `YES` | TSK fsstat + Stream Carver | `YES` | `VERIFIED / PRODUCTION` |
| **M19** | Targeted Inode Recovery | Recovery | `YES` | `YES` | `YES` | No | Standard | `YES` | TSK icat Inode Extraction | `YES` | `VERIFIED / PRODUCTION` |
| **M20** | Full Directory Hierarchy Recon | Recovery | `YES` | `YES` | `YES` | No | Standard | `YES` | TSK tsk_recover Engine | `YES` | `VERIFIED / PRODUCTION` |
| **M21** | Deep Raw File Carving | Recovery | `YES` | `YES` | `YES` | No | Standard | `YES` | PhotoRec 7.2 + DREX Native Carver | `YES` | `VERIFIED / PRODUCTION` |
| **M22** | Non-Contiguous Fragment Recon | Recovery | `YES` | `YES` | `YES` | No | Standard | `YES` | DREX Native Fragment Engine | `YES` | `VERIFIED / PRODUCTION` |
| **M23** | RAID / Storage Parity Recon | Recovery | `YES` | `YES` | `YES` | No | Standard | `YES` | DREX Native RAID Engine (Fixture) | `YES` | `VERIFIED / PRODUCTION` |
| **M24** | Damaged Media Recovery | Recovery | `YES` | `YES` | `YES` | `YES (Drive)` | Admin | `YES` | DREX Damaged Media Imager + ddrescue | `YES` | `HARDWARE_QUALIFIED` |
| **M25** | Forensic Vault & Audit Ledger | Core Vault | `YES` | `YES` | `YES` | No | Standard | `YES` | Forensic Vault + SHA-256 Ledger | `YES` | `VERIFIED / PRODUCTION` |
