# COMPETITOR FEATURE MATRIX

## 1. Feature Categories Across 29 Repositories

| Repository | Drive Erasure (NIST/ATA/NVMe) | File/Folder Erasure | Residue / Slack / MFT | Filesystem Recovery (TSK) | Raw Sector Carving | Fragment Reassembly | Damaged Media | Device Intelligence | Evidence / Merkle Chain | UI / Workstation |
|---|---|---|---|---|---|---|---|---|---|---|
| **DREX-V2** | Yes (7 methods) | Yes (9 methods) | Yes (Slack/MFT/Temp) | Yes (TSK 4.15) | Yes (PhotoRec + Py) | Yes (MCU + ZIP) | Yes (ddrescue/adapter) | Yes (WMI + CIM) | Yes (SHA-256 + Certs) | Yes (25 Pages) |
| `pulkit6732/AKHANDA` | Yes (NIST/ATA/NVMe) | Yes (CSPRNG) | Partial | No | Yes (ZipCarve) | Yes (Reassemble.py) | Partial | Yes (MTP/USB Guard) | Yes (Kyber/Dilithium/Witness) | Yes (React + Console) |
| `manoj-1407/SIH-2026` | Yes (NIST SP 800-88) | Yes (File Wipe) | No | No | Yes (Pure Python) | Partial | No | Yes (OS Drives) | Yes (Sequential Proof) | Yes (React/FastAPI) |
| `devil-net/...` | Yes (NIST SP 800-88) | Yes (ShredMaster) | Yes (MFT Scrub) | Yes (TSK 4.12) | Yes (PhotoRec) | No | No | Yes (Win32 IO) | Yes (ISO 27037 / 6-Factor) | Yes (C# WPF) |
| `pointblank-club/SecureWipe` | Yes (ATA/NVMe Erase) | No | No | No | No | No | No | Yes (ATA/NVMe) | Yes (Certificates) | Yes (TinyCore ISO) |
| `anirban-bhowmik-coder/ZeroTrace` | Yes (NIST) | Yes (File Wipe) | No | No | Yes (Magic Bytes) | No | No | Yes (Device Detect) | Yes (Audit Log) | Yes (React + Python) |
| `MithunRayakota07/resurgence-forensics` | Yes (Simulated Plan) | Yes (MFT Residue) | Yes (MFT/Resident) | No | Yes (JPEG MCU) | Yes (Out-of-order MCU) | No | No | Yes (Ed25519 Certs) | CLI Only |
| `K01SR/SecureForge` | Yes (NVMe/ATA Erase) | Yes (Multi-pass) | No | No | Yes (Chunk/Plugin) | No | No | Yes (Disk IO) | Yes (RFC 3161 TSR / Merkle) | Yes (Ratatui / Tauri v2) |
| `ayushsmenon/SIH26` | Yes (NVMe IOCTL) | Yes (Shredder) | Yes (Slack space) | Yes (TSK) | Yes ($Bitmap Carve) | Yes (Bi-fragment) | No | Yes (Win32 NVMe) | Yes (HMAC Parity Vault) | CLI Only (C++17) |
| `yasin-kazi/...` | Specs | Specs | Specs | Specs | Specs | Specs | Specs | Specs | Specs (Demo flow) | Docs Only |
| `4shm1td06/forensec` | Yes (7 algorithms) | Yes (Recursive) | Yes (Free-space) | No | Yes (25+ Formats) | No | No | Yes (Raw Disk) | Yes (Chain of Custody) | CLI (C++17) |
| `HarshithaR210/ForenSentry` | Yes (Lab Sandbox) | Yes (Lab Only) | No | No | Yes (5 Formats) | No | No | Yes (Read-only) | Yes (Vault + Chained Log) | Yes (React + Flask) |
| `Prithiv04/EraseXperts` | Yes (NIST / TRIM) | Yes (Secure Delete) | Yes (VSS Shadows) | No | Yes (FORGE-X) | Yes (P5 Fragmented) | Yes (P4 Damaged) | Yes (Drive Detect) | Yes (Sepolia Blockchain) | Yes (PyWebView) |
| `team-doom-gcetts/blackbody` | Yes (DoD/NIST) | Yes (File Wipe) | No | No | Yes (Carver) | No | No | Yes (Linux/Win) | Yes (Audit Trail) | CLI / Python |
| `VaibhavKadam-24/cipher-blackout` | Yes (NIST / NVMe) | Yes (File Wipe) | No | No | Yes (Magic Byte) | No | No | Yes (Device Scan) | Yes (SHA-256 Log) | Yes (React + FastAPI) |
| `Vigneshe247/Secure-Data-Erasure-Recovery` | Yes (Storage-Aware) | Yes (File Erasure) | No | No | Yes (Sig + Struct) | Partial | No | Yes (FTL/TRIM Aware) | Yes (4-State / 5-Factor) | Yes (React 18 + FastAPI) |
| `DHEEERAJ-sloff/OSIRIS...` | Yes (DoD 3-Pass) | Yes (File Wipe) | No | No | Yes (PhotoRec) | No | No | Yes (Drive Detect) | Yes (PIL/Zip Scoring) | Yes (Streamlit) |
