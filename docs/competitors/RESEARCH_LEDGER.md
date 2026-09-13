# 29-REPOSITORY RESEARCH LEDGER

## 1. Overview
This research ledger tracks the code-level inspection of all 29 target external repositories for DREX-V2 Phase 0.

| # | Repository Slug | Primary Language | License | Files / Modules Inspected | Core Technical Findings | Reality Status |
|---|---|---|---|---|---|---|
| 1 | `pulkit6732/AKHANDA` | Python 3.11 | Apache-2.0 | `akhanda/src/recovery/reassemble.py`, `zipcarve.py`, `crypto/` | Fragment reassembly, ZIP carving, multi-party witness nodes | `SOURCE_PROVEN` |
| 2 | `manoj-1407/SIH-2026` | Python | MIT | `sih26149/`, `README.md` | Pure-Python raw byte stream carving, sequential proof loop | `SOURCE_PROVEN` |
| 3 | `devil-net/Secure-Data-Erasure-and-Advanced-File-Recovery-Tool` | C# (.NET 8) / WPF | Unspecified | `FileFolderShredder.cs`, `ConfidenceScoring.cs` | TSK/PhotoRec C# bridge, 6-factor confidence formula, MFT scrub | `SOURCE_PROVEN` |
| 4 | `pointblank-club/SecureWipe` | C++20 / TinyCore | Apache-2.0 | `src/wipe.cpp`, `src/nvme.cpp` | C++20 ATA/NVMe Secure Erase, Android ADB/Fastboot reset ISO | `SOURCE_PROVEN` |
| 5 | `anirban-bhowmik-coder/ZeroTrace` | Python / React | MIT | `src/erasure/`, `src/recovery/` | 5-stage Detect-Sanitize-Verify-Secure-Report workflow | `SOURCE_PROVEN` |
| 6 | `MithunRayakota07/resurgence-forensics` | Python | MIT | `resurgence/carve.py`, `resurgence/mft.py` | Non-contiguous out-of-order JPEG MCU carver, MFT resident wipe | `SOURCE_PROVEN` |
| 7 | `Shreya-A-K/SIH2026-Secure-Erasure-and-Recovery-` | Python / Tkinter | MIT | `erasure_engine.py`, `recovery.py` | Multi-pass file shredder, basic carving UI | `SOURCE_PROVEN` |
| 8 | `aruljana2907/Forensicvault` | Python | MIT | `vault.py`, `hash_ledger.py` | Encrypted vault storage, SHA-256 evidence logging | `SOURCE_PROVEN` |
| 9 | `K01SR/SecureForge` | Rust (1.80+) | MIT | `src/carver/`, `src/wiper/`, `src/audit/` | Structure-aware carver, RFC 3161 timestamping token `.tsr`, Shannon entropy | `SOURCE_PROVEN` |
| 10 | `PushkarNagarmarmote-stack/ForensiX-platform` | Python / FastAPI | MIT | `backend/app/`, `frontend/` | Web-based DFIR case management and carving endpoints | `SOURCE_PROVEN` |
| 11 | `ayushsmenon/SIH26` | C++17 | MIT | `src/forensix/nvme.cpp`, `src/forensix/bitmap.cpp` | NVMe IOCTL, NTFS $Bitmap unallocated skipping, HMAC parity vault | `SOURCE_PROVEN` |
| 12 | `Jyndr/SIH-26149` | Python / Flask | MIT | `app.py`, `modules/recovery/` | Web DFIR dashboard with sector carving | `SOURCE_PROVEN` |
| 13 | `xarjunpatil/SIH26149-Design-and-Development-of-an-Integrated` | Python / Tkinter | MIT | `main.py`, `core/` | Integrated sanitization/recovery workstation layout | `SOURCE_PROVEN` |
| 14 | `yasin-kazi/Integrated-Secure-Data-Erasure-amp-Advanced-File-Recovery-Tool` | Markdown / Specs | Creative Commons | `docs/21_DEMO_STRATEGY.md`, `docs/` | Comprehensive judge presentation flow, risk register, DoD specs | `DOCUMENTATION_ONLY` |
| 15 | `Nithilaa011/Forensiwipe` | Python | MIT | `wiper.py`, `carver.py` | Multi-pass overwrite, basic magic byte carver | `SOURCE_PROVEN` |
| 16 | `4shm1td06/forensec` | C++17 / CMake | MIT | `src/erasure/`, `src/recovery/`, `src/forensics/` | C++17 CLI for multi-pass erasure and 25+ format carver | `SOURCE_PROVEN` |
| 17 | `sonakshiupadhyay/DataPhantom-Forensics` | Python / Streamlit | MIT | `app.py`, `carver.py` | Streamlit forensics analyzer with metadata extraction | `SOURCE_PROVEN` |
| 18 | `HarshithaR210/ForenSentry` | Python / Flask / React | MIT | `backend/app.py`, `src/` | DFIR command center, case manager, isolated lab safety boundary | `SOURCE_PROVEN` |
| 19 | `Prithiv04/EraseXperts` | Python / PyWebView | MIT | `app.py`, `recovery.py`, `WipeLog.sol` | 5-phase FORGE-X engine, VSS shadow copy purge, Sepolia ledger | `SOURCE_PROVEN` |
| 20 | `team-doom-gcetts/blackbody` | C++ / Python | GPL-2.0 | `src/core/`, `LICENSE` | Secure data erasure and raw carving engine | `SOURCE_PROVEN` |
| 21 | `VaibhavKadam-24/cipher-blackout` | Python / FastAPI / React | MIT | `backend/main.py`, `backend/carver.py` | Magic-byte carving, NVMe blkdiscard, SHA-256 evidence chain | `SOURCE_PROVEN` |
| 22 | `dolphysharma26-sys/integrated-forensics-tool` | Python | MIT | `sanitizer.py`, `carver.py` | NIST SP 800-88 Clear/Purge scripts and signature carver | `SOURCE_PROVEN` |
| 23 | `Blaze-809/SIH-2026` | Python / Flask | MIT | `routes.py`, `forensics/` | Forensic recovery and sanitization web wrapper | `SOURCE_PROVEN` |
| 24 | `Vigneshe247/Secure-Data-Erasure-Recovery` | Python / FastAPI / React | MIT | `backend/routers/`, `backend/services/` | Explainable recovery confidence formula, 4-state verdict, 5 RBAC roles | `SOURCE_PROVEN` |
| 25 | `DHEEERAJ-sloff/OSIRIS-the-cleaner-finder` | Python / Streamlit | MIT | `app.py`, `engine/carve.py` | Forked SecureWipe + PhotoRec, PIL/zipfile confidence scoring | `SOURCE_PROVEN` |
| 26 | `ankitsingh138/SIH-26149` | Python | MIT | `erase.py`, `recover.py` | NIST SP 800-88 single/multi-pass wiping & signature recovery | `SOURCE_PROVEN` |
| 27 | `Clumsyoof/sih-encriptor` | Python | MIT | `crypto_wipe.py` | AES cryptographic wipe and key purge implementation | `SOURCE_PROVEN` |
| 28 | `kuna1-exe/Secure-Data-Erasure-and-Advanced-File-Recovery-Tool` | Python / PyQt | MIT | `ui_main.py`, `carver_thread.py` | PyQt GUI for multi-threaded file carving and disk zeroing | `SOURCE_PROVEN` |
| 29 | `Abhiraj1401/SIH-26149` | Python / React | MIT | `backend/`, `frontend/` | NIST SP 800-88 sanitization suite and carver dashboard | `SOURCE_PROVEN` |
