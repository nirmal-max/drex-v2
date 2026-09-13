# COMPETITOR ARCHITECTURE MATRIX

## 1. Technical Stack & Architectural Comparison

| Category | Premier Implementation / Benchmark | Runner-Up | DREX-V2 Integration Approach |
|---|---|---|---|
| **Best Practical Implementation** | `K01SR/SecureForge` (Rust 1.80+ / Zero-Allocation Core) | `devil-net/...` (C# .NET 8 / WPF) | Ported RFC 3161 timestamping & Shannon entropy into Python/C++ core. |
| **Best Architectural Reference** | `yasin-kazi/...` (SIH Architecture & Risk Specs) | `pulkit6732/AKHANDA` (Multi-layer separation) | Adopted judge demo flows, risk registers, and clean module boundaries. |
| **Best Recovery (Filesystem)** | `drex-v2` / `devil-net` (The Sleuth Kit 4.15/4.12) | `ayushsmenon/SIH26` (TSK + $Bitmap) | TSK `fls` + `icat` + `tsk_recover` with direct NTFS volume bitmap filtering. |
| **Best Recovery (Carving)** | `4shm1td06/forensec` (C++17 25+ Formats) | `K01SR/SecureForge` (Structure-aware) | PhotoRec 7.2 bridge + pure-Python chunk carver with dynamic headers. |
| **Best Fragment Reconstruction** | `MithunRayakota07/resurgence-forensics` (Out-of-order MCU) | `pulkit6732/AKHANDA` (Reassemble.py) | Combined JPEG MCU entropy decoder with AKHANDA ZIP central directory parser. |
| **Best Damaged-Media Approach** | `drex-v2` (GNU ddrescue / mapfile tracking) | `Prithiv04/EraseXperts` (Phase 4 engine) | Multi-pass adaptive block rescue with bad-sector mapfile tracking. |
| **Best Evidence & Custody Model** | `pulkit6732/AKHANDA` (Witness Node Co-Signing) | `K01SR/SecureForge` (RFC 3161 TSR Token) | SHA-256 Merkle chain + witness node co-signatures + RFC 3161 timestamps. |
| **Best Post-Erasure Verification** | `K01SR/SecureForge` (Physics-based Shannon Entropy) | `Vigneshe247` (4-State Verdict Engine) | Shannon Entropy Scanner ($0.000$ to $7.999$ b/B) + 4-State scientific verdict. |
| **Best Testing Suite** | `drex-v2` (236 pytest test suite) | `K01SR/SecureForge` (117 Cargo tests) | Retained and expanded full 236-test suite with zero regressions. |
| **Best UI & Workstation** | `drex-v2` (25 Pages Blue Workstation) | `Vigneshe247` (React 18 Cybersecurity SOC) | 25 specialized pages with responsive async event queues and judge demo flow. |
| **Best Case Management** | `HarshithaR210/ForenSentry` (DFIR Case Command Center) | `Vigneshe247` (5 RBAC Roles) | Integrated case metadata, investigator credentials, and role selector. |
