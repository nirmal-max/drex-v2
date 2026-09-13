# COMPETITOR REALITY MATRIX: REAL VS CLAIMED CAPABILITIES

## 1. Reality Verification Methodology
Every major claimed capability is classified according to code and test inspection:
- **`SOURCE_PROVEN`**: Verified function/class bodies present and executable in source code.
- **`TEST_PROVEN`**: Accompanied by automated test suite assertions validating behavior.
- **`SIMULATED`**: Calculation, policy matrix, or mockup that does not execute hardware/filesystem writes.
- **`CLAIMED_ONLY`**: Described in README or docs with no supporting source code or testbed.
- **`UNSUPPORTED`**: Depends on hardware configurations (e.g. native AHCI/PCIe) not available over USB/virtual environments.

---

## 2. Reality Classification Table

| Repository | Feature Claimed | Code Reality Classification | Forensic Evidence Notes |
|---|---|---|---|
| `pulkit6732/AKHANDA` | Fragment Reassembly | `SOURCE_PROVEN` & `TEST_PROVEN` | Pure-Python reassembly in `reassemble.py` with benchmark harness. |
| `pulkit6732/AKHANDA` | Post-Quantum Witness Co-Signing | `SOURCE_PROVEN` & `TEST_PROVEN` | Ed25519 & Kyber bindings in `src/crypto/` with multi-party nodes. |
| `devil-net/...` | 6-Factor Confidence Scoring | `SOURCE_PROVEN` | Mathematical formula in C# with anti-inflation floor. |
| `devil-net/...` | NVMe Physical Sanitization | `UNSUPPORTED` on USB | Standard software fallback on USB bridges. |
| `pointblank-club/SecureWipe` | C++20 NVMe/ATA Erase | `SOURCE_PROVEN` | C++20 Linux ioctl implementation targeting raw block devices. |
| `MithunRayakota07/resurgence` | Non-contiguous JPEG Carver | `SOURCE_PROVEN` & `TEST_PROVEN` | JPEG entropy-stream/MCU stream decoder with benchmark images. |
| `MithunRayakota07/resurgence` | Hardware Erase | `SIMULATED` | Explicitly documented as simulated plan for loopback images only. |
| `K01SR/SecureForge` | Structure-Aware File Carver | `SOURCE_PROVEN` & `TEST_PROVEN` | Rust chunk parser with TOML/Lua dynamic plugin signatures. |
| `K01SR/SecureForge` | Shannon Entropy Scanner | `SOURCE_PROVEN` & `TEST_PROVEN` | High-throughput sector scanner ($0.000$ to $7.999$ bits/byte). |
| `ayushsmenon/SIH26` | NTFS $Bitmap Unallocated Scan | `SOURCE_PROVEN` | Win32 `FSCTL_GET_VOLUME_BITMAP` skipping allocated clusters. |
| `Prithiv04/EraseXperts` | VSS Shadow Copy Purging | `SOURCE_PROVEN` | Win32 `vssadmin` shadow storage delete routine. |
| `Prithiv04/EraseXperts` | Quantum Random Wipe | `CLAIMED_ONLY` / Fallback | Uses `os.urandom` standard fallback when IBM QRNG is absent. |
| `Vigneshe247/Secure-Data...` | 4-State Scientific Verdict | `SOURCE_PROVEN` | 4-state engine evaluating magic bytes, entropy, and simulated recovery. |
| `Vigneshe247/Secure-Data...` | 5 RBAC Security Roles | `SOURCE_PROVEN` | Granular FastAPI JWT role permissions with dedicated demo persona. |
| `DHEEERAJ-sloff/OSIRIS...` | PIL/Zip Format Confidence | `SOURCE_PROVEN` | Python PIL/zipfile parsing assigning High/Med/Low badges. |
| `HarshithaR210/ForenSentry` | Destructive Hardware Wipe | `SIMULATED` (Lab Sandbox) | Intentionally confined to `data/lab` to prevent live hardware damage. |
