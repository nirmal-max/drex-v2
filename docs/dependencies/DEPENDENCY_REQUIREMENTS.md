# DREX-V2 DEPENDENCY & RUNTIME REQUIREMENTS MATRIX

## 1. Overview
This document specifies all runtime dependencies, native external binaries, and optional packages for DREX-V2. In accordance with the dependency policy, no external packages may be silently installed.

---

## 2. Dependency Inventory & Status

| Dependency | Component / Role | License | Status | Security / Maintenance Assessment |
|---|---|---|---|---|
| **Python 3.10+ Standard Library** | Core runtime (`os`, `sys`, `ctypes`, `subprocess`, `hashlib`, `struct`, `tkinter`, `sqlite3`) | PSF License | `ACTIVE / INSTALLED` | Official standard library. Zero supply chain risk. |
| **The Sleuth Kit (TSK 4.15.0)** | Native filesystem analysis binaries (`fls.exe`, `icat.exe`, `fsstat.exe`, `tsk_recover.exe`, `mmls.exe`) | IBM Public License / CPL / GPL | `ACTIVE / BUNDLED` in `native_bin/` | Gold-standard court-tested digital forensics engine. |
| **PhotoRec / TestDisk 7.2** | Native raw block carving binaries (`photorec_win.exe`, `testdisk_win.exe`) | GNU GPL v2.0 | `ACTIVE / BUNDLED` in `native_bin/` | Widely trusted raw sector signature carver. |
| **pytest** | Automated test execution framework | MIT | `ACTIVE / INSTALLED` | Developer dependency for CI and regression runs. |
| **GNU ddrescue** | Damaged media multi-pass imager | GNU GPL v3.0 | `DEFERRED` (Backend Unavailable on Win) | Handled defensively with fail-closed status on Windows. |
| **cryptography** (Optional) | High-performance cryptographic primitives | Apache-2.0 / BSD | `OPTIONAL` | DREX uses standard library `hashlib` / `os.urandom` with zero external dependency. |
| **Pillow / PIL** (Optional) | Image structural header verification | HPND License | `OPTIONAL` | Used for JPEG/PNG header validation; pure-Python fallbacks exist. |
| **PyInstaller** | Executable bundling & packaging | GPL v2 with exception | `OPTIONAL` | Used by `build.ps1` to produce standalone binary. |

---

## 3. Dependency Decision Summary
- **Blocking Dependencies**: None. DREX-V2 runs completely standalone using standard Python 3.10+ and bundled native binaries in `native_bin/`.
- **Optional Dependencies**: `Pillow`, `cryptography`, `PyInstaller`.
- **Deferred Dependencies**: Native Windows port of `ddrescue`.
