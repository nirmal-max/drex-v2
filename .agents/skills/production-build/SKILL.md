---
name: production-build
description: PyInstaller packaging, native binary staging, and installer generation for DREX-V2.
---

# Production Build Skill

## When to Use
Use when packaging standalone executables, validating native DLL/EXE dependencies, or running `build.ps1`.

## Key Checks
- Verify `native_bin/` contains required TSK (`fls.exe`, `icat.exe`, `tsk_recover.exe`) and PhotoRec binaries.
- Ensure PyInstaller hooks include `backend_adapters.py`, `recovery_adapter.py`, and `recovery_backends.py`.
- Enforce `_MEIPASS` discovery priority when running as a frozen executable.
