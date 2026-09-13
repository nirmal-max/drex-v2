# DREX-V2 SAFE DELETE MANIFEST

## 1. Safe Delete Policy
No file may be deleted unless explicitly listed in this manifest with verification that:
1. It is not imported by any Python module.
2. It is not referenced in `.github/workflows/`.
3. It is not invoked by `build.ps1` or PyInstaller.
4. It is not an active test fixture in `tests/`.
5. It does not contain uncommitted unique user research.

---

## 2. Approved Items for Cleanup

| Target Path | Category | Reason for Safe Deletion | Verification Method | Deletion Status |
|---|---|---|---|---|
| `build/pytest_temp/` | `GENERATED` | Ephemeral pytest directory output | Transient runtime cache | `CLEANED` |
| `__pycache__/` | `GENERATED` | Python bytecode cache | Automatically regenerated | `CLEANED` |
| `scripts/generate_competitor_reports.py` | `TEMPORARY` | Temporary helper script | Superseded by direct doc creation | `CLEANED` |

---

## 3. Explicitly Retained Items (DO NOT DELETE)
- All root markdown audit files (`BUG_AUDIT.md`, `BUG_FIX_REPORT.md`, `DREX_TECHNICAL_AUDIT.md`, `EVIDENCE_REALITY_AUDIT.md`, `FINAL_25_METHOD_PHYSICAL_VALIDATION.md`, etc.).
- All modules in `methods/`.
- All native executables and DLLs in `native_bin/`.
- All tests in `tests/`.
- All reference checkouts in `repo/`.
- All evidence files in `DREXX_FINAL_EVIDENCE/`.
