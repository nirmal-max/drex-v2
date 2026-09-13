# DREX-V2 REPOSITORY CLEANUP PLAN

## 1. Objective
Establish a formal, evidence-based audit of all files in the DREX-V2 workspace, classifying each item to prevent accidental deletion of required source code, tests, native binaries, architecture records, or competitor research.

---

## 2. File Classification Schema
- **`KEEP`**: Essential source code, adapters, native binaries, active documentation, build scripts, workflows.
- **`REFACTOR`**: Active code targeted for architectural improvement in future phases.
- **`MERGE`**: Redundant logic to be unified into primary modules.
- **`MOVE`**: Files belonging in structured subdirectories (`docs/`, `methods/`, etc.).
- **`ARCHIVE`**: Historical validation logs to be preserved in `docs/archive/`.
- **`DELETE`**: Confirmed temporary, orphaned, or generated cache files with zero dependencies.
- **`GENERATED`**: Automated build artifacts (e.g., `build/`, `__pycache__/`, pytest basetemp).
- **`TEMPORARY`**: Temp dump files (`.tmp`, `.log`).
- **`UNKNOWN`**: Unclassified items (MANDATORY RULE: Never delete UNKNOWN items).

---

## 3. Directory Audit & Classification Table

| Directory / File | Size / Count | Classification | Rationale & Safety Justification |
|---|---|---|---|
| `drex_app.py` | 287 KB | `KEEP` | Primary desktop UI and workstation application controller. |
| `backend_adapters.py` | 24 KB | `KEEP` | Authoritative CLI adapters for TSK, PhotoRec, and ddrescue. |
| `recovery_adapter.py` | 54 KB | `KEEP` | Core recovery candidate normalization and safety validation engine. |
| `recovery_backends.py` | 3 KB | `KEEP` | Local executable discovery and backend status manager. |
| `25_METHOD_STATUS.json` | 6 KB | `KEEP` | Authoritative method status register. |
| `25_METHOD_STATUS.md` | 6 KB | `KEEP` | Markdown status reference. |
| `methods/` | 519 files | `KEEP` | Modular C++ baselines for all 25 sanitization and recovery methods. |
| `native_bin/` | 114 files | `KEEP` | Pre-compiled native TSK, PhotoRec, and Qt/Cygwin runtime DLLs. |
| `tests/` | 22 files | `KEEP` | Full 236-test automated regression and validation suite. |
| `.github/` | 16 files | `KEEP` | GitHub Actions CI workflows for media destruction and 25-method testing. |
| `docs/` | Structured | `KEEP` | Architecture, competitor research, cleanup, dependencies, validation. |
| `repo/` | 6,575 files | `KEEP` | Extracted competitor and upstream reference checkouts. |
| `DREXX_FINAL_EVIDENCE/` | 13 files | `KEEP` | Verified forensic test evidence and JSON ledgers. |
| `drex_data/` | 7 files | `KEEP` | Local application state, user configurations, and audit caches. |
| `build/` | 144 files | `GENERATED` | PyInstaller build artifacts and pytest basetemp cache. |
| `BUG_AUDIT.md` | 6 KB | `KEEP` | Historical audit record of previous bug fixes. |
| `BUG_FIX_REPORT.md` | 2 KB | `KEEP` | Historical fix validation report. |
| `README.md` | 4 KB | `KEEP` | Top-level repository overview. |
| `pytest.ini` | 42 B | `KEEP` | Pytest configuration. |
| `build.ps1` | 2 KB | `KEEP` | Standalone PowerShell build script. |
| Root `.tmp` files | Variable | `DELETE` | Transient process crash dumps (if any). |

---

## 4. Safe Cleanup Execution Summary
- **Zero source files deleted.**
- **Zero test files deleted.**
- **Zero native binaries deleted.**
- **Zero documentation deleted without replacement.**
- Only ephemeral temporary test run artifacts in `build/pytest_temp/` are cleaned.
