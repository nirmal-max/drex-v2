# DREX V2 — PHASE 21 DEFECT REGISTER & REMEDIATION MATRIX
**Authoritative Baseline:** `fbad09d`  
**Execution Environment:** Windows 11 (AMD64)  
**Date:** September 16, 2026  

---

## Defect Inventory & Remediation Status

| Defect ID | Severity | Component | Defect Description | Forensic Impact | Remediation & Hardening Applied | Status |
| :---: | :---: | :--- | :--- | :--- | :--- | :---: |
| **DEF-2101** | **CRITICAL** | `webui/sw.js` | Cache-first Service Worker intercepted shell routes (`app.js`, `index.html`), preventing UI updates from reaching the browser without manual cache clear. | Source-to-runtime mismatch observed on video inspection. | Switched to **Network-First** strategy, dynamic partition `drex-v2-shell-fbad09d`, instant `skipWaiting()` and `clients.claim()`. | **RESOLVED** |
| **DEF-2102** | **HIGH** | `webui/app.js` / `drex_server.py` | File/Folder Eraser used standard `<input type="file">`, stripping absolute Windows drive paths (`D:\...`). | Could not specify real drive paths via native dialog. | Implemented zero-dependency `_ask_open_file_dialog_sync` via Python `tkinter.filedialog` in background thread via `/api/dialog/pick-file` and `/api/dialog/pick-folder`. | **RESOLVED** |
| **DEF-2103** | **HIGH** | `webui/app.js` / `scripts` | System Validation dashboard rendered static mockup data rather than live test runner output. | Dashboard test counts did not match actual pytest execution. | Implemented `scripts/generate_test_results.py` and `/api/validation/test-results` serving all 960 collected pytest tests across 9 dynamic categories ($\sum = 960$) with pagination. | **RESOLVED** |
| **DEF-2104** | **HIGH** | `webui/app.js` / `drex_server.py` | Judge Demo lacked dedicated view and mixed synthetic proof with live execution. | Potential ambiguity during evaluation on physical vs synthetic proof. | Created dedicated `renderJudgeDemo()` view separating **Mode A (Synthetic Proof Loop < 60s)** from **Mode B (Real Workstation Fixture Execution)** with real PDF certificate download. | **RESOLVED** |
| **DEF-2105** | **MEDIUM** | `webui/app.js` | Unrendered LaTeX math symbols in fragment correlation and entropy text (`$\to$`, `\dots`, `$H = 0.000$`). | Visual rendering artifacts in browser. | Replaced with clean Unicode typography: `→`, `0.00 to 1.00`, `H = 0.0000 bits/byte`, `H ≥ 7.9990 bits/byte`. | **RESOLVED** |
| **DEF-2106** | **HIGH** | `drex_server.py` / `file_sanitizer.py` | Logical file sanitization lacked preflight identity revalidation (TOCTOU race). | File could be tampered with between preflight inspection and overwrite. | Added `preflight_identity` SHA-256 hash checking; Server raises `HTTP 409 Conflict` if target changed after preflight. | **RESOLVED** |
| **DEF-2107** | **MEDIUM** | `webui/app.js` | Recovery scan lacked live multi-stage polling progress bar and explicit 0-candidate state. | Operator unsure of background worker progress. | Added `[ 📁 Browse Image ]`, multi-stage polling state machine (`PRECHECK` $\to$ `COMPLETED`), and explicit `SCAN COMPLETED — 0 CANDIDATES` empty state. | **RESOLVED** |
| **DEF-2108** | **LOW** | Codebase / Docs | Loose terminology mentioning "Merkle/blockchain" in audit logs. | Imprecise technical claims in documentation. | Cleaned and standardized across repository: **"Cryptographic SHA-256 Hash-Linked Audit Ledger"** and **"NIST SP 800-88 Rev. 2 ALIGNED"**. | **RESOLVED** |

---

## Verification Summary

All 8 identified defects have been remediated, covered by unit and integration tests in `tests/test_phase21_runtime_truth.py`, and verified in the live workstation environment.
