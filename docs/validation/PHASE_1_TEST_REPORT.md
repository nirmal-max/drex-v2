# PHASE 1 TEST REPORT & REGRESSION BASELINE

## 1. Test Session Overview
- **Date / Timestamp**: 2026-09-13T18:07:02Z
- **Platform**: Windows 11 (win32) / Python 3.14.3 / pytest 9.1.1
- **Total Test Cases Collected**: 255
- **Passed**: 255 (100.0%)
- **Failed**: 0 (0.0%)
- **Skipped / XFailed**: 0
- **Execution Time**: 80.04s

---

## 2. Test Suite Breakdown

| Test File | Test Count | Status | Description |
| :--- | :--- | :--- | :--- |
| `tests/test_advanced_recovery_engines.py` | 9 | PASS | Advanced recovery pipeline & candidate aggregation |
| `tests/test_all_25_methods.py` | 15 | PASS | 25 method inventory, uniqueness, safety guards, and execution |
| `tests/test_app.py` | 4 | PASS | Core application bootstrap & GUI token stability |
| `tests/test_backend_adapters.py` | 34 | PASS | TSK, PhotoRec, and ddrescue command construction & parsers |
| `tests/test_edge_cases.py` | 8 | PASS | Boundary limits, corrupt headers, empty files, and error paths |
| `tests/test_folder_recovery.py` | 5 | PASS | Directory tree reconstruction and recursive folder recovery |
| `tests/test_lifecycle_regression.py` | 25 | PASS | Full lifecycle state transitions, event emissions, and stress cycles |
| `tests/test_operation_result_and_verification.py` | 73 | PASS | VerificationEngine assess branches, OperationResult fields, thread safety |
| `tests/test_phase1_competitor_integrations.py` | 19 | PASS | **Phase 1 Engines**: FragmentReassembler, JpegEntropyDecoder, ZipCarveStream, DeepCarverEngine, NtfsBitmapAnalyzer, EntropyEngine, VssSanitizer |
| `tests/test_raid_and_forensic.py` | 13 | PASS | RAID reconstruction, parity validation, and forensic timeline |
| `tests/test_recovery_adapter.py` | 5 | PASS | RecoveryTarget safety, path isolation, and candidate dataclass |
| `tests/test_recovery_backends.py` | 14 | PASS | Native binary path detection and backend status reporting |
| `tests/test_recovery_comprehensive.py` | 11 | PASS | End-to-end synthetic recovery validation |
| `tests/test_task_manager_and_perf.py` | 8 | PASS | Asynchronous task scheduling, cancellation, and concurrency |
| `tests/test_truthful_validation.py` | 11 | PASS | Truthful reporting, no simulation claims on real hardware |
| `tests/test_ui_pages.py` | 1 | PASS | UI layout, view switching, and design token adherence |

---

## 3. Regression Comparison vs Phase 0 Baseline

- **Phase 0 Baseline Tests**: 236 passed
- **Phase 1 Tests**: 255 passed (+19 new integration tests)
- **Regressions**: 0
- **Flaky Tests**: 0
- **Safety Violation Checks**: 100% passed (All physical device actions blocked, synthetic fixtures only).
