# BASELINE TEST REPORT

## 1. Test Execution Summary
- **Execution Date**: 2026-09-13
- **Environment**: Windows 11 x86-64, Python 3.14.3, pytest 9.1.1
- **Working Directory**: `d:\drex-v2-main`
- **Total Tests Collected**: **236 tests** across 22 test files in `tests/`
- **Unit & Synthetic Tests Passed**: **100% Passed** (Zero test logic failures)
- **Physical Hardware Drive Tests**: Explicitly excluded during Phase 0 in strict accordance with the non-destructive safety principle (`-k "not physical"`).

---

## 2. Test Breakdown by Module

| Test Module | Test Focus | Tests Collected | Passed | Failed | Skipped |
|---|---|---|---|---|---|
| `test_edge_cases.py` | Zero-byte, single-byte, unicode, cancellation, timeouts | 8 | 8 | 0 | 0 |
| `test_folder_recovery.py` | Nested directory trees, empty folders, path safety | 5 | 5 | 0 | 0 |
| `test_lifecycle_regression.py` | Single Tk root, repeated navigation, device single-flight, thread affinity | 18 | 18 | 0 | 0 |
| `test_operation_result_and_verification.py` | VerificationEngine, 4-state verdicts, certificate wiring, 25 methods | 42 | 42 | 0 | 0 |
| `test_backend_adapters.py` | TSK/PhotoRec CLI builder, parser defenses, capability matrix | 28 | 28 | 0 | 0 |
| `test_recovery_backends.py` | Executable discovery, native_bin priority, fail-closed handling | 11 | 11 | 0 | 0 |
| `test_recovery_adapter.py` | Quick recovery parsing, normalized JSON shapes | 5 | 5 | 0 | 0 |
| `test_recovery_comprehensive.py` | Target collision safety, offset conversions, attribute parsing, process runner | 10 | 10 | 0 | 0 |
| `test_raid_and_forensic.py` | ddrescue parser, mmls parser, forensic ledger hash-chain integrity | 13 | 13 | 0 | 0 |
| `test_task_manager_and_perf.py` | Timer precision, progress tracking, task manager async lifecycle | 8 | 8 | 0 | 0 |
| `test_truthful_validation.py` | Physical vs fixture certificate contracts, byte counts, truth models | 11 | 11 | 0 | 0 |
| `test_ui_pages.py` | Render testing for all 25 UI workstation pages | 1 | 1 | 0 | 0 |
| `test_advanced_recovery_engines.py` | Fragment carving, ZIP container parsing, JPEG MCU validation | 15 | 15 | 0 | 0 |
| `test_all_25_methods.py` | Contract validation for all 25 sanitization and recovery methods | 25 | 25 | 0 | 0 |
| `test_app.py` | App startup and initial state checks | 4 | 4 | 0 | 0 |
| *Physical test modules (e.g. `physical_usb_test.py`)* | Hardware-only USB tests | 32 | *Excluded in Phase 0* | 0 | 32 |

---

## 3. Discrepancy Resolution
- Historical document `25_METHOD_STATUS.json` referenced "81 regression tests" from an early subset run.
- The actual current repository test suite contains **236 collected tests**.
- This discrepancy is permanently resolved and documented: the true executable baseline is **236 tests**.
