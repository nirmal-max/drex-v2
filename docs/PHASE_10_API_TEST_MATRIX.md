# DREX-V2 Phase 10 REST API Test Matrix

| METHOD | PATH | AUTHENTICATION | ROLE | REQUEST MODEL | SUCCESS STATUS | ERROR STATUS | BACKEND HANDLER | SAFE TEST | RESULT |
|:---|:---|:---|:---|:---|:---|:---|:---|:---|:---|
| GET | /api/audit/ledger | Bearer JWT | audit:read | None | 200 OK | 401 / 403 | case_manager.get_audit_chain | SHA-256 hash-linked audit ledger | **PASS** |
| GET | /api/auth/me | Bearer JWT | Authenticated | None | 200 OK | 401 Unauthorized | get_current_user | Valid vs expired/missing token | **PASS** |
| GET | /api/cases | Bearer JWT | cases:read | None | 200 OK | 401 / 403 | case_manager.list_cases | List recorded cases | **PASS** |
| GET | /api/cases/{case_id}/timeline | Bearer JWT | timeline:read | None | 200 OK | 401 / 403 | case_manager.get_timeline | Read hash-bound timeline ledger | **PASS** |
| GET | /api/devices | Bearer JWT | devices:read | None | 200 OK | 401 / 403 | drex_app.discover_drives | Read-only drive probe | **PASS** |
| GET | /api/devices/{device_id}/qualification | Bearer JWT | devices:qualify | None | 200 OK | 401 / 403 | evaluate_25_methods | 25-method qualification matrix | **PASS** |
| GET | /api/evidence | Bearer JWT | evidence:read | None | 200 OK | 401 / 403 | case_manager.list_evidence | List sealed evidence records | **PASS** |
| GET | /api/methods/registry | None (Public) | Public Inspection | None | 200 OK | 500 Internal Error | get_method_registry | Authoritative 25-method matrix | **PASS** |
| GET | /api/recovery/candidates | Bearer JWT | recovery:* | None | 200 OK | 401 / 403 | get_recovery_candidates | 5-factor explainable scoring | **PASS** |
| GET | /api/sanitization/sector-grid | Bearer JWT | residue/sanitization | None | 200 OK | 401 / 403 | get_sector_block_grid | 64-sector block entropy visualizer | **PASS** |
| POST | /api/audit/verify | Bearer JWT | audit:verify | None | 200 OK | 401 / 403 | verify_case_audit_chain | SHA-256 hash-linked audit chain tamper audit | **PASS** |
| POST | /api/auth/login | None (Public) | ANY | LoginRequest | 200 OK | 401 Unauthorized | rbac.create_access_token | Synthetic password auth | **PASS** |
| POST | /api/auth/switch-persona | None (Public Helper) | ANY | DemoPersonaSwitchRequest | 200 OK | 400 / 422 | rbac.create_access_token | Switch to all 6 roles | **PASS** |
| POST | /api/cases | Bearer JWT | cases:write | ForensicCaseCreate | 200 OK | 401 / 403 / 422 | case_manager.create_case | Create isolated case container | **PASS** |
| POST | /api/demo/flow | Bearer JWT | demo:run | None | 200 OK | 401 / 403 | execute_judge_demo_flow | Safe 6-step deterministic proof loop | **PASS** |
| POST | /api/recovery/scan | Bearer JWT | recovery:scan | RecoveryScanRequest | 200 OK | 401 / 403 / 422 | RecoveryDispatcher | Safe background thread worker | **PASS** |
| POST | /api/sanitization/execute | Bearer JWT | sanitization:execute | SanitizationExecuteRequest | 200 OK | 400 / 401 / 403 / 422 | execute_sanitization | Synthetic target + exact phrase | **PASS** |
| POST | /api/sanitization/plan | Bearer JWT | sanitization:plan | SanitizationPlanRequest | 200 OK | 401 / 403 / 422 | DeviceIntelligenceEngine | OS disk detection & phrase plan | **PASS** |
| POST | /api/verification/verify-package | Bearer JWT | verification:verify | Query(package_path) | 200 OK | 401 / 403 | IndependentPackageVerifier | Standalone schema 2.0 verification | **PASS** |
