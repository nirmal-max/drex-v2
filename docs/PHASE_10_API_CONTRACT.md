# PHASE 10 MULTI-SURFACE API CONTRACT

## 1. REST Route Inventory

| Route | Method | Purpose | Role Authorization |
|---|---|---|---|
| `/api/auth/login` | POST | Authenticate persona and issue JWT | Public |
| `/api/auth/me` | GET | Retrieve authenticated user payload | Authenticated |
| `/api/auth/switch-persona` | POST | 1-Click Persona Switcher | All Personas |
| `/api/devices` | GET | Enumerate physical storage devices | Operator, Analyst, Admin |
| `/api/devices/{id}/qualification`| GET | Evaluate 25-method qualification matrix | Operator, Analyst, Admin |
| `/api/cases` | GET, POST | List cases / create new case | Investigator, Analyst, Admin |
| `/api/cases/{id}/timeline` | GET | Chronological typed timeline events | All Personas |
| `/api/evidence` | GET | List Evidence Vault items | Analyst, Auditor, Admin |
| `/api/recovery/scan` | POST | Launch non-blocking recovery scan | Analyst, Admin |
| `/api/recovery/candidates` | GET | Candidates with 5-factor confidence | Analyst, Auditor, Admin |
| `/api/sanitization/plan` | POST | Generate NIST 800-88 sanitization plan | Operator, Admin |
| `/api/sanitization/execute` | POST | Execute sanitization with safety phrase | Operator, Admin |
| `/api/sanitization/sector-grid` | GET | 64-Sector storage visualizer telemetry | All Personas |
| `/api/audit/ledger` | GET | Cryptographic SHA-256 audit ledger | Auditor, Reviewer, Admin |
| `/api/audit/verify` | POST | Verify SHA-256 hash-chain integrity | Auditor, Reviewer, Admin |
| `/api/verification/verify-package`| POST | Execute drex_verify.py Schema 2.0 | All Personas |
| `/api/methods/registry` | GET | Authoritative 25-method matrix | All Personas |
| `/api/demo/flow` | POST | Deterministic Judge Proof Loop (< 60s) | Judge, All Personas |

---

## 2. WebSocket Real-Time Telemetry

- **Endpoint**: `/ws/jobs`
- **Frames**: Bidirectional JSON frames streaming `JOB_PROGRESS`, `SECTOR_UPDATE`, `CANDIDATE_DISCOVERED`, and `LOG_ENTRY`.
