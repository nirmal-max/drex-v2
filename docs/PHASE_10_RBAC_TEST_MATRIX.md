# DREX-V2 Phase 10 Granular RBAC Test Matrix

All role permissions are strictly enforced server-side via FastAPI dependency injection (`require_permission` / `require_any_permission`). Unauthorized calls return `401 Unauthorized` (missing/invalid token) or `403 Forbidden` (insufficient role permissions). Frontend visibility is NOT considered authorization.

| METHOD | ENDPOINT | REQUIRED PERMISSION | ADMIN | FORENSIC_ANALYST | INVESTIGATOR | OPERATOR | AUDITOR | JUDGE_DEMO |
|:---|:---|:---|:---:|:---:|:---:|:---:|:---:|:---:|
| `GET` | `/api/auth/me` | `Authenticated` | **ALLOW (200)** | **ALLOW (200)** | **ALLOW (200)** | **ALLOW (200)** | **ALLOW (200)** | **ALLOW (200)** |
| `GET` | `/api/devices` | `devices:read` | **ALLOW (200)** | **ALLOW (200)** | **ALLOW (200)** | **ALLOW (200)** | DENY (403) | **ALLOW (200)** |
| `GET` | `/api/devices/{id}/qualification` | `devices:qualify` | **ALLOW (200)** | **ALLOW (200)** | DENY (403) | **ALLOW (200)** | DENY (403) | **ALLOW (200)** |
| `GET` | `/api/cases` | `cases:read` | **ALLOW (200)** | **ALLOW (200)** | **ALLOW (200)** | **ALLOW (200)** | **ALLOW (200)** | **ALLOW (200)** |
| `POST` | `/api/cases` | `cases:write` | **ALLOW (200)** | **ALLOW (200)** | **ALLOW (200)** | DENY (403) | DENY (403) | **ALLOW (200)** |
| `GET` | `/api/cases/{id}/timeline` | `timeline:read` | **ALLOW (200)** | **ALLOW (200)** | **ALLOW (200)** | DENY (403) | **ALLOW (200)** | **ALLOW (200)** |
| `GET` | `/api/evidence` | `evidence:read` | **ALLOW (200)** | **ALLOW (200)** | **ALLOW (200)** | **ALLOW (200)** | **ALLOW (200)** | **ALLOW (200)** |
| `POST` | `/api/recovery/scan` | `recovery:scan` | **ALLOW (200)** | **ALLOW (200)** | DENY (403) | DENY (403) | DENY (403) | **ALLOW (200)** |
| `GET` | `/api/recovery/candidates` | `recovery:read / extract` | **ALLOW (200)** | **ALLOW (200)** | **ALLOW (200)** | DENY (403) | DENY (403) | **ALLOW (200)** |
| `POST` | `/api/sanitization/plan` | `sanitization:plan` | **ALLOW (200)** | **ALLOW (200)** | DENY (403) | **ALLOW (200)** | DENY (403) | **ALLOW (200)** |
| `POST` | `/api/sanitization/execute` | `sanitization:execute` | **ALLOW (200)** | DENY (403) | DENY (403) | **ALLOW (200)** | DENY (403) | **ALLOW (200)** |
| `GET` | `/api/sanitization/sector-grid` | `residue:analyze / plan` | **ALLOW (200)** | **ALLOW (200)** | DENY (403) | **ALLOW (200)** | DENY (403) | **ALLOW (200)** |
| `GET` | `/api/audit/ledger` | `audit:read` | **ALLOW (200)** | **ALLOW (200)** | **ALLOW (200)** | DENY (403) | **ALLOW (200)** | **ALLOW (200)** |
| `POST` | `/api/audit/verify` | `audit:verify` | **ALLOW (200)** | DENY (403) | DENY (403) | DENY (403) | **ALLOW (200)** | **ALLOW (200)** |
| `POST` | `/api/verification/verify-package` | `verification:verify` | **ALLOW (200)** | **ALLOW (200)** | **ALLOW (200)** | **ALLOW (200)** | **ALLOW (200)** | **ALLOW (200)** |
| `POST` | `/api/demo/flow` | `demo:run` | **ALLOW (200)** | **ALLOW (200)** | **ALLOW (200)** | **ALLOW (200)** | **ALLOW (200)** | **ALLOW (200)** |
