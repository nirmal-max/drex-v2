# DREX-V2 PHASE 2: FORENSIC CASE MODEL

**Target Module**: [`forensic_vault.py`](file:///d:/drex-v2-main/forensic_vault.py) (`ForensicCase`, `CaseStatus`, `ForensicCaseManager`)  

---

## 1. Schema & Field Definitions

```python
@dataclass
class ForensicCase:
    case_id: str                   # Unique stable identifier: CASE-YYYYMMDD-HEX8
    case_number: str               # Human-readable reference: e.g. CR-2026-0042
    title: str                     # Case descriptive title
    description: str               # Summary of investigation
    examiner: str                  # Lead forensic investigator
    organization: str              # Law enforcement / enterprise agency
    created_at: str                # UTC ISO 8601 timestamp
    updated_at: str                # UTC ISO 8601 timestamp
    status: CaseStatus = CaseStatus.OPEN   # OPEN | ACTIVE | PAUSED | CLOSED | ARCHIVED
    classification: str = "CONFIDENTIAL"  # Sensitivity level
    notes: List[str]               # Chronological investigative notes
    tags: List[str]                # Categorization keywords
    timezone: str = "UTC"          # Timezone context
    schema_version: int = 1        # Version integer
```

---

## 2. State Lifecycle Machine

```
   ┌──────────┐
   │   OPEN   │ ◄── Case created by examiner
   └────┬─────┘
        │ Start investigation
        ▼
   ┌──────────┐
   │  ACTIVE  │ ◄── Operations in progress (acquisition/recovery/sanitization)
   └────┬─────┘
        ├─────────────┐
        ▼             ▼
   ┌──────────┐ ┌──────────┐
   │  PAUSED  │ │  CLOSED  │ ◄── Investigation concluded & certificates verified
   └────┬─────┘ └────┬─────┘
        │            │
        └────────────┼─────────────┐
                     ▼             ▼
               ┌──────────┐  ┌──────────┐
               │  ACTIVE  │  │ ARCHIVED │ ◄── Sealed case package exported
               └──────────┘  └──────────┘
```

---

## 3. Atomic Persistence & Validation

Cases are serialized to `case.json` using `safe_atomic_json_write`, ensuring that concurrent writes or unexpected process termination cannot corrupt case state.
Every case creation and status transition automatically generates corresponding events in `timeline.json` and `audit_chain.json`.
