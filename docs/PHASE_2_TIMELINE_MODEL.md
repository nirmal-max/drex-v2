# DREX-V2 PHASE 2: FORENSIC TIMELINE MODEL

**Target Module**: [`forensic_vault.py`](file:///d:/drex-v2-main/forensic_vault.py) (`ForensicTimelineEvent`, `TimelineEventType`)  

---

## 1. Timeline Event Schema

```python
@dataclass
class ForensicTimelineEvent:
    event_id: str                        # EVT-YYYYMMDD-HEX8
    case_id: str                         # Originating case identifier
    timestamp: str                       # UTC ISO 8601 timestamp
    event_type: TimelineEventType        # Typed enum
    actor: str                           # Investigator or service
    description: str                     # Human-readable event description
    source: str                          # Component name
    operation_id: Optional[str] = None   # Associated operation identifier
    evidence_id: Optional[str] = None    # Associated evidence identifier
    metadata: Dict[str, Any]             # Structured event context
    integrity_hash: str                  # SHA-256 hash of canonical event fields
    schema_version: int = 1
```

---

## 2. Event Types Supported

- `CASE_CREATED`, `CASE_UPDATED`
- `EVIDENCE_ADDED`, `EVIDENCE_HASHED`, `EVIDENCE_ACQUIRED`
- `RECOVERY_STARTED`, `RECOVERY_COMPLETED`, `RECOVERY_FAILED`
- `SANITIZATION_PLANNED`, `SANITIZATION_CONFIRMED`, `SANITIZATION_STARTED`, `SANITIZATION_COMPLETED`, `SANITIZATION_FAILED`
- `VERIFICATION_STARTED`, `VERIFICATION_COMPLETED`
- `CERTIFICATE_CREATED`, `CERTIFICATE_VERIFIED`
- `AUDIT_EVENT`, `EXPORT_CREATED`, `CUSTODY_CHANGE`
