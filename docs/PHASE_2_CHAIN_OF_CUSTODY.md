# DREX-V2 PHASE 2: CHAIN OF CUSTODY MODEL
 
**Target Module**: [`forensic_vault.py`](file:///d:/drex-v2-main/forensic_vault.py) (`ChainOfCustodyRecord`, `CustodyAction`, `IndependentCustodyVerifier`, `CustodyVerificationStatus`, `CustodyVerificationResult`)  
 
---
 
## 1. Schema & Field Definitions
 
```python
@dataclass
class ChainOfCustodyRecord:
    custody_event_id: str                # CUST-YYYYMMDD-HEX8
    evidence_id: str                     # Associated evidence ID
    case_id: str                         # Associated case ID
    custodian: str                       # Individual responsible
    action: CustodyAction                # RECEIVED | TRANSFERRED | ACCESSED | ...
    timestamp: str                       # UTC ISO 8601 timestamp
    reason: str                          # Purpose of action / transfer
    source_location: str                 # Originating location / storage
    destination: str                     # Destination workstation / vault
    hash_before: Optional[str] = None    # SHA-256 before custodial action
    hash_after: Optional[str] = None     # SHA-256 after custodial action
    notes: str = ""                      # Supplementary notes
    integrity_reference: str = ""        # SHA-256 digest of canonical record
    schema_version: int = 1
```
 
---
 
## 2. Supported Custodial Actions
 
- `RECEIVED`: Initial evidence seizure and intake into vault.
- `TRANSFERRED`: Relocation between examiners, labs, or storage lockers.
- `ACCESSED`: Opened for inspection or read-only mounting.
- `COPIED`: Bitstream imaging or logical export.
- `ANALYZED`: Carving, fragment reassembly, or forensic metadata indexing.
- `EXPORTED`: Packaging into court-admissible archive.
- `SEALED`: Cryptographic locking and write-protection.
- `RELEASED`: Returned to lawful owner or submitted to judicial registry.
 
---
 
## 3. Cryptographic Immutability & Independent Verification
 
1. **Per-Record Integrity**: Every custody mutation calculates a deterministic SHA-256 `integrity_reference` digest over its canonical JSON encoding.
2. **Audit Ledger Binding**: Every `record_custody_event` operation emits a matching `CUSTODY_CHANGE` event onto the hash-chained Merkle audit ledger (`audit_chain.json`).
3. **Independent Verification (`IndependentCustodyVerifier`)**:
   - Recomputes SHA-256 `integrity_reference` for all records (`TAMPERED_RECORD` on mismatch).
   - Validates that recorded custody events match the Merkle audit chain in sequence, preventing deletion or reordering of custody events (`AUDIT_MISMATCH`).
