# DREX-V2 PHASE 2: EVIDENCE VAULT DIRECTORY & OBJECT MODEL

**Target Module**: [`forensic_vault.py`](file:///d:/drex-v2-main/forensic_vault.py) (`EvidenceVault`, `VaultObject`, `VaultObjectType`)  

---

## 1. Directory Structure

Each forensic case directory inside the Evidence Vault is structured as follows:

```
cases/<case_id>/
├── case.json                     # Primary case record
├── evidence.json                 # Evidence sources registry
├── timeline.json                 # Chronological timeline events
├── custody.json                  # Chain-of-custody ledger
├── vault_objects.json            # Index of all vault objects
├── source/                       # Seized disk images and original files
├── derived/                      # Bad-block maps, sector index logs
├── recovered/                    # Carved and reassembled artifacts
├── reports/                      # Validation logs and reports
├── certificates/                 # Signed ECDSA P-256 certificates
└── audit/
    └── audit_chain.json          # Merkle hash-chained audit ledger
```

---

## 2. Vault Object Schema

```python
@dataclass
class VaultObject:
    object_id: str                       # VLT-YYYYMMDD-HEX8
    case_id: str                         # Originating case identifier
    object_type: VaultObjectType         # SOURCE | DERIVED | RECOVERED | REPORT | CERTIFICATE | AUDIT
    relative_path: str                   # Path relative to case directory
    size_bytes: int                      # Exact size in bytes
    sha256_hash: str                     # Streaming SHA-256 digest
    created_at: str                      # UTC ISO 8601 timestamp
    source_evidence_id: Optional[str]    # Parent evidence source ID
    generating_operation_id: Optional[str] # Generating operation ID
    verification_state: str = "UNVERIFIED" # VERIFIED | UNVERIFIED | PARTIAL
    integrity_state: str = "VALID"       # VALID | CORRUPTED
    metadata: Dict[str, Any]             # Additional metadata
    schema_version: int = 1
```
