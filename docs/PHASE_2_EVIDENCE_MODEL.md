# DREX-V2 PHASE 2: EVIDENCE SOURCE & VAULT MODEL

**Target Module**: [`forensic_vault.py`](file:///d:/drex-v2-main/forensic_vault.py) (`EvidenceSource`, `EvidenceSourceType`, `EvidenceVault`, `VaultObject`, `StreamingHasher`)  

---

## 1. Schema & Field Definitions

```python
@dataclass
class EvidenceSource:
    evidence_id: str                     # Unique stable identifier: EVID-YYYYMMDD-HEX8
    case_id: str                         # Originating case identifier
    source_type: EvidenceSourceType      # PHYSICAL_DEVICE | DISK_IMAGE | FILE | ...
    source_path: str                     # Path or physical drive string (e.g. \\.\PhysicalDrive1)
    device_identity: Optional[str]       # Model/identifier if known
    model: Optional[str]                 # Manufacturer model
    serial: Optional[str]                # Hardware serial number (explicit None if unknown)
    transport: Optional[str]             # SATA | NVME | USB | PCIE
    capacity: Optional[int]              # Exact size in bytes
    filesystem: Optional[str]            # NTFS | FAT32 | exFAT | ext4
    acquisition_timestamp: str           # UTC ISO 8601 acquisition time
    source_hash: Optional[str]           # Streaming SHA-256 digest on intake
    examiner: str                        # Acquiring investigator
    provenance: str                      # Chain of intake provenance
    read_only: bool                      # Write-blocker state flag
    acquisition_method: str              # LOGICAL | BITSTREAM_IMAGE | LIVE_SECTOR
    acquisition_status: str              # ACQUIRED | VERIFIED | PENDING
    limitations: List[str]               # Known hardware/bus constraints
    metadata: Dict[str, Any]             # Additional hardware telemetry
    schema_version: int = 1              # Version integer
```

---

## 2. Truthful Metadata Policy

- **No Hardware Fabrication**: If serial number, firmware revision, or geometry is not reported by the controller/bus, the field is explicitly recorded as `None`.
- **Streaming Intake Hashing**: When a file or disk image is registered, `StreamingHasher` computes its SHA-256 digest in 64 KB chunks without loading the entire payload into RAM.
- **Initial Custody Record**: Registering an evidence item automatically writes a `RECEIVED` event into `custody.json`.
