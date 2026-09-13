# DREX-V2 PHASE 2: HASH-CHAINED AUDIT & TAMPER DETECTION MODEL

**Target Module**: [`forensic_vault.py`](file:///d:/drex-v2-main/forensic_vault.py) (`AuditEvent`, `IndependentAuditVerifier`, `AuditVerificationStatus`)  

---

## 1. Cryptographic Hash Chaining

The audit ledger maintains an unbroken SHA-256 Merkle chain:

$$H_0 = \text{SHA256}(\text{"0"}^{64} \parallel \text{canonical}(P_0))$$
$$H_i = \text{SHA256}(H_{i-1} \parallel \text{canonical}(P_i)) \quad \text{for } i \ge 1$$

Where $\text{canonical}(P)$ is deterministic, compact JSON encoding with sort-keyed keys and no extra whitespace (`json.dumps(P, sort_keys=True, separators=(",", ":"))`).

---

## 2. Audit Event Structure

```python
@dataclass
class AuditEvent:
    sequence_number: int                 # 0-indexed sequence counter
    event_id: str                        # AUD-YYYYMMDD-HEX8
    case_id: str                         # Originating case identifier
    timestamp: str                       # UTC ISO 8601
    actor: str                           # Examiner / subsystem
    event_type: str                      # CASE_CREATED, EVIDENCE_REGISTERED, etc.
    canonical_payload: Dict[str, Any]    # Exact immutable event payload
    previous_hash: str                   # Hash of sequence i-1 (or 64 zeros for Genesis)
    current_hash: str                    # SHA256(previous_hash || canonical(payload))
    operation_id: Optional[str] = None   # Associated operation ID
    schema_version: int = 1
```

---

## 3. Independent Audit Verifier Capabilities

`IndependentAuditVerifier` can inspect any audit ledger file offline and verify:
1. **Sequence Continuity**: Detects omitted or renumbered events.
2. **Hash Linkage**: Ensures $H_i$'s `previous_hash` equals $H_{i-1}$'s `current_hash`.
3. **Payload Authenticity**: Re-calculates $\text{SHA256}(H_{i-1} \parallel \text{canonical}(P_i))$ and compares against `current_hash`.
4. **Tamper Detection**: Returns specific diagnostics identifying the exact sequence index where tampering, insertion, or deletion occurred.
