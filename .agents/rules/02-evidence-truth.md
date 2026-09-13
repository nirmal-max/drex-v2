# Evidence and Truth Model Rule

## Core Rules
1. **Chain of Custody**: Every operation produces a signed event entry with monotonic timestamps, target identifiers, operator role, and SHA-256 state hash.
2. **Hash Integrity**: Dual hashing (SHA-256 + Blake3/FNV) is computed for all recovered files and post-sanitization readback samples.
3. **Entropy Measurement**: Post-erasure verification requires Shannon entropy sampling ($H(X) = -\sum P(x) \log_2 P(x)$) over unallocated sectors.
4. **4-State Verdicts**: Verification engines must return one of:
   - `PASSED`: Zero residual pattern verified across 100% of sample LBAs.
   - `PASSED_WITH_WARNING`: Minor unreadable bad sectors encountered but no evidence remains.
   - `FAILED`: Residual identifiable magic bytes or non-zero patterns detected.
   - `INCONCLUSIVE`: Controller blocked verification readback.
