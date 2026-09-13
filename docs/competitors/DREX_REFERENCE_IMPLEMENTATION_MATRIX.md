# DREX REFERENCE IMPLEMENTATION MATRIX

## 1. Premier Implementations by Domain

### 1. Evidence Integrity & Witness Attestation
- **Source Repository**: `pulkit6732/AKHANDA`
- **Source Technique**: Multi-party independent witness node co-signing with Ed25519 & Kyber post-quantum envelopes.
- **Why It Is Strong**: Guarantees evidence records cannot be forged by a single compromised examiner machine.
- **What DREX Should Learn**: Co-signer boundary separation; independent validation endpoint.
- **What DREX Should NOT Copy**: Overly complex multi-container Docker swarm setups for single-node desktop evaluations.
- **License / Priority**: Apache-2.0 / `HIGH`

---

### 2. Fragment Reconstruction
- **Source Repository**: `MithunRayakota07/resurgence-forensics` & `pulkit6732/AKHANDA`
- **Source Technique**: JPEG MCU boundary stream decoding + ZIP container CRC-32 central directory reassembly.
- **Why It Is Strong**: Recovers non-contiguous and out-of-order files where forward-only carvers fail.
- **What DREX Should Learn**: JPEG MCU desynchronization detection as a hard search constraint.
- **What DREX Should NOT Copy**: Slow brute-force quadratic search across entire 1TB disk volumes without bounding heuristics.
- **License / Priority**: MIT & Apache-2.0 / `HIGH`

---

### 3. Verification & Entropy Measurement
- **Source Repository**: `K01SR/SecureForge` & `Vigneshe247/Secure-Data-Erasure-Recovery`
- **Source Technique**: Mathematical Shannon entropy calculation ($H(X) = -\sum P(x) \log_2 P(x)$) over 64-sector sample grids + 4-State scientific verdict.
- **Why It Is Strong**: Replaces subjective pass/fail claims with rigorous statistical physics measurements.
- **What DREX Should Learn**: Entropy heatmap visualization and 4-state verdict classification.
- **What DREX Should NOT Copy**: Full-drive sequential entropy calculations that block UI responsiveness.
- **License / Priority**: MIT / `CRITICAL`

---

### 4. Shadow Storage & Residue Neutralization
- **Source Repository**: `Prithiv04/EraseXperts` & `devil-net`
- **Source Technique**: `kill_vss_shadows()` via `vssadmin` + MFT filename/timestamp randomization.
- **Why It Is Strong**: Prevents forensic examiners from restoring files via hidden volume snapshots.
- **What DREX Should Learn**: VSS shadow copy purge integration.
- **What DREX Should NOT Copy**: Unchecked elevation assumptions that crash without error messages on non-admin terminals.
- **License / Priority**: MIT / `HIGH`
