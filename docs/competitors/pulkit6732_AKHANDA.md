# COMPETITOR FORENSIC AUDIT: AKHANDA

## 1. Repository Identity & Metadata
- **Repository**: `pulkit6732/AKHANDA`
- **Primary Language / Framework**: Python 3.11 / React / WebSockets
- **License**: Apache-2.0 (with complete `NOTICE` file)
- **Provenance & Upstream Pedigree**: Original work by Pulkit & AKHANDA team (Smart India Hackathon 2026)
- **Reality Status**: `SOURCE_PROVEN & TEST_PROVEN`
- **Audit Confidence Level**: `VERY HIGH`

---

## 2. Architecture & Call-Flow Analysis
- **System Architecture**: Modular microservices architecture separating cryptographic witness nodes, core erasure/recovery dispatchers, presence discovery, and React UI.
- **Core Algorithms & Techniques**: Fragment reassembly (`reassemble.py`), ZIP container carving (`zipcarve.py`), hybrid Ed25519 + Kyber post-quantum signatures, Merkle case ledger.

---

## 3. Technical Capabilities Breakdown

### A. Recovery Capabilities
- Pure-Python fragment reassembly engine capable of evaluating candidate sequences and validating container structures.
- Stream-based ZIP carving matching local file headers against Central Directory Records and CRC-32 checksums.

### B. Sanitization Capabilities
- Multi-tier media sanitization (NIST SP 800-88 Rev. 2 Clear/Purge).
- Device-level command block generation for ATA Secure Erase and NVMe Sanitize.
- Multi-pass CSPRNG random pattern overwrites with readback assertions.

### C. Hardware & Storage Support
- Android MTP device probing (`mtp_identity.ps1`), USB device guards, physical drive handle management.

### D. Evidence, Audit & Certification
- Multi-party independent witness node co-signing (`akhanda/src/witness/node.py`).
- Ed25519 tamper-evident certificates with hash-chained history.

### E. User Interface & Experience
- React web dashboard + interactive terminal console interface (`console-app/`).

### F. Testing & Quality Assurance
- 40+ pytest suites covering crypto, attestation, reassembly, scale, and fail-closed tiers.

---

## 4. Forensic Evaluation

### Strengths
- Unmatched cryptographic witness architecture, pure-Python fragment reconstruction, honest fail-closed error handling.

### Weaknesses & Limitations
- Multi-container architecture adds deployment complexity for single-node standalone forensic boot environments.

---

## 5. DREX-V2 Lessons & Integration Strategy
- **Key Lessons for DREX-V2**: Integrate pure-Python fragment reassembly (`reassemble.py`) and ZIP carving (`zipcarve.py`) into DREX Method 22.
- **Reusable Code / Components**: `akhanda/src/recovery/reassemble.py` and `akhanda/src/recovery/zipcarve.py`
- **Integration Decision**: `REUSE_WITH_ADAPTATION`
