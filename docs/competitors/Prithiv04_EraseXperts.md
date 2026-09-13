# COMPETITOR FORENSIC AUDIT: ARGUS / FORGE-X

## 1. Repository Identity & Metadata
- **Repository**: `Prithiv04/EraseXperts`
- **Primary Language / Framework**: Python / PyWebView / Solidity
- **License**: MIT
- **Provenance & Upstream Pedigree**: Original work by Prithiv & team (EraseXperts)
- **Reality Status**: `SOURCE_PROVEN & TEST_PROVEN`
- **Audit Confidence Level**: `VERY HIGH`

---

## 2. Architecture & Call-Flow Analysis
- **System Architecture**: Desktop suite using PyWebView, FastAPI/Flask bridge, 5-phase FORGE-X recovery engine, and Sepolia blockchain ledger.
- **Core Algorithms & Techniques**: 5-Phase FORGE-X engine (P1 metadata, P2 MFT, P3 format, P4 damaged, P5 fragment), VSS shadow copy purge, IBM QRNG quantum random entropy.

---

## 3. Technical Capabilities Breakdown

### A. Recovery Capabilities
- 5-phase recovery orchestrator traversing MFT, unallocated clusters, damaged sectors, and fragmented payloads.

### B. Sanitization Capabilities
- NIST SP 800-88 Rev 1 overwrite, firmware erase, VSS shadow copy purging (`kill_vss_shadows`), PDF certificate generation.

### C. Hardware & Storage Support
- Windows diskpart, PowerShell, TRIM commands, MTP helper.

### D. Evidence, Audit & Certification
- Ethereum Sepolia smart contract ledger (`WipeLog.sol`), PDF certificates, encrypted wipe log.

### E. User Interface & Experience
- PyWebView desktop interface with MetaMask bridge.

### F. Testing & Quality Assurance
- Automated test scripts.

---

## 4. Forensic Evaluation

### Strengths
- VSS shadow copy purging (`kill_vss_shadows`), 5-phase recovery classification, elegant PyWebView UI.

### Weaknesses & Limitations
- Blockchain ledger adds external internet dependency if enabled.

---

## 5. DREX-V2 Lessons & Integration Strategy
- **Key Lessons for DREX-V2**: Directly integrate VSS shadow copy purging into DREX sanitization routines.
- **Reusable Code / Components**: `kill_vss_shadows()` implementation and 5-phase recovery taxonomy.
- **Integration Decision**: `DIRECT_REUSE`
