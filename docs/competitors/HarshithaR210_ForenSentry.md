# COMPETITOR FORENSIC AUDIT: ForenSentry

## 1. Repository Identity & Metadata
- **Repository**: `HarshithaR210/ForenSentry`
- **Primary Language / Framework**: Python / Flask / React
- **License**: MIT
- **Provenance & Upstream Pedigree**: Original work by Harshitha & team for SIH 2026
- **Reality Status**: `SOURCE_PROVEN`
- **Audit Confidence Level**: `HIGH`

---

## 2. Architecture & Call-Flow Analysis
- **System Architecture**: Full DFIR workstation with React frontend, Flask backend, SQLite database, and isolated lab sandbox.
- **Core Algorithms & Techniques**: Signature carving, hash-chained audit logging, isolated lab safety boundary.

---

## 3. Technical Capabilities Breakdown

### A. Recovery Capabilities
- Forensic signature carving for PNG, JPEG, GIF, PDF, ZIP with structural validation badges.

### B. Sanitization Capabilities
- Secure erasure confined to managed `data/lab` workspace to guarantee zero physical device damage during evaluations.

### C. Hardware & Storage Support
- Read-only device inventory (WMI/OS volumes).

### D. Evidence, Audit & Certification
- Evidence Vault (SHA-256/SHA-512 hashes), hash-chained audit log, case management with investigator notes.

### E. User Interface & Experience
- Polished React operations dashboard.

### F. Testing & Quality Assurance
- Pytest unit tests.

---

## 4. Forensic Evaluation

### Strengths
- Exemplary case management and evidence vault, strict safety boundary protecting host devices.

### Weaknesses & Limitations
- Erasure deliberately confined to lab directory.

---

## 5. DREX-V2 Lessons & Integration Strategy
- **Key Lessons for DREX-V2**: Incorporate Case Management investigator notes and Evidence Vault UI layout into DREX.
- **Reusable Code / Components**: Case management data structures and evidence vault layout.
- **Integration Decision**: `DIRECT_REUSE`
