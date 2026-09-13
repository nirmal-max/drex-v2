# COMPETITOR FORENSIC AUDIT: Resurgence

## 1. Repository Identity & Metadata
- **Repository**: `MithunRayakota07/resurgence-forensics`
- **Primary Language / Framework**: Python 3.10+
- **License**: MIT
- **Provenance & Upstream Pedigree**: Original research by Mithun Rayakota
- **Reality Status**: `SOURCE_PROVEN & TEST_PROVEN`
- **Audit Confidence Level**: `VERY HIGH`

---

## 2. Architecture & Call-Flow Analysis
- **System Architecture**: Pure-Python forensic carving and anti-forensic residue analysis toolkit.
- **Core Algorithms & Techniques**: Out-of-order JPEG MCU boundary entropy decoding, MFT resident file scrubbing.

---

## 3. Technical Capabilities Breakdown

### A. Recovery Capabilities
- Non-contiguous and backward-jumping JPEG fragment reconstruction using MCU stream desynchronization detection.

### B. Sanitization Capabilities
- MFT unallocated record scrubbing and cluster-tip zeroing.

### C. Hardware & Storage Support
- Raw disk image files (`.img`, `.raw`).

### D. Evidence, Audit & Certification
- Ed25519-signed NIST SP 800-88r2 Appendix C certificates recording checked and unchecked paths.

### E. User Interface & Experience
- CLI interface (`resurgence-carve`).

### F. Testing & Quality Assurance
- Automated test harness against `hard.img` and `easy.img` corpora.

---

## 4. Forensic Evaluation

### Strengths
- Honest documentation of limitations (scores 0/6 on NIST CFReDS benchmark), breakthrough out-of-order JPEG MCU decoding.

### Weaknesses & Limitations
- Slow execution time (tens of seconds per complex file).

---

## 5. DREX-V2 Lessons & Integration Strategy
- **Key Lessons for DREX-V2**: Directly integrate JPEG MCU stream validation into DREX Method 22 (Fragment Recovery).
- **Reusable Code / Components**: `resurgence/carve.py` (`JpegEntropyDecoder`).
- **Integration Decision**: `REUSE_WITH_ADAPTATION`
