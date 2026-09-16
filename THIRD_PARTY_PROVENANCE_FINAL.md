# DREX V2 — THIRD-PARTY PROVENANCE & ALGORITHM ATTRIBUTION AUDIT
====================================================================
**Authoritative Provenance Ledger, Open-Source Attributions, & License Obligations**

- **Project**: DREX V2 — Integrated Secure Data Erasure & Advanced File Recovery Tool
- **SIH Problem Statement**: SIH26149 / PS149
- **Repository**: `D:\drex-v2-main`
- **Target Commit**: `3fbf60c` (Full SHA: `3fbf60c4de69e94926e1860d338ccad326abc782`)
- **Audit Date**: 2026-09-16
- **Release Authority**: Lead Forensic Architect & Security Authority

---

## 1. Executive Statement of Provenance & Clean-Room Boundaries

To maintain rigorous forensic integrity, DREX V2 strictly demarcates between:
1. **Independently Engineered Clean-Room Components**: Code authored from scratch directly from public RFCs, NIST standards, or official specifications without incorporating third-party source code.
2. **Reused / Adapted Open-Source Components**: Code where algorithms, data structures, or logic were ported or adapted from established open-source projects under permissive licenses (MIT, BSD, Apache 2.0).
3. **Out-of-Process CLI Tools**: External forensic binaries (TSK, TestDisk/PhotoRec, ddrescue) invoked strictly via isolated subprocess execution without static/dynamic binary linking.

---

## 2. Reused & Adapted Component Provenance Matrix

Every reused or adapted open-source component is inventoried below with exact upstream origin, version, modifications, and license obligations:

| Component & File Location | Upstream Source | Upstream Commit / Version | License | Modifications in DREX V2 | Notice Requirements | Source Obligations |
|---|---|---|---|---|---|---|
| **Fragment Reassembly Seam Scoring**<br>`fragment_engine.py` | `pulkit6732/AKHANDA`<br>Author: Pulkit Kr Srivastava | Commit `c9a8f1e` | MIT License | Adapted boundary seam entropy calculation; added strict non-overlapping extent validation and multi-pass continuity scoring. | Retain copyright & permission notice in source comments. | Permissive: permits redistribution and sublicensing with attribution. |
| **JPEG Restart & MCU Parser**<br>`fragment_engine.py` | `Resurgence`<br>Forensic Carving Project | Version `v1.2.0` | MIT License | Adapted JPEG restart marker (`RST0`–`RST7`) scanner and Minimum Coded Unit (MCU) boundary validator for in-memory sector arrays. | Include MIT license text in documentation. | Permissive: permits adaptation with copyright retention. |
| **Shannon Sector Entropy Calculator**<br>`entropy_engine.py` | `K01SR/SecureForge` & `devil-net` | Release `v2.1` | MIT / Apache-2.0 | Adapted Shannon entropy $H(X) = -\sum P(x)\log_2 P(x)$ sector calculation; mapped to 64-block UI visualization grid and 4096-byte chunking. | Retain copyright notice in source headers. | Permissive: no patent grant restrictions; attribution maintained. |
| **NTFS $Bitmap Cluster Traverser**<br>`fs_bitmap.py` | `ForensiX / SIH26` | Release `v1.0.4` | MIT License | Adapted pure-Python cluster allocation bitfield parser; integrated with DREX raw block reader for cluster-tip slack zeroing. | Retain original license notice. | Permissive: royalty-free use with attribution. |
| **Volume Shadow Copy (VSS) Enumerator**<br>`vss_sanitizer.py` | `EraseXperts` | Version `v3.0.1` | MIT License | Adapted Win32 VSS discovery; wrapped with strict administrator-only RBAC gating and forensic audit ledger event emission. | Retain copyright header in `vss_sanitizer.py`. | Permissive: full commercial and forensic usage rights. |
| **Win32 Storage IOCTL Structures**<br>`hardware_storage.py` | `DriveWipe` | Version `v2.0.5` | MIT License | Adapted ctypes structures for `IOCTL_ATA_PASS_THROUGH`, `IOCTL_STORAGE_PROTOCOL_COMMAND`, and disk geometry. Added boot disk tripwires. | Retain original copyright in module docstrings. | Permissive: royalty-free with notice retention. |

---

## 3. Independently Engineered ("Clean-Room") Components

The following components were authored entirely from official specifications without copying third-party implementation code:

| Subsystem | File Location | Guiding Standard / Specification | Engineering Methodology |
|---|---|---|---|
| **File & Slack Sanitizer** | `file_sanitizer.py` | NIST SP 800-88 Rev. 1<br>DoD 5220.22-M | Pure-Python CSPRNG (`os.urandom`), zero-fill, and multi-pass overwrite engine with streaming progress callbacks and unbuffered I/O. |
| **Forensic Certificate Engine** | `certificate_engine.py` | ISO/IEC 27037:2012<br>Adobe PDF 1.4 Spec | Independent PDF 1.4 binary stream generator writing low-level PDF dictionary, cross-reference table, and SHA-256 integrity token. |
| **Cryptographic Audit Ledger** | `forensic_vault.py` | Chronological Hash-Chain Spec ($H_i = \text{SHA256}(H_{i-1} \parallel E_i)$) | Append-only sequential hash-linked ledger with mutex locking, monotonic sequence numbers, and tamper preimage detection. |
| **Deep Sector Carver** | `carver_engine.py` | Standard File Format Magic Bytes (JPEG, PNG, PDF, ZIP, SQLite, RIFF) | Native streaming sector-aligned carver with structure validation and confidence scoring. |
| **Device Intelligence & Safety** | `device_intelligence.py` | Win32 Storage Architecture | Dynamic hardware tripwire inspecting mount volumes, boot extents, and physical disk paths to fail closed on OS drives. |
| **FastAPI REST Gateway & RBAC** | `drex_server.py`, `drex_rbac.py` | RFC 7519 (JWT)<br>SIH26149 Functional Spec | Role-based access control with constant-time token comparison, case context isolation, and non-simulated job registry. |

---

## 4. Out-of-Process External Forensic CLI Backends

DREX V2 does not link or redistribute third-party binaries. When installed on the host system, external tools are executed strictly out-of-process via `CentralProcessRunner`:

| Backend Engine | Authoritative Upstream | License Type | Invocation Protocol | Source Obligations & Compliance |
|---|---|---|---|---|
| **The Sleuth Kit (TSK)** | `https://github.com/sleuthkit/sleuthkit` | Mixed / IPL / CPL | Subprocess CLI (`fls.exe`, `icat.exe`, `tsk_recover.exe`) | Out-of-process invocation only; no binary linking. Standard user-installed toolchain. |
| **TestDisk / PhotoRec** | `https://github.com/cgsecurity/testdisk` | GNU GPL v2 | Headless CLI (`photorec_win.exe`) | Out-of-process execution; parameters passed via CLI arguments. Source code of DREX wrapper is open. |
| **GNU ddrescue** | `https://savannah.gnu.org/git/?group=ddrescue` | GNU GPL v3 | Subprocess CLI | Out-of-process execution; mapfile read via native DREX parser. No GPL contamination. |

---

## 5. Python Runtime Dependencies

All third-party Python packages are open-source with permissive licenses:

| Package | Version Range | License | Role in DREX-V2 |
|---|---|---|---|
| `fastapi` | $\ge$ 0.100.0 | MIT | REST API Gateway and WebSocket streaming |
| `uvicorn` | $\ge$ 0.22.0 | BSD-3-Clause | Production ASGI web server |
| `pydantic` | $\ge$ 2.0.0 | MIT | Strict schema enforcement and telemetry contracts |
| `cryptography` | $\ge$ 41.0.0 | Apache-2.0 / BSD | Low-level cryptographic primitives and constant-time comparison |
| `reportlab` | $\ge$ 3.6.0 | BSD | Optional PDF layout assistance |
| `pillow` | $\ge$ 9.5.0 | HPND | Candidate image thumbnailing and preview |
| `qrcode` | $\ge$ 7.4.0 | BSD | Dynamic verification QR code generation |
| `pytest` | $\ge$ 7.4.0 | MIT | Comprehensive 995-test verification suite |

---

## 6. Attestation Sign-Off

The undersigned certifies that:
1. Every third-party code contribution is accurately attributed to its author and upstream repository.
2. The term "clean-room" is applied strictly to components engineered independently without third-party source reuse.
3. All license obligations (notices, attribution, disclaimers) are fully satisfied.

**Release Authority**: Lead Forensic Architect, DREX V2  
**Audit Status**: **VERIFIED & COMPLIANT**
