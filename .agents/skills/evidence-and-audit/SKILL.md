---
name: evidence-and-audit
description: Forensic evidence tracking, SHA-256 Merkle hash chaining, and tamper-evident certificates.
---

# Evidence and Audit Skill

## When to Use
Use when recording forensic actions, managing the Evidence Vault, generating chain-of-custody logs, or issuing digital certificates.

## Architecture
- **Hash Chaining**: Each audit log entry includes `prev_hash` covering the previous record's SHA-256 signature.
- **Certificate Issuance**: NIST SP 800-88 / ISO 27037 compliance certificates with digital signatures.
- **Evidence Ledger**: Immutable registry of all extracted candidates and sanitization events.
