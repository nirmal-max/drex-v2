---
name: sanitization
description: NIST SP 800-88, DoD 5220.22-M, and IEEE 2883 media sanitization workflows.
---

# Sanitization Skill

## When to Use
Use when implementing or verifying disk erasure, file/folder shredding, metadata scrubbing, or free space wiping.

## Principles
1. **Clear vs Purge**: Select appropriate technique based on security requirements and media type.
2. **Flash / NVMe Awareness**: Enforce cryptographic erase / block erase rather than software overwriting on SSDs.
3. **Residue Elimination**: Target MFT names, cluster slack, and shadow copies.
4. **Verification**: Measure Shannon entropy and perform 100% readback checks on wiped areas.
