---
name: raw-carving
description: Deep raw sector carving, magic-byte header/footer matching, and signature validation.
---

# Raw Carving Skill

## When to Use
Use when extracting files from unallocated space, formatted partitions, or corrupted filesystems where directory metadata is missing.

## Carving Capabilities
- Header / Footer matching for standard digital evidence (JPEG SOI/EOI, PNG IHDR/IEND, PDF `%PDF` / `%%EOF`, ZIP `PK\x03\x04` / `PK\x05\x06`).
- Integrated PhotoRec backend for batch carving across 480+ formats.
- 5-Factor confidence scoring to evaluate structural validity of extracted payloads.
