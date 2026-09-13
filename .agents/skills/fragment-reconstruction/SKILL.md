---
name: fragment-reconstruction
description: Non-contiguous out-of-order file fragment reassembly and validation.
---

# Fragment Reconstruction Skill

## When to Use
Use when reassembling files split non-contiguously across disk sectors (e.g. fragmented JPEGs, segmented ZIP archives, multi-stream documents).

## Approaches
1. **JPEG MCU Boundary Stream Decoding**: Validating entropy streams at MCU boundaries to reject desynchronized candidate sequences.
2. **ZIP Central Directory Stitching**: Extracting local file headers and matching CRC-32 checksums against Central Directory Records.
3. **Bi-Fragment Gap Search**: Forward and backward jump candidate evaluation.
