---
name: forensic-recovery
description: Forensic filesystem traversal, inode extraction, and directory tree reconstruction.
---

# Forensic Recovery Skill

## When to Use
Use when performing or validating structured filesystem recovery (FAT, exFAT, NTFS, EXT) using The Sleuth Kit (TSK) or native filesystem parsers.

## Workflow
1. Qualify Target: Identify filesystem type via `fsstat` or partition table analysis (`mmls`).
2. Discover: Execute `fls -r -p -d` to extract deleted file directory entries and inode pointers.
3. Extract: Extract specific files using `icat` or full partition trees via `tsk_recover`.
4. Validate: Compute SHA-256 hash and verify file headers against signature database.
