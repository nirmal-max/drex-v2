---
name: validation-lab
description: Automated test image generation, ground truth validation, and method verification.
---

# Validation Lab Skill

## When to Use
Use when running the DREX validation suite, generating synthetic test disk images, or benchmarking carvers against known ground truth corpora.

## Procedures
- `tests/create_test_image.py`: Builds controlled FAT/NTFS disk images with known deleted file inodes and cluster layouts.
- `tests/test_all_25_methods.py`: Validates all 25 DREX methods against formal contracts.
