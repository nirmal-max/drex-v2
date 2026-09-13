---
name: damaged-media-recovery
description: Damaged media imaging, bad sector mapfile tracking, and readback strategies.
---

# Damaged Media Recovery Skill

## When to Use
Use when acquiring disk images from failing drives, corrupted sectors, or media with I/O timeouts.

## Strategy
1. Non-destructive mapfile tracking (storing status per sector: non-tried, non-trimmed, non-scraped, bad).
2. Multi-pass imaging: Fast sequential copy of good blocks first, followed by single-sector trimming and scraping of damaged zones.
3. Fail-closed safety: Never issue aggressive repeated retries that accelerate head/motor failure.
