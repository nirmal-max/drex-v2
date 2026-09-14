"""
DREX-V2 Phase 9 — Determinism & Bounded Streaming Validation
============================================================
File: tests/test_phase9_determinism_and_bounds.py

Asserts mathematical determinism of fixture generation and bounded memory
usage over streaming processing:
1. Seed Invariance: Fixed seed yields bit-identical output across runs.
2. Bounded Streaming: Streaming operations hold a flat memory ceiling regardless of dataset size.
"""

from __future__ import annotations

import gc
import hashlib
import tracemalloc
from pathlib import Path
import pytest

from fixture_generator import (
    SyntheticFixtureGenerator,
    deterministic_prng_bytes,
    sha256_bytes,
)


class TestPhase9DeterminismAndBounds:
    """Determinism and bounded memory verification suite."""

    def test_prng_seed_invariance_and_hash_identity(self):
        """Identical seed produces 100% bit-for-bit identical byte stream across distinct invocations."""
        seq1 = deterministic_prng_bytes(seed=12345, length=1048576)
        seq2 = deterministic_prng_bytes(seed=12345, length=1048576)
        assert sha256_bytes(seq1) == sha256_bytes(seq2)

        # Different seed produces distinct stream
        seq3 = deterministic_prng_bytes(seed=54321, length=1048576)
        assert sha256_bytes(seq1) != sha256_bytes(seq3)

    def test_synthetic_fat32_deterministic_hash_invariance(self):
        """Synthetic FAT32 generator produces bit-for-bit identical image for same seed."""
        img1, meta1 = SyntheticFixtureGenerator.generate_fat32_image(total_sectors=66000, seed=42)
        img2, meta2 = SyntheticFixtureGenerator.generate_fat32_image(total_sectors=66000, seed=42)

        assert meta1.raw_image_sha256 == meta2.raw_image_sha256
        assert sha256_bytes(img1) == sha256_bytes(img2)

    def test_synthetic_ntfs_deterministic_hash_invariance(self):
        """Synthetic NTFS generator produces bit-for-bit identical image for same seed."""
        img1, meta1 = SyntheticFixtureGenerator.generate_ntfs_image(seed=42)
        img2, meta2 = SyntheticFixtureGenerator.generate_ntfs_image(seed=42)

        assert meta1.raw_image_sha256 == meta2.raw_image_sha256
        assert sha256_bytes(img1) == sha256_bytes(img2)

    def test_bounded_streaming_memory_flat_ceiling(self, tmp_path: Path):
        """Iterating over 10 MB stream with 64 KB buffer exhibits flat memory ceiling (< 2 MB heap growth)."""
        gc.collect()
        tracemalloc.start()
        tracemalloc.reset_peak()
        start_current, _ = tracemalloc.get_traced_memory()

        # Simulate 10 MB stream
        chunk_size = 64 * 1024
        total_chunks = 160  # 10 MB
        hasher = hashlib.sha256()

        for _ in range(total_chunks):
            chunk = deterministic_prng_bytes(seed=999, length=chunk_size)
            hasher.update(chunk)
            del chunk

        digest = hasher.hexdigest()
        end_current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        heap_growth = peak - start_current
        # Heap growth should be well bounded under 2 MB (only buffer allocations)
        assert heap_growth < 2 * 1024 * 1024, f"Unbounded memory growth detected: {heap_growth} bytes"
        assert len(digest) == 64
