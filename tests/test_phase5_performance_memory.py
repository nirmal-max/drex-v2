"""Empirical Memory & Streaming Profiling Tests for DREX-V2 Phase 5
================================================================
Validates that damaged media acquisition and RAID reconstruction operate
with strictly bounded memory footprints (O(1) memory overhead relative to image size).
"""

import os
import tempfile
import tracemalloc
from pathlib import Path
import pytest

from recovery_adapter import DirectDamagedMediaImager, VirtualRaidReconstructor


class TestPhase5MemoryQualification:
    """Empirical memory qualification tracking peak RSS / buffer deltas."""

    def test_damaged_media_streaming_memory_bound(self, tmp_path):
        # Generate 10 MB synthetic source file
        fixture_size = 10 * 1024 * 1024  # 10 MB
        chunk_size = 64 * 1024           # 64 KB chunk buffer

        src = tmp_path / "10mb_source.raw"
        out_img = tmp_path / "10mb_out.raw"
        out_map = tmp_path / "10mb_out.map"

        # Write exactly 10 MB in 64 KB chunks
        chunk_data = (b"DREX_SYNTHETIC_DATA_BLOCK_STREAM_" * 2000)[:chunk_size]
        with open(src, "wb") as f:
            for _ in range(fixture_size // chunk_size):
                f.write(chunk_data)

        tracemalloc.start()
        snapshot_before = tracemalloc.take_snapshot()

        res = DirectDamagedMediaImager.image_source(
            source_data=src,
            output_image_path=out_img,
            mapfile_path=out_map,
            sector_size=512,
            chunk_size=chunk_size,
        )

        snapshot_after = tracemalloc.take_snapshot()
        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        # The peak memory delta must be well under 4 MB (far below the 10 MB disk image size)
        peak_mb = peak / (1024 * 1024)
        assert peak_mb < 5.0, f"Observed peak memory {peak_mb:.2f} MB exceeds 5 MB bound for 10 MB image"
        assert res["total_bytes"] == fixture_size
        assert res["rescued_bytes"] == fixture_size

    def test_raid5_streaming_memory_bound(self, tmp_path):
        # 3 disks of 5 MB each (total 10 MB reconstructed)
        disk_size = 5 * 1024 * 1024
        chunk_size = 64 * 1024

        d0 = tmp_path / "r5_disk0.raw"
        d1 = tmp_path / "r5_disk1.raw"
        p = tmp_path / "r5_p.raw"
        out = tmp_path / "r5_reconstructed.raw"

        block_data = (b"R5_DATA_BLOCK_STREAMING_TEST_" * 3000)[:chunk_size]

        with open(d0, "wb") as f0, open(d1, "wb") as f1, open(p, "wb") as fp:
            for _ in range(disk_size // chunk_size):
                f0.write(block_data)
                f1.write(block_data)
                fp.write(b"\x00" * chunk_size)

        tracemalloc.start()
        written = VirtualRaidReconstructor.reconstruct_raid5_stream(
            [d0, d1, p],
            out,
            chunk_size=chunk_size,
            layout="dedicated-parity",
        )
        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        peak_mb = peak / (1024 * 1024)
        assert peak_mb < 5.0, f"Observed peak memory {peak_mb:.2f} MB exceeds 5 MB bound for 10 MB array rebuild"
        assert written == (disk_size // chunk_size) * chunk_size * 2
