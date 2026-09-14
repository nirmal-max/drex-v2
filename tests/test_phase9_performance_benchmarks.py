"""
DREX-V2 Phase 9 — Performance Benchmarks & Memory Telemetry Suite
=================================================================
File: tests/test_phase9_performance_benchmarks.py

Evaluates IO throughput, streaming SHA-256 performance, and dual-signal
memory profiling (tracemalloc heap vs OS Process RSS) without arbitrary
functional timeouts.
"""

from __future__ import annotations

import time
from pathlib import Path
import pytest

from performance_lab import (
    PerformanceLab,
    BenchmarkResult,
    MemoryProfileSnapshot,
)
from fixture_generator import (
    deterministic_prng_bytes,
)


class TestPhase9PerformanceBenchmarks:
    """Performance laboratory tests measuring throughput, duration, and memory watermarks."""

    def test_dual_signal_memory_snapshot_extraction(self):
        """Memory snapshot correctly separates tracemalloc heap allocation from OS Process RSS."""
        snap = PerformanceLab.capture_memory_snapshot()
        assert isinstance(snap.timestamp_utc, float)
        assert isinstance(snap.tracemalloc_current_bytes, int)
        assert isinstance(snap.tracemalloc_peak_bytes, int)
        assert isinstance(snap.process_rss_bytes, int)

    def test_streaming_sha256_throughput_and_bounded_memory(self):
        """Benchmark streaming SHA-256 over 10 MB dataset asserting positive throughput and bounded heap."""
        dataset_size = 10 * 1024 * 1024  # 10 MB
        payload = deterministic_prng_bytes(seed=42, length=dataset_size)

        bench = PerformanceLab.benchmark_streaming_sha256(
            data_generator=lambda: payload,
            total_bytes=dataset_size,
        )

        assert bench.duration_seconds > 0.0
        assert bench.throughput_mb_per_sec > 0.0
        assert bench.dataset_size_bytes == dataset_size
        assert bench.bounded_streaming_verified is True

    def test_candidate_processing_rate_telemetry(self):
        """Benchmark candidate rate calculation (candidates/sec) across 1000 simulated candidates."""
        candidates_count = 1000

        def process_candidates():
            acc = 0
            for i in range(candidates_count):
                acc += (i * 31) % 997
            return acc

        bench = PerformanceLab.benchmark_callable(
            benchmark_id="BENCH-CAND-RATE-01",
            operation_name="Simulated Candidate Filter",
            func=process_candidates,
            candidates_count=candidates_count,
        )

        assert bench.candidates_processed == candidates_count
        assert bench.candidate_rate_per_sec > 0.0
        assert bench.duration_seconds >= 0.0
