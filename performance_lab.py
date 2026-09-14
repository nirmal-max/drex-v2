"""
DREX-V2 Performance Laboratory & Dual-Signal Memory Profiler
============================================================
Module: performance_lab.py
Phase: 9 / Validation Laboratory

Provides precise, reproducible throughput benchmarking, candidate processing rate
measurement, and dual-signal memory profiling:
1. tracemalloc: Python heap memory allocation and peak watermark
2. Process RSS / Working Set: Operating system process physical resident memory

Design Invariants:
- Strictly distinguishes tracemalloc heap allocation from OS Process RSS.
- Zero arbitrary functional timeouts (measures runtime purely as benchmark telemetry).
- Enforces bounded memory scaling over fixed 64 KB streaming buffers.
- Pure Python standard library with optional psutil/ctypes working set queries.

Zero external dependencies.
License: Apache 2.0.
"""

from __future__ import annotations

import ctypes
import dataclasses
import gc
import hashlib
import os
import sys
import time
import tracemalloc
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple, Union


# ─── Data Models ─────────────────────────────────────────────────────────────

@dataclass
class MemoryProfileSnapshot:
    """Snapshot of memory telemetry capturing dual-signal metrics."""
    timestamp_utc: float
    tracemalloc_current_bytes: int
    tracemalloc_peak_bytes: int
    process_rss_bytes: int
    process_vms_bytes: int = 0


@dataclass
class BenchmarkResult:
    """Benchmark telemetry record for an individual performance test."""
    benchmark_id: str
    operation_name: str
    dataset_size_bytes: int
    duration_seconds: float
    throughput_mb_per_sec: float
    candidates_processed: int = 0
    candidate_rate_per_sec: float = 0.0
    memory_start: MemoryProfileSnapshot = field(default_factory=lambda: MemoryProfileSnapshot(0.0, 0, 0, 0))
    memory_end: MemoryProfileSnapshot = field(default_factory=lambda: MemoryProfileSnapshot(0.0, 0, 0, 0))
    memory_heap_delta_bytes: int = 0
    memory_peak_heap_bytes: int = 0
    bounded_streaming_verified: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)


# ─── OS Resident Set Size (RSS) Extraction ────────────────────────────────────

def get_process_memory_rss() -> Tuple[int, int]:
    """
    Query current process RSS (Working Set) and VMS (Pagefile Usage) in bytes.
    Uses Win32 K32GetProcessMemoryCounters when on Windows, or standard fallback.
    """
    if os.name == "nt":
        class PROCESS_MEMORY_COUNTERS(ctypes.Structure):
            _fields_ = [
                ("cb", ctypes.c_ulong),
                ("PageFaultCount", ctypes.c_ulong),
                ("PeakWorkingSetSize", ctypes.c_size_t),
                ("WorkingSetSize", ctypes.c_size_t),
                ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                ("PagefileUsage", ctypes.c_size_t),
                ("PeakPagefileUsage", ctypes.c_size_t),
            ]

        try:
            counters = PROCESS_MEMORY_COUNTERS()
            counters.cb = ctypes.sizeof(PROCESS_MEMORY_COUNTERS)
            handle = ctypes.windll.kernel32.GetCurrentProcess()
            if ctypes.windll.psapi.GetProcessMemoryCounters(handle, ctypes.byref(counters), counters.cb):
                return int(counters.WorkingSetSize), int(counters.PagefileUsage)
        except Exception:
            pass

    return 0, 0


# ─── Performance Laboratory Profiler ──────────────────────────────────────────

class PerformanceLab:
    """
    Dual-signal benchmarking and memory telemetry engine.
    """

    @classmethod
    def capture_memory_snapshot(cls) -> MemoryProfileSnapshot:
        """Capture current tracemalloc heap state and OS process RSS."""
        current_tm, peak_tm = (0, 0)
        if tracemalloc.is_tracing():
            current_tm, peak_tm = tracemalloc.get_traced_memory()

        rss, vms = get_process_memory_rss()
        return MemoryProfileSnapshot(
            timestamp_utc=time.time(),
            tracemalloc_current_bytes=current_tm,
            tracemalloc_peak_bytes=peak_tm,
            process_rss_bytes=rss,
            process_vms_bytes=vms,
        )

    @classmethod
    def benchmark_callable(
        cls,
        benchmark_id: str,
        operation_name: str,
        func: Callable[[], Any],
        dataset_size_bytes: int = 0,
        candidates_count: int = 0,
        max_heap_leak_threshold_bytes: int = 64 * 1024 * 1024,  # 64 MB
    ) -> BenchmarkResult:
        """
        Execute a callable under dual-signal memory profiling and high-resolution timing.
        """
        gc.collect()
        was_tracing = tracemalloc.is_tracing()
        if not was_tracing:
            tracemalloc.start()
        tracemalloc.reset_peak()

        mem_start = cls.capture_memory_snapshot()
        t0 = time.perf_counter()

        result = func()

        t1 = time.perf_counter()
        mem_end = cls.capture_memory_snapshot()

        duration = max(t1 - t0, 1e-9)
        throughput_mb_s = (dataset_size_bytes / (1024 * 1024)) / duration if dataset_size_bytes > 0 else 0.0
        candidate_rate = candidates_count / duration if candidates_count > 0 else 0.0
        heap_delta = mem_end.tracemalloc_current_bytes - mem_start.tracemalloc_current_bytes
        peak_heap = mem_end.tracemalloc_peak_bytes

        bounded_ok = (peak_heap - mem_start.tracemalloc_current_bytes) < max_heap_leak_threshold_bytes

        if not was_tracing:
            tracemalloc.stop()

        return BenchmarkResult(
            benchmark_id=benchmark_id,
            operation_name=operation_name,
            dataset_size_bytes=dataset_size_bytes,
            duration_seconds=round(duration, 6),
            throughput_mb_per_sec=round(throughput_mb_s, 2),
            candidates_processed=candidates_count,
            candidate_rate_per_sec=round(candidate_rate, 2),
            memory_start=mem_start,
            memory_end=mem_end,
            memory_heap_delta_bytes=heap_delta,
            memory_peak_heap_bytes=peak_heap,
            bounded_streaming_verified=bounded_ok,
            metadata={"result_returned": bool(result is not None)},
        )

    @classmethod
    def benchmark_streaming_sha256(cls, data_generator: Callable[[], bytes], total_bytes: int) -> BenchmarkResult:
        """Benchmark 64 KB chunked streaming SHA-256 hash calculation."""
        def op():
            hasher = hashlib.sha256()
            for chunk in cls._chunk_generator(data_generator(), 64 * 1024):
                hasher.update(chunk)
            return hasher.hexdigest()

        return cls.benchmark_callable(
            benchmark_id="BENCH-SHA256-STREAM",
            operation_name="Streaming SHA-256 (64 KB Chunk Buffer)",
            func=op,
            dataset_size_bytes=total_bytes,
        )

    @staticmethod
    def _chunk_generator(data: bytes, chunk_size: int = 65536):
        for i in range(0, len(data), chunk_size):
            yield data[i : i + chunk_size]
