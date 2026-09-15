"""DREX-V2 Phase 16 Resource Limits & Bounded Behavior Test Suite
=============================================================
Tests memory-bounded scanning, timeout containment, candidate pool limits,
combinatorial branch bounds, graph node/edge caps, fail-closed adapter semantics,
and adversarial input handling.
"""

import time
import pytest

from carver_engine import CarveConfig, CarveProgress, DeepCarverEngine
from damaged_media import DamagedMediaAdapter, DamagedMediaExecutionResult
from fragment_engine import BoundedPermutationReconstructor, FragmentChunk, FragmentGraph
from fs_base import ReadOnlySource, SourceSafetyState
from validators import CandidateState, ValidationResult
from validators.jpeg import JpegValidator


class SlowMockSource(ReadOnlySource):
    """Mock source for testing time and byte limits."""

    def __init__(self, size: int = 10 * 1024 * 1024, delay_per_read: float = 0.0):
        self._size = size
        self._delay = delay_per_read
        self._reads = 0

    def read(self, offset: int, size: int) -> bytes:
        if offset < 0 or size < 0:
            raise ValueError("Negative offset or size")
        if offset >= self._size:
            return b""
        self._reads += 1
        if self._delay > 0:
            time.sleep(self._delay)
        # Return mostly zeros with occasional valid JPEG header
        chunk = bytearray(size)
        if offset % (64 * 1024) == 0:
            pattern = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x01\x00`\x00`\x00\x00\xff\xc0\x00\x0b\x08\x00\x10\x00\x10\x01\x01\x11\x00\xff\xda\x00\x08\x01\x01\x00\x00\x3f\x00\x00\xff\xd9"
            chunk[:len(pattern)] = pattern
        return bytes(chunk)

    def get_size(self) -> int:
        return self._size

    def get_sector_size(self) -> int:
        return 512

    def get_safety_state(self) -> SourceSafetyState:
        return SourceSafetyState.READ_ONLY_HANDLE_CONFIRMED

    def get_source_identifier(self) -> str:
        return "SLOW_MOCK_SOURCE"


# ─── 1. Carver max_scan_bytes Bounding ────────────────────────────────────────

def test_01_carver_max_scan_bytes_limit():
    """Verify carver stops scanning strictly at max_scan_bytes bound."""
    source = SlowMockSource(size=10 * 1024 * 1024)  # 10 MB total
    scan_limit = 256 * 1024  # Scan only 256 KB
    
    last_progress = None
    def on_progress(p: CarveProgress):
        nonlocal last_progress
        last_progress = p
        
    engine = DeepCarverEngine(config=CarveConfig(max_scan_bytes=scan_limit, window_size=64 * 1024, overlap_size=8 * 1024))
    engine.carve_artifacts(source, progress_callback=on_progress)
    
    assert last_progress is not None
    assert last_progress.bytes_processed <= scan_limit + 64 * 1024


# ─── 2. Carver max_duration_seconds Timeout Containment ───────────────────────

def test_02_carver_max_duration_timeout_containment():
    """Verify carver gracefully halts with resource_limited=True when max duration is exceeded."""
    source = SlowMockSource(size=50 * 1024 * 1024, delay_per_read=0.05)
    
    last_progress = None
    def on_progress(p: CarveProgress):
        nonlocal last_progress
        last_progress = p
        
    engine = DeepCarverEngine(config=CarveConfig(max_duration_seconds=0.1, window_size=64 * 1024, overlap_size=8 * 1024))
    t0 = time.time()
    artifacts = engine.carve_artifacts(source, progress_callback=on_progress)
    elapsed = time.time() - t0
    
    assert elapsed < 1.0  # Terminated quickly
    assert last_progress.resource_limited is True
    assert "Execution duration exceeded limit" in (last_progress.limit_reason or "")


# ─── 3. Carver max_candidates Pool Limit ──────────────────────────────────────

def test_03_carver_max_candidates_cap():
    """Verify carver candidate pool does not exceed max_candidates configuration."""
    source = SlowMockSource(size=1 * 1024 * 1024)
    engine = DeepCarverEngine(config=CarveConfig(max_candidates=3))
    
    artifacts = engine.carve_artifacts(source)
    assert len(artifacts) <= 3


# ─── 4. Carver Cooperative Cancellation ───────────────────────────────────────

def test_04_carver_cooperative_cancellation():
    """Verify carver immediately aborts when cancel_check callback returns True."""
    source = SlowMockSource(size=10 * 1024 * 1024)
    
    cancel_requested = False
    reads = 0
    def check_cancel():
        nonlocal reads
        reads += 1
        return reads >= 2  # Cancel on 2nd check
        
    last_progress = None
    def on_progress(p: CarveProgress):
        nonlocal last_progress
        last_progress = p
        
    engine = DeepCarverEngine(config=CarveConfig(window_size=64 * 1024))
    artifacts = engine.carve_artifacts(source, progress_callback=on_progress, cancel_check=check_cancel)
    
    assert last_progress is not None
    assert last_progress.cancelled is True


# ─── 5. Branch-and-Bound Permutation Depth Limits ─────────────────────────────

def test_05_permutation_reconstructor_max_depth_guard():
    """Verify BoundedPermutationReconstructor halts and tags RESOURCE_LIMITED when fragment count exceeds depth."""
    frags = [b"\x00" * 128 for _ in range(10)]
    reconstructor = BoundedPermutationReconstructor(max_depth=6)
    
    data, state, limits = reconstructor.reconstruct_with_ambiguity_check(
        frags,
        JpegValidator.validate,
    )
    assert state == CandidateState.RESOURCE_LIMITED
    assert any("exceeds branch-and-bound max depth" in l for l in limits)


# ─── 6. Permutation Reconstructor Evaluation Branch Limits ────────────────────

def test_06_permutation_reconstructor_max_branches_guard():
    """Verify BoundedPermutationReconstructor caps evaluated permutation branches to max_evaluated_branches."""
    from validators import EvidenceScores
    eval_count = 0
    def counting_validator(b: bytes) -> ValidationResult:
        nonlocal eval_count
        eval_count += 1
        return ValidationResult(is_valid=False, state=CandidateState.CORRUPTED_INCOMPLETE, length=0, evidence=EvidenceScores())
        
    frags = [b"FRAG_" + bytes([i]) for i in range(5)]  # 5! = 120 permutations
    reconstructor = BoundedPermutationReconstructor(max_depth=8, max_evaluated_branches=25)
    
    reconstructor.reconstruct_with_ambiguity_check(frags, counting_validator)
    assert eval_count <= 25


# ─── 7. FragmentGraph Max Nodes Capacity Cap ──────────────────────────────────

def test_07_fragment_graph_max_nodes_rejection():
    """Verify FragmentGraph add_chunk rejects chunks exceeding max_nodes capacity."""
    graph = FragmentGraph(max_nodes=5)
    
    results = [
        graph.add_chunk(FragmentChunk(chunk_id=i, offset=i * 512, data=b"\x11" * 512))
        for i in range(8)
    ]
    assert results == [True, True, True, True, True, False, False, False]
    assert len(graph.chunks) == 5


# ─── 8. FragmentGraph Max Out-Degree Edges Bound ───────────────────────────────

def test_08_fragment_graph_max_edges_per_node_bound():
    """Verify FragmentGraph limits adjacency out-degree to max_edges_per_node."""
    graph = FragmentGraph(max_nodes=20, max_edges_per_node=3)
    for i in range(10):
        graph.add_chunk(FragmentChunk(chunk_id=i, offset=i * 512, data=b"\x22" * 512))
        
    graph.build_graph()
    for cid, edges in graph._adjacency.items():
        assert len(edges) <= 3


# ─── 9. Damaged Media Adapter Fail-Closed Invariant ───────────────────────────

def test_09_damaged_media_adapter_fail_closed_truth_state():
    """Verify DamagedMediaAdapter fails closed with BACKEND_UNAVAILABLE / HARDWARE_REQUIRED."""
    adapter = DamagedMediaAdapter(
        source_uri="/dev/sdb",
        destination_image_path="/images/evidence.raw",
        mapfile_path="/images/evidence.map",
    )
    
    assert adapter.is_backend_available() is False
    assert adapter.is_hardware_qualified() is False
    
    res = adapter.execute_imaging_pass(pass_number=1)
    assert isinstance(res, DamagedMediaExecutionResult)
    assert res.status == "BACKEND_UNAVAILABLE / HARDWARE_REQUIRED"
    assert res.read_only_source_verified is True
    assert "Native ddrescue binary or direct controller pass-through unavailable" in res.error_message


# ─── 10. Adversarial / Boundary Input Robustness ──────────────────────────────

def test_10_adversarial_empty_and_zero_size_handling():
    """Verify Carver and Fragment Engines handle 0-byte and empty inputs safely without throwing exceptions."""
    engine = DeepCarverEngine()
    empty_artifacts = engine.carve_artifacts(b"")
    assert empty_artifacts == []
    
    reconstructor = BoundedPermutationReconstructor()
    data, state, limits = reconstructor.reconstruct_with_ambiguity_check([], JpegValidator.validate)
    assert state == CandidateState.CORRUPTED_INCOMPLETE
    assert data == b""
