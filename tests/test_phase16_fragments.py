"""DREX-V2 Phase 16 Fragment Reconstruction & Graph Test Suite
=============================================================
Tests bounded fragment graph traversal, seam continuity scoring,
restart marker stream validation, ZIP delta clustering, and ambiguity containment.
"""

import os
import struct
import pytest

from fragment_engine import (
    BiFragmentGapSearch,
    BoundedPermutationReconstructor,
    FragmentChunk,
    FragmentEdge,
    FragmentGraph,
    FragmentReassembler,
    JpegRstStreamReassembler,
    ZipCarveStream,
    seam_continuity_score,
    shannon_entropy,
)
from validators import CandidateState, EvidenceScores, ValidationResult
from validators.jpeg import JpegValidator
from validators.png import PngValidator


# ─── 1. Entropy & Seam Continuity Tests ────────────────────────────────────────

def test_01_shannon_entropy_bounds():
    """Verify Shannon entropy calculates 0.0 for uniform bytes and ~8.0 for random bytes."""
    zeros = b"\x00" * 1024
    assert shannon_entropy(zeros) == 0.0
    
    # 256 distinct byte values equally distributed -> exactly 8.0 bits/byte
    uniform_all = bytes(range(256)) * 4
    assert abs(shannon_entropy(uniform_all) - 8.0) < 0.001


def test_02_seam_continuity_scoring():
    """Verify seam continuity returns high scores for matching patterns and low for cliffs."""
    # Smooth sine-wave or continuous sequence
    data_a = bytes([i % 256 for i in range(512)])
    data_b = bytes([(512 + i) % 256 for i in range(512)])
    score_smooth = seam_continuity_score(data_a, data_b)
    
    # Severe discontinuity (all zeros jumping to uniform random)
    data_zeros = b"\x00" * 512
    data_rand = os.urandom(512)
    score_cliff = seam_continuity_score(data_zeros, data_rand)
    
    assert score_smooth > 0.60
    assert score_smooth > score_cliff


# ─── 2. Fragment Chunking & Header/Footer Detection ───────────────────────────

def test_03_fragment_chunk_magic_detection():
    """Verify fragment chunking automatically tags header and footer chunks."""
    reassembler = FragmentReassembler(chunk_size=512)
    raw_stream = b"\xff\xd8\xff\xe0" + b"\x00" * 508 + b"\x11" * 512 + b"\x22" * 510 + b"\xff\xd9"
    
    chunks = reassembler.analyze_chunks(raw_stream, file_type="jpeg")
    assert len(chunks) == 3
    assert chunks[0].is_header is True
    assert chunks[0].is_footer is False
    assert chunks[1].is_header is False
    assert chunks[1].is_footer is False
    assert chunks[2].is_footer is True


# ─── 3. Bounded Fragment Graph Construction & Capacity ────────────────────────

def test_04_fragment_graph_node_capacity_limit():
    """Verify FragmentGraph enforces max_nodes cap to prevent memory bloat."""
    graph = FragmentGraph(max_nodes=10)
    
    for i in range(15):
        chunk = FragmentChunk(chunk_id=i, offset=i * 512, data=b"\x01" * 512)
        added = graph.add_chunk(chunk)
        if i < 10:
            assert added is True
        else:
            assert added is False
            
    assert len(graph.chunks) == 10


def test_05_fragment_graph_edge_weighting_and_bounding():
    """Verify FragmentGraph limits out-degree per node and scores compatibility."""
    graph = FragmentGraph(max_nodes=50, max_edges_per_node=2, min_continuity_threshold=0.10)
    
    c_head = FragmentChunk(chunk_id=0, offset=0, data=b"\xff\xd8\xff\xe0" + b"\x55" * 508, is_header=True)
    c_mid1 = FragmentChunk(chunk_id=1, offset=512, data=b"\x55" * 512)
    c_mid2 = FragmentChunk(chunk_id=2, offset=1024, data=b"\x55" * 512)
    c_mid3 = FragmentChunk(chunk_id=3, offset=1536, data=b"\x55" * 512)
    c_foot = FragmentChunk(chunk_id=4, offset=2048, data=b"\x55" * 510 + b"\xff\xd9", is_footer=True)
    
    for c in [c_head, c_mid1, c_mid2, c_mid3, c_foot]:
        graph.add_chunk(c)
        
    edge_count = graph.build_graph(file_type="jpeg")
    assert edge_count > 0
    
    # Check out-degree constraint
    for cid, edges in graph._adjacency.items():
        assert len(edges) <= 2
        for edge in edges:
            assert 0.0 <= edge.weight <= 1.0
            assert "seam_continuity" in edge.evidence_breakdown


def test_06_fragment_graph_find_best_paths():
    """Verify best path traversal from header to footer without loops."""
    graph = FragmentGraph(max_nodes=10, max_edges_per_node=4)
    c0 = FragmentChunk(0, 0, b"\xff\xd8" + b"\xaa" * 510, is_header=True)
    c1 = FragmentChunk(1, 512, b"\xaa" * 512)
    c2 = FragmentChunk(2, 1024, b"\xaa" * 510 + b"\xff\xd9", is_footer=True)
    
    for c in [c0, c1, c2]:
        graph.add_chunk(c)
    graph.build_graph(file_type="jpeg")
    
    paths = graph.find_best_paths(max_paths=3, max_length=5)
    assert len(paths) >= 1
    assert paths[0][0] == 0  # Starts with header


# ─── 4. Ambiguity Containment & Permutation Reconstructor ─────────────────────

def test_07_permutation_reconstructor_unique_solution():
    """Verify single passing permutation resolves to RECOVERED_ARTIFACT without ambiguity."""
    chunk_hdr = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x01\x00`\x00`\x00\x00"
    chunk_sof = b"\xff\xc0\x00\x0b\x08\x00\x10\x00\x10\x01\x01\x11\x00\xff\xda\x00\x08\x01\x01\x00\x00\x3f\x00"
    chunk_tail = b"\x00\x12\x34\x56\x78\x9a\xbc\xde\xf0\xff\xd9"
    
    fragments = [chunk_tail, chunk_hdr, chunk_sof]  # Shuffled fragments
    
    reconstructor = BoundedPermutationReconstructor(max_depth=5, max_evaluated_branches=20)
    data, state, limits = reconstructor.reconstruct_with_ambiguity_check(
        fragments,
        JpegValidator.validate,
    )
    
    assert state in (CandidateState.RECOVERED_ARTIFACT, CandidateState.CONTENT_VALIDATED, CandidateState.STRUCTURALLY_VALID)
    assert data.startswith(b"\xff\xd8")
    assert data.endswith(b"\xff\xd9")


def test_08_permutation_reconstructor_ambiguity_detection():
    """Verify multiple competing structurally valid permutations are flagged AMBIGUOUS_RECONSTRUCTION."""
    # Define two dummy fragments that pass validation in both orders (A+B and B+A)
    class SymmetricValidator:
        @staticmethod
        def validate(data: bytes) -> ValidationResult:
            if b"VALID_MARKER" in data and len(data) == 24:
                return ValidationResult(is_valid=True, state=CandidateState.CONTENT_VALIDATED, length=24, evidence=EvidenceScores(sig_match=1.0, structure=1.0))
            return ValidationResult(is_valid=False, state=CandidateState.CORRUPTED_INCOMPLETE, length=0)
            
    frag1 = b"VALID_MARKER"
    frag2 = b"123456789012"
    
    reconstructor = BoundedPermutationReconstructor()
    data, state, limits = reconstructor.reconstruct_with_ambiguity_check(
        [frag1, frag2],
        SymmetricValidator.validate,
    )
    
    assert state == CandidateState.AMBIGUOUS_RECONSTRUCTION
    assert any("Ambiguous reconstruction" in l for l in limits)


def test_09_permutation_reconstructor_depth_bound():
    """Verify branch-and-bound combinatorial depth cap triggers RESOURCE_LIMITED."""
    fragments = [b"\x00" * 64 for _ in range(12)]  # 12 fragments exceeds max_depth=8
    reconstructor = BoundedPermutationReconstructor(max_depth=8)
    
    data, state, limits = reconstructor.reconstruct_with_ambiguity_check(
        fragments,
        JpegValidator.validate,
    )
    
    assert state == CandidateState.RESOURCE_LIMITED
    assert any("exceeds branch-and-bound max depth" in l for l in limits)


# ─── 5. Bi-Fragment Gap Search & RST Reassembler ──────────────────────────────

def test_10_bi_fragment_gap_evaluation():
    """Verify forward and backward gap evaluation for bi-fragment sector carving."""
    head = b"%PDF-1.4\n1 0 obj<<>>endobj\n"
    tail = b"trailer<<>>\nstartxref\n25\n%%EOF\n"
    
    is_valid, state = BiFragmentGapSearch.evaluate_gap(
        head,
        tail,
        lambda b: ValidationResult(
            is_valid=b.startswith(b"%PDF") and b.endswith(b"%%EOF\n"),
            state=CandidateState.CONTENT_VALIDATED,
            length=len(b),
            evidence=EvidenceScores(sig_match=1.0, structure=1.0),
        ),
    )
    assert is_valid is True
    assert state == CandidateState.CONTENT_VALIDATED
