"""Tests for DREX-V2 Phase 5 Fragment Recovery & Auditable Evidence Engine
=======================================================================
Validates multi-fragment reconstruction, out-of-order reassembly, gap handling,
and multi-factor auditable evidence scoring with raw verified facts.
"""

import hashlib
import pytest

from fragment_engine import (
    FragmentChunk,
    FragmentReassembler,
    ReassemblyCandidate,
    seam_continuity_score,
    shannon_entropy,
)
from validators.base import AuditableEvidenceScore, CandidateState, RecoveryOutcome


class TestFragmentReconstructionPipeline:
    """Validate fragment reassembly across contiguous, out-of-order, and missing fragment cases."""

    def test_contiguous_jpeg_reconstruction(self):
        # 3 contiguous chunks: header, body, footer
        c0 = FragmentChunk(0, 0, b"\xff\xd8\xff\xe0\x00\x10JFIF" + b"\xaa" * 500, file_type="jpeg", is_header=True)
        c1 = FragmentChunk(1, 512, b"\xaa" * 512, file_type="jpeg")
        c2 = FragmentChunk(2, 1024, b"\xaa" * 510 + b"\xff\xd9", file_type="jpeg", is_footer=True)

        reassembler = FragmentReassembler(chunk_size=512)
        candidates = reassembler.reassemble([c0, c1, c2], file_type="jpeg")

        assert len(candidates) >= 1
        cand = candidates[0]
        assert cand.state == CandidateState.STRUCTURALLY_VALID
        assert cand.outcome == RecoveryOutcome.RECOVERED
        assert cand.is_valid_structure is True
        assert len(cand.chunks) == 3
        assert cand.assembled_bytes.startswith(b"\xff\xd8\xff")
        assert cand.assembled_bytes.endswith(b"\xff\xd9")

        # Verify auditable evidence score and raw facts
        assert cand.evidence_score is not None
        score_dict = cand.evidence_score.to_dict()
        assert 0.0 <= score_dict["confidence_score"] <= 100.0
        assert score_dict["raw_evidence_facts"]["has_valid_header"] is True
        assert score_dict["raw_evidence_facts"]["has_valid_footer"] is True
        assert score_dict["raw_evidence_facts"]["chunk_count"] == 3

    def test_out_of_order_jpeg_reconstruction(self):
        # 3 chunks provided in scrambled order: footer, header, body
        c0 = FragmentChunk(0, 0, b"\xff\xd8\xff\xe0\x00\x10JFIF" + b"\x55" * 500, file_type="jpeg", is_header=True)
        c1 = FragmentChunk(1, 512, b"\x55" * 512, file_type="jpeg")
        c2 = FragmentChunk(2, 1024, b"\x55" * 510 + b"\xff\xd9", file_type="jpeg", is_footer=True)

        reassembler = FragmentReassembler(chunk_size=512)
        # Pass chunks in reverse order
        candidates = reassembler.reassemble([c2, c0, c1], file_type="jpeg")

        assert len(candidates) >= 1
        cand = candidates[0]
        # First chunk must be header
        assert cand.chunks[0].is_header is True
        assert cand.assembled_bytes.startswith(b"\xff\xd8\xff")
        assert cand.assembled_bytes.endswith(b"\xff\xd9")
        assert cand.outcome == RecoveryOutcome.RECOVERED

    def test_missing_middle_fragment_gap_handling(self):
        # 2 chunks with missing middle: header and unrelated chunk
        c0 = FragmentChunk(0, 0, b"\xff\xd8\xff\xe0\x00\x10JFIF" + b"\x11" * 500, file_type="jpeg", is_header=True)
        c1 = FragmentChunk(1, 512, b"\x22" * 512, file_type="jpeg")  # Incomplete, no footer

        reassembler = FragmentReassembler(chunk_size=512)
        candidates = reassembler.reassemble([c0, c1], file_type="jpeg")

        assert len(candidates) >= 1
        cand = candidates[0]
        assert cand.outcome in (RecoveryOutcome.PARTIAL_RECOVERY, RecoveryOutcome.RECOVERED_WITH_GAP)
        assert cand.state == CandidateState.CANDIDATE

    def test_png_fragment_reassembly(self):
        # PNG header chunk + body + IEND footer chunk
        png_sig = b"\x89PNG\r\n\x1a\n"
        c0 = FragmentChunk(0, 0, png_sig + b"\x00\x00\x00\rIHDR" + b"\x00" * 490, file_type="png", is_header=True)
        c1 = FragmentChunk(1, 512, b"IDAT" + b"\x00" * 500 + b"IEND\xaeB`\x82", file_type="png", is_footer=True)

        reassembler = FragmentReassembler(chunk_size=512)
        candidates = reassembler.reassemble([c0, c1], file_type="png")

        assert len(candidates) >= 1
        cand = candidates[0]
        assert cand.assembled_bytes.startswith(png_sig)
        assert b"IEND" in cand.assembled_bytes
        assert cand.outcome == RecoveryOutcome.RECOVERED

    def test_zip_fragment_reassembly(self):
        # ZIP header chunk + central directory footer
        c0 = FragmentChunk(0, 0, b"PK\x03\x04" + b"\x00" * 508, file_type="zip", is_header=True)
        c1 = FragmentChunk(1, 512, b"PK\x01\x02" + b"\x00" * 400 + b"PK\x05\x06" + b"\x00" * 104, file_type="zip", is_footer=True)

        reassembler = FragmentReassembler(chunk_size=512)
        candidates = reassembler.reassemble([c0, c1], file_type="zip")

        assert len(candidates) >= 1
        cand = candidates[0]
        assert cand.assembled_bytes.startswith(b"PK\x03\x04")
        assert b"PK\x05\x06" in cand.assembled_bytes
        assert cand.outcome == RecoveryOutcome.RECOVERED

    def test_auditable_evidence_score_structure(self):
        score = AuditableEvidenceScore(
            confidence_score=87.5,
            scoring_breakdown={
                "physical_adjacency": 25.0,
                "format_structure": 30.0,
                "parser_acceptance": 20.0,
                "checksum": 12.5,
            },
            raw_evidence_facts={
                "crc32_matches": True,
                "entropy_gradient": 0.03,
                "marker_offset": 512,
            }
        )
        d = score.to_dict()
        assert d["confidence_score"] == 87.5
        assert d["scoring_breakdown"]["format_structure"] == 30.0
        assert d["raw_evidence_facts"]["crc32_matches"] is True
