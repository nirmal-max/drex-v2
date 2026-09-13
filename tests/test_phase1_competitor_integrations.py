"""Phase 1 Competitor Code Integration & Algorithmic Regression Test Suite.

Covers:
- Fragment Reassembly & Seam Continuity (AKHANDA adaptation)
- JPEG Entropy & Restart Marker Parsing (Resurgence adaptation)
- Streaming ZIP Carving & CRC Validation (AKHANDA adaptation)
- Deep Structure-Aware Carving & Multi-Dimensional Evidence Scoring (forensec adaptation)
- NTFS $Bitmap Cluster Allocation & 4-Policy Traversal (ForensiX / SIH26 adaptation)
- Shannon Entropy Physics Verification Engine (SecureForge / devil-net adaptation)
- Volume Shadow Copy (VSS) Discovery, Reporting & Safe Gating (EraseXperts adaptation)
- Runtime Integration into DREX VerificationEngine and Recovery Adapters
"""

from __future__ import annotations

import io
import os
import struct
import zlib
from pathlib import Path
import pytest

from fragment_engine import (
    FragmentChunk,
    FragmentReassembler,
    JpegEntropyDecoder,
    ZipCarveStream,
    seam_continuity_score,
    shannon_entropy,
)
from carver_engine import (
    CarvedCandidate,
    DeepCarverEngine,
    EvidenceScores,
    FormatValidator,
)
from fs_bitmap import (
    BitmapScanPolicy,
    ClusterRun,
    NtfsBitmapAnalyzer,
    VolumeAllocationStats,
)
from entropy_engine import (
    BlockEntropyResult,
    EntropyEvaluation,
    calculate_shannon_entropy,
    evaluate_sanitization_entropy,
    scan_entropy_blocks,
)
from vss_sanitizer import (
    VssPurgePlan,
    VssPurgeResult,
    VssSanitizer,
    VssShadowCopy,
)
from drex_app import VerificationEngine


# ─── 1. Fragment Engine Tests ────────────────────────────────────────────────

class TestFragmentEngine:
    def test_shannon_entropy_bounds(self):
        # Empty buffer
        assert shannon_entropy(b"") == 0.0
        # All zeroes: minimum entropy
        assert shannon_entropy(b"\x00" * 1024) == 0.0
        # All 0xFF: minimum entropy
        assert shannon_entropy(b"\xff" * 1024) == 0.0
        # Uniform 256-byte distribution: maximum theoretical entropy 8.0 bits/byte
        uniform = bytes(range(256)) * 4
        assert abs(shannon_entropy(uniform) - 8.0) < 0.01

    def test_seam_continuity_score(self):
        # Discontinuous: tail of zeroes + head of high random bytes
        tail = b"\x00" * 256
        head = bytes(range(256))
        score = seam_continuity_score(tail, head)
        assert 0.0 <= score <= 1.0

        # Continuous: identical patterned streams
        pattern = b"FORENSIC_STREAM_DATA_CHUNK_" * 10
        score_cont = seam_continuity_score(pattern, pattern)
        assert score_cont >= 0.8

    def test_fragment_reassembler_jpeg(self):
        reassembler = FragmentReassembler(chunk_size=512)
        # Construct synthetic JPEG
        header = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x01\x00`\x00`\x00\x00" + b"\x00" * 480
        body = b"\xff\xdb\x00C\x00" + b"\x05" * 64 + b"\x00" * 441
        footer = b"\xff\xda\x00\x0c\x03\x01\x00\x02\x11\x03\x11\x00?\x00" + b"\xaa" * 400 + b"\xff\xd9" + b"\x00" * 96

        raw_stream = header + body + footer
        chunks = reassembler.analyze_chunks(raw_stream, file_type="jpeg")
        assert len(chunks) == 3
        assert chunks[0].is_header is True
        assert chunks[2].is_footer is True

        candidates = reassembler.reassemble(chunks, file_type="jpeg")
        assert len(candidates) >= 1
        cand = candidates[0]
        assert cand.is_valid_structure is True
        assert cand.reconstruction_confidence >= 0.70
        assert len(cand.assembled_bytes) == len(raw_stream)

    def test_jpeg_entropy_decoder_markers(self):
        # Construct JPEG buffer with restart markers RST0, RST1
        jpeg_data = (
            b"\xff\xd8"                          # SOI
            b"\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
            b"\xff\xc0\x00\x11\x08\x00\x40\x00\x40\x03\x01\x11\x00\x02\x11\x01\x03\x11\x01" # SOF0
            b"\xff\xda\x00\x08\x01\x01\x00\x00?\x00"  # SOS
            b"\x12\x34\x56"
            b"\xff\xd0"                          # RST0
            b"\x78\x9a\xbc"
            b"\xff\xd1"                          # RST1
            b"\xde\xf0"
            b"\xff\xd9"                          # EOI
        )
        decoder = JpegEntropyDecoder(jpeg_data)
        assert decoder.parse() is True
        assert decoder.has_soi is True
        assert decoder.has_sof is True
        assert decoder.has_sos is True
        assert decoder.has_eoi is True
        assert decoder.restart_count == 2
        assert decoder.structural_validity_score() == 1.0

    def test_zip_carve_stream(self):
        # Create a real in-memory ZIP archive
        buf = io.BytesIO()
        import zipfile
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("evidence.txt", b"Forensic evidence artifact content.")
            zf.writestr("notes.log", b"Case #2026-09-14 forensic scan log.")

        zip_bytes = buf.getvalue()
        carver = ZipCarveStream(zip_bytes)
        assert carver.parse() is True
        assert carver.eocd_found is True
        assert len(carver.members) == 2
        assert carver.members[0].filename == "evidence.txt"
        assert carver.members[0].is_valid_crc is True
        assert carver.members[1].filename == "notes.log"
        assert carver.members[1].is_valid_crc is True
        assert carver.structural_validity_score() == 1.0


# ─── 2. Carver Engine Tests ──────────────────────────────────────────────────

class TestCarverEngine:
    def test_evidence_scores_composite(self):
        scores = EvidenceScores(
            sig_match=1.0,
            structure=1.0,
            continuity=1.0,
            metadata=1.0,
            size_bounded=1.0,
        )
        assert scores.composite_score() == 1.0

        scores_partial = EvidenceScores(
            sig_match=1.0,
            structure=0.5,
            continuity=0.5,
            metadata=0.0,
            size_bounded=1.0,
        )
        expected = 0.30 * 1.0 + 0.30 * 0.5 + 0.20 * 0.5 + 0.10 * 0.0 + 0.10 * 1.0
        assert abs(scores_partial.composite_score() - expected) < 0.001

    def test_format_validator_png(self):
        # Create minimal valid PNG
        # Signature (8B) + IHDR (25B) + IEND (12B)
        ihdr_payload = struct.pack(">IIBBBBB", 100, 100, 8, 2, 0, 0, 0)
        ihdr_crc = zlib.crc32(b"IHDR" + ihdr_payload) & 0xFFFFFFFF
        ihdr_chunk = struct.pack(">I", 13) + b"IHDR" + ihdr_payload + struct.pack(">I", ihdr_crc)

        iend_crc = zlib.crc32(b"IEND") & 0xFFFFFFFF
        iend_chunk = struct.pack(">I", 0) + b"IEND" + struct.pack(">I", iend_crc)

        png_bytes = b"\x89PNG\r\n\x1a\n" + ihdr_chunk + iend_chunk
        valid, length, evidence, meta = FormatValidator.validate_png(png_bytes)
        assert valid is True
        assert length == len(png_bytes)
        assert meta["width"] == 100
        assert meta["height"] == 100
        assert meta["valid_chunks"] == 2
        assert evidence.composite_score() >= 0.70

    def test_format_validator_sqlite(self):
        # Create minimal 100-byte SQLite header
        header = bytearray(100)
        header[0:16] = b"SQLite format 3\x00"
        struct.pack_into(">H", header, 16, 4096)  # Page size 4096
        struct.pack_into(">I", header, 24, 42)    # Change counter
        struct.pack_into(">I", header, 28, 10)    # DB size in pages = 10 (40KB)

        valid, length, evidence, meta = FormatValidator.validate_sqlite(bytes(header))
        assert valid is True
        assert length == 40960
        assert meta["page_size"] == 4096
        assert meta["change_counter"] == 42
        assert evidence.composite_score() >= 0.80

    def test_deep_carver_engine_multi_carve(self):
        # Construct synthetic sector stream containing padding, PNG, and SQLite
        padding = b"\x00" * 512
        png_data = b"\x89PNG\r\n\x1a\n" + b"\x00\x00\x00\rIHDR" + b"\x00" * 13 + b"\x00" * 4 + b"\x00\x00\x00\x00IEND\xaeB`\x82"
        sqlite_data = bytearray(512)
        sqlite_data[0:16] = b"SQLite format 3\x00"
        struct.pack_into(">H", sqlite_data, 16, 512)
        struct.pack_into(">I", sqlite_data, 28, 1)

        disk_image = padding + png_data + padding + bytes(sqlite_data) + padding
        carver = DeepCarverEngine()
        candidates = carver.carve(disk_image)
        assert len(candidates) >= 2
        types = [c.file_type for c in candidates]
        assert "png" in types
        assert "sqlite" in types


# ─── 3. NTFS $Bitmap Tests ───────────────────────────────────────────────────

class TestNtfsBitmapAnalyzer:
    def test_bitmap_allocation_and_stats(self):
        # 16 bytes = 128 clusters
        # Byte 0 = 0b00001111 (clusters 0..3 allocated, 4..7 free)
        # Byte 1 = 0b11110000 (clusters 8..11 free, 12..15 allocated)
        # Remaining 14 bytes = 0x00 (all free)
        bitmap = bytearray(16)
        bitmap[0] = 0b00001111
        bitmap[1] = 0b11110000

        analyzer = NtfsBitmapAnalyzer(bytes(bitmap), bytes_per_sector=512, sectors_per_cluster=8)
        assert analyzer.is_cluster_allocated(0) is True
        assert analyzer.is_cluster_allocated(3) is True
        assert analyzer.is_cluster_allocated(4) is False
        assert analyzer.is_cluster_allocated(7) is False
        assert analyzer.is_cluster_allocated(8) is False
        assert analyzer.is_cluster_allocated(12) is True

        stats = analyzer.get_allocation_stats()
        assert stats.total_clusters == 128
        assert stats.allocated_clusters == 8
        assert stats.free_clusters == 120
        assert stats.free_percentage == round((120 / 128) * 100.0, 2)

    def test_bitmap_policies(self):
        bitmap = bytearray(8)
        bitmap[0] = 0x0F  # 4 alloc, 4 free
        bitmap[1] = 0xF0  # 4 free, 4 alloc

        analyzer = NtfsBitmapAnalyzer(bytes(bitmap))

        # FREE_ONLY policy
        free_runs = analyzer.extract_cluster_runs(policy=BitmapScanPolicy.FREE_ONLY)
        assert all(not r.is_allocated for r in free_runs)
        assert sum(r.length for r in free_runs) == (64 - 8)

        # FULL_VOLUME policy
        full_runs = analyzer.extract_cluster_runs(policy=BitmapScanPolicy.FULL_VOLUME)
        assert len(full_runs) == 1
        assert full_runs[0].length == 64

        # TARGETED policy
        target_runs = analyzer.extract_cluster_runs(policy=BitmapScanPolicy.TARGETED, start_cluster=10, cluster_limit=20)
        assert len(target_runs) == 1
        assert target_runs[0].start_cluster == 10
        assert target_runs[0].length == 20


# ─── 4. Entropy Engine Tests ─────────────────────────────────────────────────

class TestEntropyEngine:
    def test_entropy_evaluation_zero_pattern(self):
        zero_buf = b"\x00" * 16384
        eval_res = evaluate_sanitization_entropy(zero_buf, expected_pattern="zero")
        assert eval_res.is_compliant is True
        assert eval_res.verdict == "PASSED"
        assert eval_res.mean_entropy == 0.0

    def test_entropy_evaluation_random_pattern(self):
        import secrets
        random_buf = secrets.token_bytes(16384)
        eval_res = evaluate_sanitization_entropy(random_buf, expected_pattern="random")
        assert eval_res.is_compliant is True
        assert eval_res.verdict in ("PASSED", "PASSED_WITH_WARNING")
        assert eval_res.mean_entropy >= 7.80

    def test_entropy_evaluation_mismatch(self):
        # Provide zeroes when random was expected
        zero_buf = b"\x00" * 8192
        eval_res = evaluate_sanitization_entropy(zero_buf, expected_pattern="random")
        assert eval_res.is_compliant is False
        assert eval_res.verdict == "FAILED"


# ─── 5. VSS Sanitizer Safety Tests ───────────────────────────────────────────

class TestVssSanitizer:
    def test_discover_shadows_mock_parsing(self):
        mock_vssadmin = """
vssadmin 1.1 - Volume Shadow Copy Service administrative command-line tool
(C) Copyright 2001-2013 Microsoft Corp.

Contents of shadow copy set ID: {11111111-2222-3333-4444-555555555555}
   Contained 1 shadow copies at creation time: 9/13/2026 10:00:00 PM
      Shadow Copy ID: {AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}
      Original Volume: (C:)\\?\\Volume{00000000-0000-0000-0000-000000000000}\\
      Creation Time: 9/13/2026 10:00:00 PM
      Shadow Copy Provider: 'Microsoft Software Shadow Copy provider 1.0'
"""
        shadows = VssSanitizer.discover_shadows(command_output=mock_vssadmin)
        assert len(shadows) == 1
        assert shadows[0].shadow_id == "{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}"
        assert "(C:)" in shadows[0].original_volume

    def test_purge_plan_creation(self):
        plan = VssPurgePlan(
            shadow_copies=[VssShadowCopy(shadow_id="{123}", original_volume="C:", creation_time="2026-09-13")],
            target_count=1,
            is_elevated=False,
            requires_confirmation=True,
        )
        assert plan.target_count == 1
        assert plan.requires_confirmation is True

    def test_execute_purge_dry_run_safety(self):
        # Dry-run must NEVER execute destructive actions
        res = VssSanitizer.execute_purge(confirm_destructive=True, dry_run=True, target_volume="D:")
        assert res.status == "DRY_RUN"
        assert res.shadows_purged == 0
        assert "DRY RUN" in res.output

    def test_execute_purge_unconfirmed_blocked(self):
        # Unconfirmed destructive request must be BLOCKED
        res = VssSanitizer.execute_purge(confirm_destructive=False, dry_run=False)
        assert res.status == "BLOCKED"
        assert "confirmation not provided" in res.error_message.lower()


# ─── 6. DREX Runtime Integration Tests ───────────────────────────────────────

class TestRuntimeIntegration:
    def test_verification_engine_with_entropy_evidence(self):
        eval_res = EntropyEvaluation(
            mean_entropy=7.995,
            min_entropy=7.980,
            max_entropy=8.000,
            total_blocks=4,
            expected_pattern="random",
            is_compliant=True,
            verdict="PASSED",
            evidence_notes="Verified high-entropy CSPRNG random distribution.",
        )
        evidence = {
            "verification_status": "VERIFIED",
            "bytes_verified": 4096,
            "disk_size_bytes": 4096,
            "entropy_evaluation": eval_res,
        }
        status, warnings = VerificationEngine.assess(evidence)
        assert status == "VERIFIED"
        assert any("Entropy signal:" in w for w in warnings)
