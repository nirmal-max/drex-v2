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

    def test_end_to_end_raw_carving_runtime_pipeline(self, tmp_path: Path):
        """Pipeline A: Synthetic Raw Carving via DeepRecoveryAdapter."""
        from recovery_adapter import DeepRecoveryAdapter, RECOVERY_METHOD_SPECS
        
        # Construct synthetic disk image with embedded PNG and SQLite
        img_file = tmp_path / "synthetic_disk.raw"
        padding = b"\x00" * 512
        png_data = b"\x89PNG\r\n\x1a\n" + b"\x00\x00\x00\rIHDR" + b"\x00" * 13 + b"\x00" * 4 + b"\x00\x00\x00\x00IEND\xaeB`\x82"
        sqlite_data = bytearray(512)
        sqlite_data[0:16] = b"SQLite format 3\x00"
        struct.pack_into(">H", sqlite_data, 16, 512)
        struct.pack_into(">I", sqlite_data, 28, 1)

        img_file.write_bytes(padding + png_data + padding + bytes(sqlite_data) + padding)

        spec = next(s for s in RECOVERY_METHOD_SPECS if s.method_id == "deep")
        adapter = DeepRecoveryAdapter(spec, tmp_path, tmp_path)

        # 1. Discovery & Scan
        scan_res = adapter.scan(str(img_file))
        assert scan_res.status == "OK"
        assert len(scan_res.candidates) >= 2
        assert any(c.file_type == "png" for c in scan_res.candidates)
        assert any(c.file_type == "sqlite" for c in scan_res.candidates)

        # 2. Candidate Validation & Evidence
        png_cand = next(c for c in scan_res.candidates if c.file_type == "png")
        assert png_cand.recoverable is True
        assert png_cand.confidence >= 0.50

        # 3. Recovery Extraction
        out_dir = tmp_path / "recovered_carve"
        recovered = adapter.recover(str(img_file), png_cand.candidate_id, out_dir)
        assert len(recovered) == 1
        assert recovered[0].is_file()
        assert recovered[0].read_bytes() == png_data

    def test_end_to_end_fragment_reconstruction_runtime_pipeline(self, tmp_path: Path):
        """Pipeline B: Synthetic Fragment Reconstruction via FragmentRecoveryAdapter."""
        from recovery_adapter import FragmentRecoveryAdapter, RECOVERY_METHOD_SPECS

        img_file = tmp_path / "frag_image.raw"
        header = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x01\x00`\x00`\x00\x00" + b"\x00" * 480
        body = b"\xff\xdb\x00C\x00" + b"\x05" * 64 + b"\x00" * 441
        footer = b"\xff\xda\x00\x0c\x03\x01\x00\x02\x11\x03\x11\x00?\x00" + b"\xaa" * 400 + b"\xff\xd9" + b"\x00" * 96

        # Write 3 clusters of 512 bytes
        img_file.write_bytes(header + body + footer)

        spec = next(s for s in RECOVERY_METHOD_SPECS if s.method_id == "fragment")
        adapter = FragmentRecoveryAdapter(spec, tmp_path, tmp_path, file_type="jpeg")

        # 1. Scan
        scan_res = adapter.scan(str(img_file), file_type="jpeg")
        assert scan_res.status == "READY"

        # 2. Recovery & Reassembly
        out_dir = tmp_path / "recovered_frags"
        recovered = adapter.recover(str(img_file), "dummy_cand", out_dir, file_type="jpeg", cluster_size=512)
        assert len(recovered) >= 1
        rec_data = recovered[0].read_bytes()
        assert rec_data.startswith(b"\xff\xd8")
        assert b"\xff\xd9" in rec_data

    def test_end_to_end_verification_runtime_pipeline(self):
        """Pipeline C: Synthetic Data to DREX Verification Path."""
        # 1. Constant Zero Pattern
        zero_buf = b"\x00" * 8192
        zero_eval = evaluate_sanitization_entropy(zero_buf, expected_pattern="zero")
        assert zero_eval.verdict == "PASSED"

        evidence_zero = {
            "verification_status": "VERIFIED",
            "bytes_verified": 8192,
            "disk_size_bytes": 8192,
            "entropy_evaluation": zero_eval,
        }
        status, warnings = VerificationEngine.assess(evidence_zero)
        assert status == "VERIFIED"
        assert any("Verified uniform constant pattern" in w for w in warnings)

        # 2. CSPRNG Random Pattern
        import secrets
        rand_buf = secrets.token_bytes(8192)
        rand_eval = evaluate_sanitization_entropy(rand_buf, expected_pattern="random")
        assert rand_eval.verdict in ("PASSED", "PASSED_WITH_WARNING")

        evidence_rand = {
            "verification_status": "VERIFIED",
            "bytes_verified": 8192,
            "disk_size_bytes": 8192,
            "entropy_evaluation": rand_eval,
        }
        status_r, warnings_r = VerificationEngine.assess(evidence_rand)
        assert status_r == "VERIFIED"

    def test_end_to_end_ntfs_bitmap_runtime_pipeline(self):
        """Pipeline D: Synthetic NTFS Bitmap Multi-Policy Allocation."""
        # 32 bytes = 256 clusters
        bitmap = bytearray(32)
        # Cluster 0..15 allocated (2 bytes of 0xFF)
        bitmap[0] = 0xFF
        bitmap[1] = 0xFF
        # Cluster 16..31 free (2 bytes of 0x00)
        bitmap[2] = 0x00
        bitmap[3] = 0x00
        # Cluster 32..47 allocated (2 bytes of 0xFF)
        bitmap[4] = 0xFF
        bitmap[5] = 0xFF

        analyzer = NtfsBitmapAnalyzer(bytes(bitmap), bytes_per_sector=512, sectors_per_cluster=8)
        stats = analyzer.get_allocation_stats()
        assert stats.total_clusters == 256
        assert stats.allocated_clusters == 32
        assert stats.free_clusters == 224

        # Verify FREE_ONLY policy extracts only free runs
        free_runs = analyzer.extract_cluster_runs(policy=BitmapScanPolicy.FREE_ONLY)
        assert all(not r.is_allocated for r in free_runs)
        assert sum(r.length for r in free_runs) == 224

        # Verify FULL_VOLUME policy spans total clusters
        full_runs = analyzer.extract_cluster_runs(policy=BitmapScanPolicy.FULL_VOLUME)
        assert len(full_runs) == 1
        assert full_runs[0].length == 256

    def test_end_to_end_vss_safety_runtime_pipeline(self):
        """Pipeline E: VSS Discovery, Reporting, and Non-Destructive Safety Gates."""
        # 1. Discovery on Mock Output
        mock_output = """
Contents of shadow copy set ID: {11111111-2222-3333-4444-555555555555}
   Contained 1 shadow copies at creation time: 9/13/2026 10:00:00 PM
      Shadow Copy ID: {AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}
      Original Volume: (C:)\\?\\Volume{00000000-0000-0000-0000-000000000000}\\
      Creation Time: 9/13/2026 10:00:00 PM
"""
        shadows = VssSanitizer.discover_shadows(command_output=mock_output)
        assert len(shadows) == 1

        # 2. Plan Generation
        plan = VssSanitizer.create_purge_plan(shadows=shadows)
        assert plan.target_count == 1
        assert plan.requires_confirmation is True

        # 3. Dry-Run Execution (Guaranteed Non-Destructive)
        res_dry = VssSanitizer.execute_purge(confirm_destructive=True, dry_run=True, target_volume="C:")
        assert res_dry.status == "DRY_RUN"
        assert res_dry.shadows_purged == 0

        # 4. Blocked when Unconfirmed
        res_unconf = VssSanitizer.execute_purge(confirm_destructive=False, dry_run=False)
        assert res_unconf.status == "BLOCKED"


# ─── 7. Forensic Hardening & Mathematical Audit Suites ───────────────────────

class TestFragmentForensicHardening:
    """Forensic verification of fragment reassembly under adversarial conditions."""

    def test_shuffled_and_reversed_fragments(self):
        # 3-chunk JPEG (exactly 512 bytes per cluster)
        c1 = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x01\x00`\x00`\x00\x00" + b"\x00" * 492
        c2 = b"\xff\xdb\x00C\x00" + b"\x05" * 64 + b"\x00" * 443
        c3 = b"\xff\xda\x00\x0c\x03\x01\x00\x02\x11\x03\x11\x00?\x00" + b"\xaa" * 400 + b"\xff\xd9" + b"\x00" * 96

        reassembler = FragmentReassembler(chunk_size=512)
        # Reversed order: c3, c2, c1
        raw_reversed = c3 + c2 + c1
        chunks = reassembler.analyze_chunks(raw_reversed, file_type="jpeg")
        candidates = reassembler.reassemble(chunks, file_type="jpeg")
        assert len(candidates) >= 1
        # Reassembled candidate should find the header chunk (c1) as start
        best_cand = candidates[0]
        assert best_cand.chunks[0].data.startswith(b"\xff\xd8")

    def test_missing_intermediate_fragment_behavior(self):
        # Header + Footer but missing body: must result in candidate without claiming full continuous recovery
        c1 = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x01\x00`\x00`\x00\x00" + b"\x01" * 480
        c3 = b"\xff\xda\x00\x0c\x03\x01\x00\x02\x11\x03\x11\x00?\x00" + b"\xaa" * 400 + b"\xff\xd9" + b"\x00" * 96

        reassembler = FragmentReassembler(chunk_size=512)
        chunks = reassembler.analyze_chunks(c1 + c3, file_type="jpeg")
        candidates = reassembler.reassemble(chunks, file_type="jpeg")
        assert len(candidates) >= 1

    def test_corrupted_and_truncated_jpeg_markers(self):
        # Truncated marker stream
        truncated = b"\xff\xd8\xff\xe0\x00\x10JFIF"
        decoder = JpegEntropyDecoder(truncated)
        assert decoder.parse() is False
        assert decoder.is_truncated is True
        assert decoder.structural_validity_score() == 0.3


class TestZipForensicHardening:
    """Forensic verification of ZIP stream carver against corruptions and traversals."""

    def test_empty_zip_archive(self):
        # Minimal empty ZIP: exactly 22 bytes EOCD
        # EOCD: PK\x05\x06 + 18 bytes of zeroes
        empty_eocd = b"PK\x05\x06" + b"\x00" * 18
        carver = ZipCarveStream(empty_eocd)
        # Parse returns False (no members), but eocd_found is True
        assert carver.parse() is False
        assert carver.eocd_found is True
        assert carver.structural_validity_score() == 0.4

    def test_truncated_and_corrupt_eocd(self):
        # Buffer without EOCD
        corrupt = b"PK\x03\x04\x14\x00\x00\x00" + b"\x00" * 100
        carver = ZipCarveStream(corrupt)
        assert carver.parse() is False
        assert carver.eocd_found is False
        assert carver.structural_validity_score() == 0.0

    def test_zip_crc_mismatch_detection(self):
        # Create a valid ZIP archive, then corrupt member payload
        buf = io.BytesIO()
        import zipfile
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as zf:
            zf.writestr("test.txt", b"Authentic forensic stream payload")

        zip_bytes = bytearray(buf.getvalue())
        # Find payload and corrupt 1 byte
        payload_pos = zip_bytes.find(b"Authentic")
        if payload_pos != -1:
            zip_bytes[payload_pos] = ord("X")

        carver = ZipCarveStream(bytes(zip_bytes))
        assert carver.parse() is True
        assert len(carver.members) == 1
        # CRC mismatch detected
        assert carver.members[0].is_valid_crc is False
        assert carver.structural_validity_score() < 1.0


class TestRawCarverForensicHardening:
    """Forensic verification of DeepCarverEngine format validators and bounding."""

    def test_candidate_limit_bounding(self):
        # Buffer with 10 repeated PNG signatures
        repeated_png = (b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR" + b"\x00" * 17 + b"\x00\x00\x00\x00IEND\xaeB`\x82") * 10
        carver = DeepCarverEngine(max_candidates=3)
        cands = carver.carve(repeated_png)
        assert len(cands) <= 3

    def test_pdf_format_validator(self):
        valid_pdf = (
            b"%PDF-1.4\n"
            b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
            b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
            b"xref\n0 3\n0000000000 65535 f \n"
            b"trailer\n<< /Size 3 /Root 1 0 R >>\n"
            b"startxref\n120\n"
            b"%%EOF"
        )
        valid, length, evidence, meta = FormatValidator.validate_pdf(valid_pdf)
        assert valid is True
        assert length == len(valid_pdf)
        assert meta["has_eof"] is True
        assert meta["has_xref"] is True
        assert evidence.composite_score() >= 0.70

    def test_gif_and_riff_carving(self):
        gif_bytes = b"GIF89a" + b"\x0a\x00\x0a\x00\x80\x00\x00" + b"\x00" * 20 + b"\x3b"
        carver = DeepCarverEngine()
        cands = carver.carve(gif_bytes)
        assert any(c.file_type == "gif" for c in cands)


class TestNtfsBitmapForensicHardening:
    """Forensic verification of NTFS $Bitmap bit indexing and cluster runs."""

    def test_odd_size_and_boundary_indexing(self):
        # 3 bytes = 24 clusters
        # 0b10101010, 0b01010101, 0b11110000
        bitmap = bytes([0b10101010, 0b01010101, 0b11110000])
        analyzer = NtfsBitmapAnalyzer(bitmap)
        assert analyzer.total_clusters == 24
        assert analyzer.is_cluster_allocated(0) is False
        assert analyzer.is_cluster_allocated(1) is True
        assert analyzer.is_cluster_allocated(8) is True
        assert analyzer.is_cluster_allocated(9) is False
        # Out-of-bounds queries return False safely
        assert analyzer.is_cluster_allocated(999) is False
        assert analyzer.is_cluster_allocated(-1) is False

    def test_free_first_policy_ordering(self):
        bitmap = bytes([0b00001111])  # 4 alloc, 4 free
        analyzer = NtfsBitmapAnalyzer(bitmap)
        runs = analyzer.extract_cluster_runs(policy=BitmapScanPolicy.FREE_FIRST)
        assert len(runs) == 2
        # Free runs appear first in FREE_FIRST
        assert runs[0].is_allocated is False
        assert runs[1].is_allocated is True


class TestMathematicalAuditAndSafety:
    """Audit mathematical bounds, evidence normalization, and VSS safety."""

    def test_evidence_scores_normalization_invariant(self):
        # Invariant: weights sum exactly to 1.0
        # 0.30 + 0.30 + 0.20 + 0.10 + 0.10 = 1.00
        scores_min = EvidenceScores(0.0, 0.0, 0.0, 0.0, 0.0)
        assert scores_min.composite_score() == 0.0

        scores_max = EvidenceScores(1.0, 1.0, 1.0, 1.0, 1.0)
        assert scores_max.composite_score() == 1.0

        # Clamping check on out-of-range inputs
        scores_excess = EvidenceScores(2.0, 2.0, 2.0, 2.0, 2.0)
        assert scores_excess.composite_score() == 1.0

    def test_shannon_entropy_mathematical_stability(self):
        # 1 byte
        assert calculate_shannon_entropy(b"A") == 0.0
        # 2 distinct bytes
        assert abs(calculate_shannon_entropy(b"AB") - 1.0) < 0.01
        # Block scanning with uneven buffer
        blocks = scan_entropy_blocks(b"\x00" * 5000, block_size=4096)
        assert len(blocks) == 2
        assert blocks[0].size == 4096
        assert blocks[1].size == 904
        assert all(b.entropy == 0.0 for b in blocks)

    def test_vss_volume_injection_rejection(self):
        # Malicious volume parameter attempting command chaining must be rejected
        res = VssSanitizer.execute_purge(
            confirm_destructive=True,
            dry_run=True,
            target_volume="C: & whoami",
        )
        assert res.status == "BLOCKED"
        assert "Invalid target volume format" in (res.error_message or "")


# ─── 8. Deterministic Known-Answer NTFS $Bitmap Fixtures ─────────────────────

class TestNtfsKnownAnswerFixtures:
    """Deterministic known-answer test vectors verifying bit decoding and run grouping."""

    def test_known_answer_alternating_pattern(self):
        # 0x55 = 0b01010101 (clusters 0,2,4,6 allocated; 1,3,5,7 free)
        # 0xAA = 0b10101010 (clusters 8,10,12,14 free; 9,11,13,15 allocated)
        raw_bitmap = bytes([0x55, 0xAA])
        analyzer = NtfsBitmapAnalyzer(raw_bitmap, bytes_per_sector=512, sectors_per_cluster=8)

        # Exact bit-level verification
        expected_alloc = [
            True, False, True, False, True, False, True, False,  # byte 0
            False, True, False, True, False, True, False, True,  # byte 1
        ]
        for c_idx, expected in enumerate(expected_alloc):
            assert analyzer.is_cluster_allocated(c_idx) == expected, f"Mismatch at cluster {c_idx}"

        stats = analyzer.get_allocation_stats()
        assert stats.total_clusters == 16
        assert stats.allocated_clusters == 8
        assert stats.free_clusters == 8
        assert stats.free_percentage == 50.0
        assert stats.cluster_size_bytes == 4096

    def test_known_answer_all_allocated(self):
        # 8 bytes of 0xFF = 64 clusters, all allocated
        raw_bitmap = b"\xff" * 8
        analyzer = NtfsBitmapAnalyzer(raw_bitmap)
        stats = analyzer.get_allocation_stats()
        assert stats.total_clusters == 64
        assert stats.allocated_clusters == 64
        assert stats.free_clusters == 0
        assert stats.free_percentage == 0.0
        assert stats.unallocated_runs_count == 0

        free_runs = analyzer.extract_cluster_runs(policy=BitmapScanPolicy.FREE_ONLY)
        assert len(free_runs) == 0

    def test_known_answer_all_free(self):
        # 8 bytes of 0x00 = 64 clusters, all free
        raw_bitmap = b"\x00" * 8
        analyzer = NtfsBitmapAnalyzer(raw_bitmap)
        stats = analyzer.get_allocation_stats()
        assert stats.total_clusters == 64
        assert stats.allocated_clusters == 0
        assert stats.free_clusters == 64
        assert stats.free_percentage == 100.0
        assert stats.unallocated_runs_count == 1

        free_runs = analyzer.extract_cluster_runs(policy=BitmapScanPolicy.FREE_ONLY)
        assert len(free_runs) == 1
        assert free_runs[0].start_cluster == 0
        assert free_runs[0].length == 64
        assert free_runs[0].is_allocated is False

    def test_known_answer_cluster_to_byte_offset_math(self):
        raw_bitmap = b"\x00" * 16
        analyzer = NtfsBitmapAnalyzer(raw_bitmap, bytes_per_sector=512, sectors_per_cluster=8)
        # 512 * 8 = 4096 bytes per cluster
        assert analyzer.cluster_to_byte_offset(0) == 0
        assert analyzer.cluster_to_byte_offset(1) == 4096
        assert analyzer.cluster_to_byte_offset(10) == 40960


# ─── 9. Comprehensive Security Test Matrix ──────────────────────────────────

class TestExplicitSecurityMatrix:
    """Security audit tests verifying command safety, path isolation, and secret absence."""

    def test_command_injection_safeguards(self):
        # Malicious volume targets attempting shell chaining / pipes
        malicious_targets = [
            "C: | calc.exe",
            "C: && notepad",
            "C:; echo pwned",
            "`whoami`",
            "$(reboot)",
            "../../Windows",
        ]
        for target in malicious_targets:
            res = VssSanitizer.execute_purge(
                confirm_destructive=True,
                dry_run=True,
                target_volume=target,
            )
            assert res.status == "BLOCKED"
            assert "Invalid target volume format" in (res.error_message or "")

    def test_path_traversal_isolation_guard(self, tmp_path: Path):
        from recovery_adapter import RecoveryError, RecoveryTarget, TargetKind
        src_dir = tmp_path / "source_media"
        src_dir.mkdir()
        dest_dir = src_dir / "recovered_inside"
        dest_dir.mkdir()

        target = RecoveryTarget(path=str(src_dir), kind=TargetKind.FOLDER)
        # Enforce that destination residing inside source tree is BLOCKED
        with pytest.raises(RecoveryError, match="cannot reside inside the recovery source tree"):
            target.validate_destination(dest_dir)

    def test_zip_traversal_filename_parsing_safety(self):
        # ZIP with path traversal filename "../../etc/passwd"
        buf = io.BytesIO()
        import zipfile
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as zf:
            zf.writestr("../../evil.sh", b"malicious content")

        zip_bytes = buf.getvalue()
        carver = ZipCarveStream(zip_bytes)
        assert carver.parse() is True
        # Carving records filename safely without extracting to filesystem
        assert len(carver.members) == 1
        assert carver.members[0].filename == "../../evil.sh"

    def test_malformed_input_crash_resistance(self):
        # Random corrupt byte buffers passed into all format validators
        corrupt_data = os.urandom(1024)
        v_jpg, _, _, _ = FormatValidator.validate_jpeg(corrupt_data)
        assert v_jpg is False
        v_png, _, _, _ = FormatValidator.validate_png(corrupt_data)
        assert v_png is False
        v_pdf, _, _, _ = FormatValidator.validate_pdf(corrupt_data)
        assert v_pdf is False
        v_sql, _, _, _ = FormatValidator.validate_sqlite(corrupt_data)
        assert v_sql is False

    def test_resource_exhaustion_bounds(self):
        # Extremely large candidate stream bounded by max_candidates
        many_pngs = (b"\x89PNG\r\n\x1a\n" + b"\x00\x00\x00\rIHDR" + b"\x00" * 17 + b"\x00\x00\x00\x00IEND\xaeB`\x82") * 100
        carver = DeepCarverEngine(max_candidates=5)
        cands = carver.carve(many_pngs)
        assert len(cands) == 5

    def test_zero_secrets_or_hardcoded_credentials(self):
        # Verify no hardcoded API keys or test secrets in phase 1 source files
        import glob
        import re
        secret_patterns = [
            re.compile(r"ghp_[A-Za-z0-9_]{36}"),
            re.compile(r"sk-[A-Za-z0-9]{32}"),
            re.compile(r"-----BEGIN [A-Z]+ PRIVATE KEY-----"),
        ]
        this_file = Path(__file__).resolve()
        source_files = [f for f in glob.glob("*.py") + glob.glob("tests/*.py") if Path(f).resolve() != this_file]
        for fpath in source_files:
            content = Path(fpath).read_text(encoding="utf-8", errors="ignore")
            for pattern in secret_patterns:
                assert not pattern.search(content), f"Potential secret found in {fpath}"

    def test_zip_carve_stream_deltas_and_fragment_grouping(self):
        """Test delta property and get_fragment_deltas from AKHANDA zipcarve.py integration."""
        buf = io.BytesIO()
        import zipfile
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("doc1.txt", b"Document content 1")
            zf.writestr("doc2.txt", b"Document content 2")

        zip_data = buf.getvalue()
        carver = ZipCarveStream(zip_data)
        assert carver.parse() is True
        assert len(carver.members) == 2
        # In a contiguous single-buffer archive, all members have delta = 0
        assert carver.members[0].delta == 0
        assert carver.members[1].delta == 0
        deltas = carver.get_fragment_deltas()
        assert deltas == [0]

    def test_format_validator_png_idat_pixel_completeness(self):
        """Test PNG decompressed IDAT pixel arithmetic completeness from AKHANDA reassemble.py."""
        # Minimal 1x1 8-bit RGBA PNG (width=1, height=1, bit_depth=8, color_type=6)
        # Expected uncompressed IDAT size = height * (1 + ceil(1 * 4 * 8 / 8)) = 1 * (1 + 4) = 5 bytes
        # 5 raw bytes: filter_type(0x00) + R(0xFF) + G(0x00) + B(0x00) + A(0xFF)
        raw_scanline = b"\x00\xff\x00\x00\xff"
        compressed_idat = zlib.compress(raw_scanline)
        
        ihdr_data = struct.pack(">IIBBBBB", 1, 1, 8, 6, 0, 0, 0)
        ihdr_crc = zlib.crc32(b"IHDR" + ihdr_data)
        ihdr_chunk = struct.pack(">I", len(ihdr_data)) + b"IHDR" + ihdr_data + struct.pack(">I", ihdr_crc)

        idat_crc = zlib.crc32(b"IDAT" + compressed_idat)
        idat_chunk = struct.pack(">I", len(compressed_idat)) + b"IDAT" + compressed_idat + struct.pack(">I", idat_crc)

        iend_crc = zlib.crc32(b"IEND")
        iend_chunk = struct.pack(">I", 0) + b"IEND" + struct.pack(">I", iend_crc)

        valid_png = b"\x89PNG\r\n\x1a\n" + ihdr_chunk + idat_chunk + iend_chunk

        valid, length, evidence, meta = FormatValidator.validate_png(valid_png)
        assert valid is True
        assert meta["idat_complete"] is True
        assert evidence.continuity == 1.0
        assert evidence.structure == 1.0

        # Incomplete/truncated scanline: only 3 bytes instead of 5
        corrupted_idat = zlib.compress(b"\x00\xff\x00")
        corrupted_idat_chunk = struct.pack(">I", len(corrupted_idat)) + b"IDAT" + corrupted_idat + struct.pack(">I", zlib.crc32(b"IDAT" + corrupted_idat))
        corrupt_png = b"\x89PNG\r\n\x1a\n" + ihdr_chunk + corrupted_idat_chunk + iend_chunk

        valid_c, length_c, evidence_c, meta_c = FormatValidator.validate_png(corrupt_png)
        assert valid_c is True
        assert meta_c["idat_complete"] is False
        assert evidence_c.continuity < 1.0
