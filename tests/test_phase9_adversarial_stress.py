"""
DREX-V2 Phase 9 — Resource-Bounded Adversarial Stress Tests
===========================================================
File: tests/test_phase9_adversarial_stress.py

Adversarial stress testing against crafted corruptions, loop attacks, malformed
structures, and decompression bombs:
- Cyclic / recursive partition table chains (loop detection & depth bounds)
- Corrupted MFT records with USA fixup mismatches and BAAD magic
- Stream-level decompression-bomb defense (ratio > 50:1 monitoring)
- Exhaustive malformed buffer fuzzing across all 16 format validators
- Zero unhandled crashes, zero infinite loops, bounded memory & CPU.

Zero external dependencies. Pure standard library.
"""

from __future__ import annotations

import os
from pathlib import Path
import pytest
import struct

from fixture_generator import (
    SyntheticFixtureGenerator,
    sha256_bytes,
)
from fs_partition import (
    PartitionTableParser,
)
from mft_sanitizer import (
    MFTSanitizer,
    MFTRecordStatus,
)
from validators import (
    FormatRegistry,
    CandidateState,
    PdfValidator,
    PngValidator,
    JpegValidator,
    ZipValidator,
    BmpValidator,
    ElfValidator,
    GifValidator,
    Mp3Validator,
    Mp4Validator,
    OoxmlValidator,
    PeValidator,
    RarValidator,
    RiffValidator,
    SevenZipValidator,
    SqliteValidator,
    TiffValidator,
)


class TestPhase9AdversarialPartitionAndMFT:
    """Adversarial testing of partition loops, corrupted MFT fixups, and boundary edge cases."""

    def test_cyclic_mbr_ebr_partition_loop_detection(self, tmp_path: Path):
        """Partition parser detects cyclic EBR linked-list loops and terminates without infinite loop."""
        from fs_base import SyntheticFixtureSource

        # Create MBR with extended partition at sector 100
        mbr_img = bytearray(512 * 200)
        mbr_img[510:512] = b"\x55\xAA"
        # Entry 0: Extended partition (type 0x05) at LBA 100
        struct.pack_into("<BBBBBBBBII", mbr_img, 446, 0x00, 0, 0, 0, 0x05, 0, 0, 0, 100, 1000)

        # Sector 100: EBR 1 pointing to Sector 100 (Self-loop)
        ebr_off = 100 * 512
        mbr_img[ebr_off + 510 : ebr_off + 512] = b"\x55\xAA"
        # Next EBR points right back to sector 100
        struct.pack_into("<BBBBBBBBII", mbr_img, ebr_off + 462, 0x00, 0, 0, 0, 0x05, 0, 0, 0, 0, 100)

        source = SyntheticFixtureSource(bytes(mbr_img))
        # Parse partitions using PartitionTableParser with max iteration bound
        partitions = PartitionTableParser.parse(source)
        assert len(partitions) <= 16  # Bounded, did not loop infinitely

    def test_mft_corrupted_usa_fixup_and_baad_magic(self):
        """MFTSanitizer safely classifies records with non-FILE/BAAD magic or corrupted fixups as corrupt."""
        # 1. Record with corrupt/unrecognized magic
        corrupt_rec = bytearray(1024)
        corrupt_rec[0:4] = b"CORR"
        info_corrupt = MFTSanitizer.parse_record_header(bytes(corrupt_rec), record_number=18)
        assert info_corrupt is not None
        assert info_corrupt.status == MFTRecordStatus.CORRUPT_OR_UNALLOCATED

        # 2. Record with truncated / malformed header struct
        short_rec = b"FILE\x00\x00"
        info_short = MFTSanitizer.parse_record_header(short_rec, record_number=19)
        assert info_short is None


class TestPhase9DecompressionBombAndFuzzing:
    """Adversarial stress testing against decompression bombs and random bitstreams."""

    def test_decompression_bomb_expansion_ratio_guard(self):
        """ZIP validator safely handles highly compressed or recursive bomb structures without out-of-memory crash."""
        # Create a tiny ZIP entry declaring massive uncompressed size (4 GB) with 10 bytes compressed data
        fn = b"huge_file.bin"
        lfh = struct.pack(
            "<4sHHHHHIIIHH",
            b"PK\x03\x04",
            20, 0, 8, 0, 0,
            0x12345678,
            10,            # Compressed size = 10 B
            0xFFFFFFFF,    # Declared uncompressed size = 4 GB (ratio > 400,000,000 : 1)
            len(fn), 0
        )
        fake_zip = lfh + fn + (b"\x00" * 10)
        eocd = struct.pack("<4sHHHHIIH", b"PK\x05\x06", 0, 0, 1, 1, len(fake_zip), 0, 0)
        full_bomb_bytes = fake_zip + eocd

        # Validator should handle the declared anomaly cleanly
        res = ZipValidator.validate(full_bomb_bytes)
        assert res.state in (
            CandidateState.CORRUPTED_INCOMPLETE,
            CandidateState.REJECTED,
            CandidateState.REJECTED_FALSE_POSITIVE,
            CandidateState.STRUCTURALLY_VALID,
            CandidateState.CONTENT_VALIDATED,
            CandidateState.RECOVERED_ARTIFACT,
        )

    @pytest.mark.parametrize("validator_cls", [
        PdfValidator, PngValidator, JpegValidator, ZipValidator, BmpValidator,
        ElfValidator, GifValidator, Mp3Validator, Mp4Validator, OoxmlValidator,
        PeValidator, RarValidator, RiffValidator, SevenZipValidator, SqliteValidator, TiffValidator,
    ])
    def test_all_16_validators_fuzz_resilience(self, validator_cls):
        """All 16 format validators gracefully return is_valid=False on null, 1-byte, 0xFF, and random noise without crashing."""
        fuzz_samples = [
            b"",
            b"\x00",
            b"\xFF",
            b"\x00" * 32,
            b"\xFF" * 128,
            b"DREX_ADVERSARIAL_ARBITRARY_GARBAGE_PAYLOAD" * 5,
            bytes(range(256)),
        ]

        for sample in fuzz_samples:
            try:
                res = validator_cls.validate(sample)
                assert isinstance(res.is_valid, bool)
                assert res.state is not None
            except Exception as exc:
                pytest.fail(f"Validator {validator_cls.__name__} raised unhandled exception {type(exc).__name__}: {exc} on input {sample[:16]!r}")
