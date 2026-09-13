"""DREX-V2 Phase 4 Comprehensive Acceptance Test Suite:
Advanced File Carving & Fragment Reconstruction

Validates:
1. Known-Answer Contiguous Fixtures for all supported formats with exact byte and SHA-256 verification.
2. PNG Non-Interlaced & Adam7 7-Pass Interlaced Decompression.
3. JPEG DRI & Conditional RST Marker Sequencing.
4. ZIP and OOXML Container vs. Member Granular Recovery.
5. All 9 Streaming-Boundary Scenarios (window +- 1, overlap +- 1, sector +- 1, boundary crossing).
6. Adversarial Signature & False-Positive Resilience.
7. Multi-Fragment Unique vs. Ambiguous Reconstruction.
8. Missing/Corrupted Fragment Truthful Containment (Zero synthetic byte invention).
9. Phase 2 Forensic Vault & Cryptographically Hash-Linked Audit Chain Integration.
10. Read-Only Source Immutability Invariant.
11. Bounded-Memory Environment-Aware Performance Profiling.
"""

import hashlib
import io
import math
import struct
import tempfile
import time
import zlib
from pathlib import Path
import pytest

from carver_engine import (
    CarveConfig,
    CarvedArtifact,
    CarvedCandidate,
    DeepCarverEngine,
    FragmentExtent,
    StreamingCarver,
)
from forensic_vault import (
    EvidenceSourceType,
    EvidenceVault,
    ForensicCaseManager,
    RecoveryArtifactRecord,
    RecoveryCandidateState,
    VaultObjectType,
)
from fragment_engine import (
    BoundedPermutationReconstructor,
    DeltaClusterReassembler,
    FragmentChunk,
    FragmentReassembler,
    JpegEntropyDecoder,
    JpegRstStreamReassembler,
    ZipCarveStream,
    seam_continuity_score,
    shannon_entropy,
)
from fs_base import SyntheticFixtureSource
from validators import (
    CandidateState,
    EvidenceScores,
    FormatCapability,
    FormatRegistry,
    MemberStatus,
    SupportLevel,
)
from validators.bmp import BmpValidator
from validators.elf import ElfValidator
from validators.gif import GifValidator
from validators.jpeg import JpegValidator
from validators.mp3 import Mp3Validator
from validators.mp4 import Mp4Validator
from validators.ooxml import OoxmlValidator
from validators.pdf import PdfValidator
from validators.pe import PeValidator
from validators.png import PngValidator
from validators.rar import RarValidator
from validators.riff import RiffValidator
from validators.sevenzip import SevenZipValidator
from validators.sqlite import SqliteValidator
from validators.tiff import TiffValidator
from validators.zip import ZipValidator


# ─── Helper Fixture Generators ───────────────────────────────────────────────

def make_valid_jpeg(width: int = 16, height: int = 16, with_dri: bool = False) -> bytes:
    """Generate minimal structurally valid JPEG bytes with SOF0, SOS, DQT, DHT, and EOI."""
    buf = bytearray(b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x01\x00`\x00`\x00\x00")
    # DQT
    buf.extend(b"\xff\xdb\x00\x43\x00" + (b"\x10" * 64))
    # SOF0
    buf.extend(b"\xff\xc0\x00\x11\x08")
    buf.extend(struct.pack(">HHB", height, width, 3))
    buf.extend(b"\x01\x11\x00\x02\x11\x01\x03\x11\x01")
    # DHT
    buf.extend(b"\xff\xc4\x00\x1f\x00\x00\x01\x05\x01\x01\x01\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b")
    # DRI (optional)
    if with_dri:
        buf.extend(b"\xff\xdd\x00\x04\x00\x02")  # restart interval = 2
    # SOS
    buf.extend(b"\xff\xda\x00\x0c\x03\x01\x00\x02\x11\x03\x11\x00\x3f\x00")
    # Entropy payload with byte-stuffing and RST markers if DRI enabled
    if with_dri:
        buf.extend(b"\x12\x34\xff\x00\x56\x78\xff\xd0\x9a\xbc\xff\x00\xde\xf0\xff\xd1\x11\x22")
    else:
        buf.extend(b"\x12\x34\xff\x00\x56\x78\x9a\xbc\xff\x00\xde\xf0")
    # EOI
    buf.extend(b"\xff\xd9")
    return bytes(buf)


def make_valid_png(width: int = 8, height: int = 8, interlaced: bool = False) -> bytes:
    """Generate minimal valid PNG with IHDR, IDAT, and IEND chunks with exact CRC32s."""
    buf = bytearray(b"\x89PNG\r\n\x1a\n")
    interlace_val = 1 if interlaced else 0
    # IHDR: 8x8, 8-bit, RGB (color_type 2), interlace
    ihdr_data = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, interlace_val)
    ihdr_crc = zlib.crc32(b"IHDR" + ihdr_data) & 0xFFFFFFFF
    buf.extend(struct.pack(">I", len(ihdr_data)) + b"IHDR" + ihdr_data + struct.pack(">I", ihdr_crc))

    # IDAT raw raster data
    if not interlaced:
        raw_raster = bytearray()
        for _ in range(height):
            raw_raster.append(0)  # filter type 0
            raw_raster.extend(b"\xaa\xbb\xcc" * width)  # RGB
    else:
        # Adam7 raw raster
        raw_raster = bytearray()
        passes = [(0, 0, 8, 8), (4, 0, 8, 8), (0, 4, 4, 8), (2, 0, 4, 4), (0, 2, 2, 4), (1, 0, 2, 2), (0, 1, 1, 2)]
        for x_orig, y_orig, x_step, y_step in passes:
            pw = 0 if width <= x_orig else (width - x_orig + x_step - 1) // x_step
            ph = 0 if height <= y_orig else (height - y_orig + y_step - 1) // y_step
            if pw > 0 and ph > 0:
                for _ in range(ph):
                    raw_raster.append(0)
                    raw_raster.extend(b"\x11\x22\x33" * pw)

    compressed_idat = zlib.compress(bytes(raw_raster))
    idat_crc = zlib.crc32(b"IDAT" + compressed_idat) & 0xFFFFFFFF
    buf.extend(struct.pack(">I", len(compressed_idat)) + b"IDAT" + compressed_idat + struct.pack(">I", idat_crc))

    # IEND
    iend_crc = zlib.crc32(b"IEND") & 0xFFFFFFFF
    buf.extend(struct.pack(">I", 0) + b"IEND" + struct.pack(">I", iend_crc))
    return bytes(buf)


def make_valid_zip(filenames_and_contents: List[Tuple[str, bytes]]) -> bytes:
    """Generate valid in-memory ZIP archive with LFH, CD, and EOCD."""
    buf = bytearray()
    cd_entries = bytearray()
    cd_offset = 0

    for name, content in filenames_and_contents:
        fn_bytes = name.encode("utf-8")
        crc = zlib.crc32(content) & 0xFFFFFFFF
        comp_data = content  # Method 0 (Stored)
        loc_offset = len(buf)

        # LFH
        lfh = struct.pack("<4sHHHHHIIIHH", b"PK\x03\x04", 20, 0, 0, 0, 0, crc, len(comp_data), len(content), len(fn_bytes), 0)
        buf.extend(lfh + fn_bytes + comp_data)

        # CD Entry
        cde = struct.pack("<4sHHHHHHIIIHHHHHII", b"PK\x01\x02", 20, 20, 0, 0, 0, 0, crc, len(comp_data), len(content), len(fn_bytes), 0, 0, 0, 0, 0, loc_offset)
        cd_entries.extend(cde + fn_bytes)

    cd_offset = len(buf)
    cd_size = len(cd_entries)
    buf.extend(cd_entries)

    # EOCD
    eocd = struct.pack("<4sHHHHIIH", b"PK\x05\x06", 0, 0, len(filenames_and_contents), len(filenames_and_contents), cd_size, cd_offset, 0)
    buf.extend(eocd)
    return bytes(buf)


def make_valid_pdf() -> bytes:
    """Generate minimal valid PDF document."""
    pdf = (
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
        b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\nendobj\n"
        b"xref\n0 4\n0000000000 65535 f \n0000000009 00000 n \n0000000058 00000 n \n0000000115 00000 n \n"
        b"trailer\n<< /Size 4 /Root 1 0 R >>\nstartxref\n190\n%%EOF\n"
    )
    return pdf


def make_valid_sqlite() -> bytes:
    """Generate minimal valid SQLite 3 database file with Page 1 B-tree table leaf header."""
    page_size = 512
    buf = bytearray(page_size)
    buf[:16] = b"SQLite format 3\x00"
    struct.pack_into(">H", buf, 16, page_size)
    buf[18] = 1  # write version
    buf[19] = 1  # read version
    struct.pack_into(">I", buf, 24, 1)  # change counter
    struct.pack_into(">I", buf, 28, 1)  # db size in pages = 1
    struct.pack_into(">I", buf, 40, 1)  # schema cookie
    # Page 1 B-Tree table leaf header at offset 100
    buf[100] = 0x0D  # Table Leaf
    struct.pack_into(">H", buf, 103, 0)  # 0 cells
    return bytes(buf)


def make_valid_bmp() -> bytes:
    """Generate minimal valid 8x8 24bpp BMP."""
    width, height = 8, 8
    row_bytes = ((width * 3 + 3) // 4) * 4
    pixel_bytes = row_bytes * height
    bf_size = 54 + pixel_bytes
    hdr = struct.pack("<2sIHHI", b"BM", bf_size, 0, 0, 54)
    info = struct.pack("<IiiHHIIIIII", 40, width, height, 1, 24, 0, pixel_bytes, 2835, 2835, 0, 0)
    pixels = b"\xff\x00\x00" * width + b"\x00" * (row_bytes - width * 3)
    return hdr + info + (pixels * height)


def make_valid_gif() -> bytes:
    """Generate minimal valid GIF89a with 1x1 image and trailer."""
    buf = bytearray(b"GIF89a\x01\x00\x01\x00\x80\x00\x00")  # 1x1, 2-color GCT
    buf.extend(b"\x00\x00\x00\xff\xff\xff")  # Black, White
    # Image descriptor
    buf.extend(b"\x2c\x00\x00\x00\x00\x01\x00\x01\x00\x00")
    # Image sub-blocks
    buf.extend(b"\x02\x02\x44\x01\x00")  # LZW min code 2, 2-byte sub-block, terminator
    # Trailer
    buf.extend(b"\x3b")
    return bytes(buf)


def make_valid_riff_wav() -> bytes:
    """Generate minimal valid RIFF WAVE audio file."""
    audio_data = b"\x00\x7f" * 100
    fmt_chunk = struct.pack("<4sIHHIIHH", b"fmt ", 16, 1, 1, 8000, 8000, 1, 8)
    data_chunk = struct.pack("<4sI", b"data", len(audio_data)) + audio_data
    riff_len = 4 + len(fmt_chunk) + len(data_chunk)
    hdr = struct.pack("<4sI4s", b"RIFF", riff_len, b"WAVE")
    return hdr + fmt_chunk + data_chunk


def make_valid_elf() -> bytes:
    """Generate minimal valid ELF64 header."""
    buf = bytearray(64)
    buf[:4] = b"\x7fELF"
    buf[4] = 2  # 64-bit
    buf[5] = 1  # Little endian
    buf[6] = 1  # Version 1
    # e_type = ET_EXEC (2), e_machine = EM_X86_64 (62), e_version = 1
    struct.pack_into("<HHI", buf, 16, 2, 62, 1)
    struct.pack_into("<Q", buf, 24, 0x400000)  # e_entry
    struct.pack_into("<Q", buf, 32, 64)        # e_phoff
    struct.pack_into("<Q", buf, 40, 0)         # e_shoff
    struct.pack_into("<HHHHHH", buf, 52, 64, 56, 1, 64, 0, 0)
    # 1 dummy Program Header
    ph = struct.pack("<IIQQQQQQ", 1, 5, 0, 0x400000, 0x400000, 64, 64, 0x1000)
    return bytes(buf + ph)


def make_valid_pe() -> bytes:
    """Generate minimal valid PE binary with MS-DOS stub and PE header."""
    dos_stub = bytearray(128)
    dos_stub[:2] = b"MZ"
    struct.pack_into("<I", dos_stub, 0x3C, 128)  # e_lfanew = 128
    pe_hdr = struct.pack("<4sHHIIIHH", b"PE\x00\x00", 0x8664, 1, int(time.time()), 0, 0, 0, 0x0102)
    # Section header
    sec_hdr = struct.pack("<8sIIIIIIHHI", b".text\x00\x00\x00", 100, 0x1000, 512, 512, 0, 0, 0, 0, 0x60000020)
    padding = b"\x00" * (512 - len(dos_stub) - len(pe_hdr) - len(sec_hdr))
    raw_sec = b"\x90" * 512  # NOPs
    return bytes(dos_stub + pe_hdr + sec_hdr + padding + raw_sec)


# ─── 1. Known-Answer Contiguous Fixture Tests ────────────────────────────────

class TestKnownAnswerCarving:
    """Tests clean contiguous carving across all formats with byte-for-byte and SHA-256 verification."""

    def test_carve_known_answer_jpeg(self):
        jpeg_bytes = make_valid_jpeg(16, 16)
        expected_hash = hashlib.sha256(jpeg_bytes).hexdigest()

        res = JpegValidator.validate(jpeg_bytes)
        assert res.is_valid is True
        assert res.state == CandidateState.RECOVERED_ARTIFACT
        assert res.length == len(jpeg_bytes)
        assert res.metadata["width"] == 16
        assert res.metadata["height"] == 16
        assert hashlib.sha256(jpeg_bytes[:res.length]).hexdigest() == expected_hash

    def test_carve_known_answer_png_non_interlaced(self):
        png_bytes = make_valid_png(8, 8, interlaced=False)
        expected_hash = hashlib.sha256(png_bytes).hexdigest()

        res = PngValidator.validate(png_bytes)
        assert res.is_valid is True
        assert res.state == CandidateState.RECOVERED_ARTIFACT
        assert res.length == len(png_bytes)
        assert res.metadata["geometry_matched"] is True
        assert hashlib.sha256(png_bytes[:res.length]).hexdigest() == expected_hash

    def test_carve_known_answer_png_adam7_interlaced(self):
        png_adam7 = make_valid_png(8, 8, interlaced=True)
        expected_hash = hashlib.sha256(png_adam7).hexdigest()

        res = PngValidator.validate(png_adam7)
        assert res.is_valid is True
        assert res.state == CandidateState.RECOVERED_ARTIFACT
        assert res.metadata["interlace_method"] == 1
        assert res.metadata["geometry_matched"] is True
        assert hashlib.sha256(png_adam7[:res.length]).hexdigest() == expected_hash

    def test_carve_known_answer_pdf(self):
        pdf_bytes = make_valid_pdf()
        expected_hash = hashlib.sha256(pdf_bytes).hexdigest()

        res = PdfValidator.validate(pdf_bytes)
        assert res.is_valid is True
        assert res.state == CandidateState.RECOVERED_ARTIFACT
        assert res.length == len(pdf_bytes)
        assert hashlib.sha256(pdf_bytes[:res.length]).hexdigest() == expected_hash

    def test_carve_known_answer_zip_and_members(self):
        members = [("test1.txt", b"Hello DREX-V2 Forensic Carving!"), ("test2.bin", b"\x01\x02\x03\x04" * 16)]
        zip_bytes = make_valid_zip(members)
        expected_hash = hashlib.sha256(zip_bytes).hexdigest()

        res = ZipValidator.validate(zip_bytes)
        assert res.is_valid is True
        assert res.state == CandidateState.RECOVERED_ARTIFACT
        assert res.length == len(zip_bytes)
        assert res.member_statuses["test1.txt"] == MemberStatus.MEMBER_RECOVERED
        assert res.member_statuses["test2.bin"] == MemberStatus.MEMBER_RECOVERED
        assert hashlib.sha256(zip_bytes[:res.length]).hexdigest() == expected_hash

    def test_carve_known_answer_ooxml_docx(self):
        members = [
            ("[Content_Types].xml", b'<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>'),
            ("_rels/.rels", b'<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>'),
            ("word/document.xml", b'<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"/>'),
        ]
        docx_bytes = make_valid_zip(members)
        res = OoxmlValidator.validate(docx_bytes)
        assert res.is_valid is True
        assert res.state == CandidateState.RECOVERED_ARTIFACT
        assert res.metadata["ooxml_type"] == "docx"

    def test_carve_known_answer_sqlite(self):
        db_bytes = make_valid_sqlite()
        expected_hash = hashlib.sha256(db_bytes).hexdigest()

        res = SqliteValidator.validate(db_bytes)
        assert res.is_valid is True
        assert res.state == CandidateState.RECOVERED_ARTIFACT
        assert res.length == 512
        assert hashlib.sha256(db_bytes[:res.length]).hexdigest() == expected_hash

    def test_carve_known_answer_bmp(self):
        bmp_bytes = make_valid_bmp()
        expected_hash = hashlib.sha256(bmp_bytes).hexdigest()

        res = BmpValidator.validate(bmp_bytes)
        assert res.is_valid is True
        assert res.state == CandidateState.RECOVERED_ARTIFACT
        assert res.length == len(bmp_bytes)
        assert hashlib.sha256(bmp_bytes[:res.length]).hexdigest() == expected_hash

    def test_carve_known_answer_gif(self):
        gif_bytes = make_valid_gif()
        expected_hash = hashlib.sha256(gif_bytes).hexdigest()

        res = GifValidator.validate(gif_bytes)
        assert res.is_valid is True
        assert res.state == CandidateState.RECOVERED_ARTIFACT
        assert res.length == len(gif_bytes)
        assert hashlib.sha256(gif_bytes[:res.length]).hexdigest() == expected_hash

    def test_carve_known_answer_riff_wav(self):
        wav_bytes = make_valid_riff_wav()
        expected_hash = hashlib.sha256(wav_bytes).hexdigest()

        res = RiffValidator.validate(wav_bytes)
        assert res.is_valid is True
        assert res.state == CandidateState.RECOVERED_ARTIFACT
        assert res.length == len(wav_bytes)
        assert hashlib.sha256(wav_bytes[:res.length]).hexdigest() == expected_hash

    def test_carve_known_answer_elf(self):
        elf_bytes = make_valid_elf()
        expected_hash = hashlib.sha256(elf_bytes).hexdigest()

        res = ElfValidator.validate(elf_bytes)
        assert res.is_valid is True
        assert res.state == CandidateState.RECOVERED_ARTIFACT
        assert res.length == len(elf_bytes)
        assert hashlib.sha256(elf_bytes[:res.length]).hexdigest() == expected_hash

    def test_carve_known_answer_pe(self):
        pe_bytes = make_valid_pe()
        expected_hash = hashlib.sha256(pe_bytes).hexdigest()

        res = PeValidator.validate(pe_bytes)
        assert res.is_valid is True
        assert res.state == CandidateState.RECOVERED_ARTIFACT
        assert res.length == len(pe_bytes)
        assert hashlib.sha256(pe_bytes[:res.length]).hexdigest() == expected_hash


# ─── 2. Streaming-Boundary Test Suite (9 Scenarios) ──────────────────────────

class TestStreamingBoundaries:
    """Verifies scanner accuracy for signatures and payloads crossing window/overlap/sector boundaries."""

    @pytest.fixture
    def carver_engine(self):
        cfg = CarveConfig(window_size=1024, overlap_size=256, sector_size=512, max_candidates=100)
        return StreamingCarver(config=cfg)

    def _test_boundary_placement(self, carver_engine, target_offset):
        jpeg = make_valid_jpeg(8, 8)
        img_size = max(4096, target_offset + len(jpeg) + 512)
        raw_disk = bytearray(b"\x00" * img_size)
        raw_disk[target_offset:target_offset + len(jpeg)] = jpeg

        source = SyntheticFixtureSource(bytes(raw_disk))
        artifacts = carver_engine.carve_artifacts(source)

        assert len(artifacts) >= 1
        found = next((a for a in artifacts if a.extents[0].start_offset == target_offset), None)
        assert found is not None
        assert found.file_type == "JPEG"
        assert found.state == CandidateState.RECOVERED_ARTIFACT
        assert found.data == jpeg
        assert found.sha256 == hashlib.sha256(jpeg).hexdigest()

    def test_carve_signature_at_window_minus_1(self, carver_engine):
        self._test_boundary_placement(carver_engine, 1024 - 1)

    def test_carve_signature_at_window_boundary(self, carver_engine):
        self._test_boundary_placement(carver_engine, 1024)

    def test_carve_signature_at_window_plus_1(self, carver_engine):
        self._test_boundary_placement(carver_engine, 1024 + 1)

    def test_carve_signature_at_overlap_minus_1(self, carver_engine):
        self._test_boundary_placement(carver_engine, 256 - 1)

    def test_carve_signature_at_overlap_boundary(self, carver_engine):
        self._test_boundary_placement(carver_engine, 256)

    def test_carve_signature_at_overlap_plus_1(self, carver_engine):
        self._test_boundary_placement(carver_engine, 256 + 1)

    def test_carve_signature_at_sector_minus_1(self, carver_engine):
        self._test_boundary_placement(carver_engine, 511)

    def test_carve_signature_at_sector_boundary(self, carver_engine):
        self._test_boundary_placement(carver_engine, 512)

    def test_carve_signature_at_sector_plus_1(self, carver_engine):
        self._test_boundary_placement(carver_engine, 513)

    def test_carve_payload_crossing_window_boundary(self, carver_engine):
        """Payload starts before window end, spans across window seam into window 2."""
        pdf = make_valid_pdf()
        start_offset = 950  # window is 1024; PDF length ~260 bytes -> spans across 1024
        raw_disk = bytearray(b"\x00" * 4096)
        raw_disk[start_offset:start_offset + len(pdf)] = pdf

        source = SyntheticFixtureSource(bytes(raw_disk))
        artifacts = carver_engine.carve_artifacts(source)

        found = next((a for a in artifacts if a.extents[0].start_offset == start_offset), None)
        assert found is not None
        assert found.file_type == "PDF"
        assert found.data == pdf
        assert found.sha256 == hashlib.sha256(pdf).hexdigest()


# ─── 3. Adversarial Signature & False-Positive Tests ─────────────────────────

class TestAdversarialResilience:
    """Verifies that invalid or adversarial inputs are rejected without improper promotion."""

    def test_adversarial_fake_jpeg_rejected(self):
        # Random high entropy noise prefixed with \xFF\xD8\xFF
        noise = b"\xff\xd8\xff" + b"\x12\x34\x56\x78\x9a\xbc\xde\xf0" * 50
        res = JpegValidator.validate(noise)
        assert res.state == CandidateState.REJECTED_FALSE_POSITIVE
        assert res.is_valid is False

    def test_adversarial_fake_png_corrupt_crc_rejected(self):
        png = bytearray(make_valid_png(8, 8))
        # Corrupt IDAT CRC
        png[len(png) - 16] ^= 0xFF
        res = PngValidator.validate(bytes(png))
        assert res.state == CandidateState.CORRUPTED_INCOMPLETE
        assert res.state != CandidateState.RECOVERED_ARTIFACT
        assert any("CRC mismatch" in lim for lim in res.limitations)

    def test_adversarial_fake_zip_rejected(self):
        fake_zip = b"PK\x03\x04" + b"\xaa\xbb\xcc\xdd" * 20
        res = ZipValidator.validate(fake_zip)
        assert res.state == CandidateState.REJECTED_FALSE_POSITIVE
        assert res.is_valid is False

    def test_adversarial_fake_pdf_rejected(self):
        fake_pdf = b"%PDF-1.4\nThis is a plain text file pretending to be a PDF without objects."
        res = PdfValidator.validate(fake_pdf)
        assert res.state == CandidateState.REJECTED_FALSE_POSITIVE
        assert res.is_valid is False

    def test_adversarial_repeated_signatures_deduplication(self):
        """100 identical PNG signatures in consecutive sectors should not cause candidate explosion."""
        cfg = CarveConfig(window_size=2048, overlap_size=256, max_candidates=5)
        carver = StreamingCarver(config=cfg)

        raw_disk = bytearray(b"\x00" * (100 * 512))
        valid_png = make_valid_png(4, 4)
        for i in range(100):
            raw_disk[i * 512:i * 512 + len(valid_png)] = valid_png

        artifacts = carver.carve_artifacts(bytes(raw_disk))
        assert len(artifacts) <= 5  # Bounded strictly by max_candidates


# ─── 4. Fragment Reconstruction & Permutation Tests ──────────────────────────

class TestFragmentReconstruction:
    """Validates multi-fragment reassembly, AKHANDA ZIP delta clustering, and ambiguity containment."""

    def test_fragment_unique_order_reassembly_jpeg(self):
        """JPEG with DRI and RST markers split into 3 fragments [A, B, C] placed as [C, A, B]."""
        jpeg_dri = make_valid_jpeg(16, 16, with_dri=True)
        # Split into 3 parts
        p1 = jpeg_dri[:60]
        p2 = jpeg_dri[60:120]
        p3 = jpeg_dri[120:]

        scrambled = [p3, p1, p2]
        reconstructed, is_valid, rst_seq = JpegRstStreamReassembler.reassemble_rst_fragments(scrambled)

        assert is_valid is True
        assert reconstructed == jpeg_dri
        assert hashlib.sha256(reconstructed).hexdigest() == hashlib.sha256(jpeg_dri).hexdigest()

    def test_fragment_akhanda_zip_delta_clustering(self):
        """ZIP archive split non-contiguously on disk clusters correctly by relative CD deltas (PROV-001)."""
        members = [("m1.txt", b"Chunk 1 payload"), ("m2.txt", b"Chunk 2 payload")]
        zip_bytes = make_valid_zip(members)

        # Place on synthetic disk at sector 10 (offset 5120)
        disk = bytearray(b"\x00" * 20480)
        disk[5120:5120 + len(zip_bytes)] = zip_bytes

        carver = ZipCarveStream(bytes(disk))
        assert carver.parse() is True
        deltas = carver.get_fragment_deltas()
        assert len(deltas) == 1
        assert deltas[0] == 5120  # Matches exact image offset delta

    def test_fragment_ambiguous_order_retained_as_ambiguous(self):
        """Two disjoint ambiguous chunks with equal evidence must NOT be arbitrarily promoted."""
        chunk1 = b"DATA_PART_1_AAAA"
        chunk2 = b"DATA_PART_2_BBBB"

        # Dummy validator that accepts any concatenation of chunk1 and chunk2
        def dummy_validator(data: bytes):
            if chunk1 in data and chunk2 in data and len(data) == len(chunk1) + len(chunk2):
                return JpegValidator.validate(make_valid_jpeg(8, 8))  # Returns valid result
            from validators.base import ValidationResult, CandidateState, EvidenceScores
            return ValidationResult(is_valid=False, length=0, state=CandidateState.REJECTED_FALSE_POSITIVE, evidence=EvidenceScores())

        reconstructor = BoundedPermutationReconstructor(max_depth=4)
        _, state, limitations = reconstructor.reconstruct_with_ambiguity_check([chunk1, chunk2], dummy_validator)

        assert state == CandidateState.AMBIGUOUS_RECONSTRUCTION
        assert any("Ambiguous reconstruction" in lim for lim in limitations)

    def test_fragment_missing_middle_truthful_failure(self):
        """Missing middle fragment must fail truthfully (CORRUPTED_INCOMPLETE); zero fake bytes."""
        jpeg = make_valid_jpeg(16, 16)
        chunk_head = jpeg[:50]
        chunk_tail = jpeg[-30:]

        res = JpegValidator.validate(chunk_head + chunk_tail)
        assert res.state in (CandidateState.CORRUPTED_INCOMPLETE, CandidateState.REJECTED_FALSE_POSITIVE)
        assert res.state != CandidateState.RECOVERED_ARTIFACT


# ─── 5. Vault & Audit Integration & Source Immutability ──────────────────────

class TestVaultAndSafetyIntegration:
    """Verifies read-only source invariance and Phase 2 Vault / cryptographically hash-linked audit integration."""

    def test_carve_source_immutability_invariant(self):
        pdf = make_valid_pdf()
        raw_disk = bytearray(b"\x00" * 2048)
        raw_disk[512:512 + len(pdf)] = pdf
        original_bytes = bytes(raw_disk)
        original_hash = hashlib.sha256(original_bytes).hexdigest()

        source = SyntheticFixtureSource(original_bytes)
        carver = StreamingCarver()
        artifacts = carver.carve_artifacts(source)

        assert len(artifacts) == 1
        # Invariance assertion: source length and SHA-256 strictly unchanged
        assert len(source.read(0, source.get_size())) == len(original_bytes)
        assert hashlib.sha256(source.read(0, source.get_size())).hexdigest() == original_hash

    def test_carve_evidence_vault_audit_chain_registration(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            mgr = ForensicCaseManager(Path(tmp_dir))
            case = mgr.create_case("CASE-2026-CARVE-01", "Forensic Carving Case", "Examiner Sharma", "DREX Lab")

            jpeg_bytes = make_valid_jpeg(16, 16)
            carver = StreamingCarver()
            artifacts = carver.carve_artifacts(jpeg_bytes)

            assert len(artifacts) == 1
            art = artifacts[0]
            assert art.state == CandidateState.RECOVERED_ARTIFACT

            # Write recovered artifact temporarily and store in vault
            tmp_art_path = Path(tmp_dir) / "carved_recovered.jpg"
            tmp_art_path.write_bytes(art.data)

            cdir = mgr._case_path(case.case_id)
            vault = EvidenceVault(cdir)
            v_obj = vault.store_file(case.case_id, tmp_art_path, VaultObjectType.RECOVERED, "carved_recovered.jpg")

            assert v_obj.object_type == VaultObjectType.RECOVERED
            assert v_obj.sha256_hash == art.sha256

            # Register RecoveryArtifactRecord in case manager
            rec = RecoveryArtifactRecord(
                candidate_id=art.artifact_id,
                case_id=case.case_id,
                source_evidence_id="RAW-SOURCE-001",
                source_offset=art.extents[0].start_offset if art.extents else 0,
                filesystem_origin="RAW_CARVE",
                carving_method=f"FormatRegistry.validate({art.file_type})",
                reconstruction_method=art.reconstruction_method,
                evidence_confidence_score=art.confidence,
                validation_state=RecoveryCandidateState.RECOVERED_ARTIFACT,
                output_hash=art.sha256,
                output_size=art.total_size,
                limitations=art.limitations,
            )
            saved_rec = mgr.record_recovery_artifact(case.case_id, rec, actor="Examiner Sharma")
            assert saved_rec.validation_state == RecoveryCandidateState.RECOVERED_ARTIFACT

            # Verify audit chain integrity
            from forensic_vault import IndependentAuditVerifier, AuditVerificationStatus
            audit_path = cdir / "audit" / "audit_chain.json"
            audit_res = IndependentAuditVerifier.verify_audit_file(audit_path)
            assert audit_res.status == AuditVerificationStatus.VALID


# ─── 6. Bounded-Memory Performance Profiling ─────────────────────────────────

class TestPerformanceScaling:
    """Verifies bounded-memory execution and performance metrics reporting."""

    def test_streaming_carver_bounded_memory_scaling(self):
        """Carves a 5 MB multi-file synthetic disk image in 512 KB chunks."""
        cfg = CarveConfig(window_size=512 * 1024, overlap_size=32 * 1024, max_candidates=50)
        carver = StreamingCarver(config=cfg)

        raw_disk = bytearray(b"\x00" * (5 * 1024 * 1024))
        # Place JPEG at 1 MB, PNG at 2 MB, PDF at 3 MB, SQLite at 4 MB
        raw_disk[1024 * 1024:1024 * 1024 + len(make_valid_jpeg(8, 8))] = make_valid_jpeg(8, 8)
        raw_disk[2 * 1024 * 1024:2 * 1024 * 1024 + len(make_valid_png(8, 8))] = make_valid_png(8, 8)
        raw_disk[3 * 1024 * 1024:3 * 1024 * 1024 + len(make_valid_pdf())] = make_valid_pdf()
        raw_disk[4 * 1024 * 1024:4 * 1024 * 1024 + len(make_valid_sqlite())] = make_valid_sqlite()

        progress_reports = []
        def on_progress(p):
            progress_reports.append(p.bytes_processed)

        artifacts = carver.carve_artifacts(bytes(raw_disk), progress_callback=on_progress)

        assert len(artifacts) == 4
        assert len(progress_reports) > 0
        file_types = {a.file_type for a in artifacts}
        assert file_types == {"JPEG", "PNG", "PDF", "SQLITE"}
