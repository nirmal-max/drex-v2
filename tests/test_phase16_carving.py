"""DREX-V2 Phase 16 Advanced File Carving Test Suite
=================================================
Tests multi-format structural carving, deep candidate validation,
cryptographic deduplication, sector alignment filtering, and container
integrity verification across JPEG, PNG, PDF, SQLite, ZIP, OOXML, and MP4.
"""

import hashlib
import io
import struct
import zipfile
import pytest

from carver_engine import CarveConfig, CarvedArtifact, DeepCarverEngine, FormatValidator
from fs_base import ReadOnlySource, SourceSafetyState
from validators import CandidateState, EvidenceScores, MemberStatus
from validators.jpeg import JpegValidator
from validators.png import PngValidator
from validators.pdf import PdfValidator
from validators.sqlite import SqliteValidator
from validators.zip import ZipValidator
from validators.ooxml import OoxmlValidator


class MemorySource(ReadOnlySource):
    """Deterministic in-memory ReadOnlySource fixture for carving tests."""

    def __init__(self, data: bytes, sector_size: int = 512, identifier: str = "MEM_CARVE_SOURCE"):
        self._data = bytes(data)
        self._sector_size = sector_size
        self._id = identifier

    def read(self, offset: int, size: int) -> bytes:
        if offset < 0 or size < 0:
            raise ValueError("Negative offset/size")
        if offset >= len(self._data):
            return b""
        return self._data[offset : offset + size]

    def get_size(self) -> int:
        return len(self._data)

    def get_sector_size(self) -> int:
        return self._sector_size

    def get_safety_state(self) -> SourceSafetyState:
        return SourceSafetyState.READ_ONLY_HANDLE_CONFIRMED

    def get_source_identifier(self) -> str:
        return self._id


# ─── Helper Builders for Synthetic Valid Files ────────────────────────────────

def create_valid_jpeg() -> bytes:
    """Create a minimal structurally valid JPEG image."""
    # SOI (FF D8) + APP0 (FF E0 00 10 ...) + SOF0 (FF C0 00 0B ...) + SOS (FF DA 00 08 ...) + Scan Data + EOI (FF D9)
    soi = b"\xff\xd8"
    app0 = b"\xff\xe0\x00\x10JFIF\x00\x01\x01\x01\x00`\x00`\x00\x00"
    sof0 = b"\xff\xc0\x00\x0b\x08\x00\x10\x00\x10\x01\x01\x11\x00"  # 16x16 8-bit 1 component
    sos = b"\xff\xda\x00\x08\x01\x01\x00\x00\x3f\x00"
    scan_data = b"\x00\x12\x34\x56\x78\x9a\xbc\xde\xf0"
    eoi = b"\xff\xd9"
    return soi + app0 + sof0 + sos + scan_data + eoi


def create_valid_png() -> bytes:
    """Create a minimal valid 1x1 PNG image with correct CRCs."""
    import zlib
    sig = b"\x89PNG\r\n\x1a\n"
    # IHDR: 1x1, 8-bit depth, grayscale (0), compression 0, filter 0, interlace 0
    ihdr_data = struct.pack(">IIBBBBB", 1, 1, 8, 0, 0, 0, 0)
    ihdr_crc = zlib.crc32(b"IHDR" + ihdr_data)
    ihdr_chunk = struct.pack(">I", 13) + b"IHDR" + ihdr_data + struct.pack(">I", ihdr_crc)

    raw_pixel = b"\x00\xff"  # filter type 0 + pixel 0xff
    compressed = zlib.compress(raw_pixel)
    idat_crc = zlib.crc32(b"IDAT" + compressed)
    idat_chunk = struct.pack(">I", len(compressed)) + b"IDAT" + compressed + struct.pack(">I", idat_crc)

    iend_crc = zlib.crc32(b"IEND")
    iend_chunk = struct.pack(">I", 0) + b"IEND" + struct.pack(">I", iend_crc)

    return sig + ihdr_chunk + idat_chunk + iend_chunk


def create_valid_pdf() -> bytes:
    """Create a minimal valid PDF document with xref table and trailer."""
    content = (
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
        b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\nendobj\n"
        b"xref\n0 4\n0000000000 65535 f \n0000000009 00000 n \n0000000058 00000 n \n0000000115 00000 n \n"
        b"trailer\n<< /Size 4 /Root 1 0 R >>\nstartxref\n185\n%%EOF\n"
    )
    return content


def create_valid_zip() -> bytes:
    """Create a valid in-memory ZIP archive with a text entry."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("evidence.txt", "Forensic audit artifact content.")
    return buf.getvalue()


def create_valid_docx() -> bytes:
    """Create a valid in-memory OOXML DOCX package."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="xml" ContentType="application/xml"/></Types>')
        zf.writestr("_rels/.rels", '<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>')
        zf.writestr("word/document.xml", '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>Phase 16 Provenance</w:t></w:r></w:p></w:body></w:document>')
    return buf.getvalue()


def create_valid_sqlite() -> bytes:
    """Create a minimal valid 512-byte SQLite header."""
    header = bytearray(512)
    header[0:16] = b"SQLite format 3\x00"
    struct.pack_into(">H", header, 16, 512)  # Page size: 512 bytes
    header[18] = 1  # File format write version
    header[19] = 1  # File format read version
    header[20] = 0  # Reserved space
    header[21] = 64 # Max payload fraction
    header[22] = 32 # Min payload fraction
    header[23] = 32 # Leaf payload fraction
    struct.pack_into(">I", header, 24, 1)    # File change counter
    struct.pack_into(">I", header, 28, 1)    # Size in pages
    struct.pack_into(">I", header, 40, 1)    # Schema cookie
    struct.pack_into(">I", header, 44, 4)    # Schema format 4
    struct.pack_into(">I", header, 56, 1)    # Text encoding UTF-8
    return bytes(header)


# ─── Tests ────────────────────────────────────────────────────────────────────

def test_01_jpeg_structural_carving():
    """Verify deep structural carving of a complete JPEG image with confidence scoring."""
    raw_img = create_valid_jpeg()
    disk_data = b"\x00" * 1024 + raw_img + b"\x00" * 512
    
    engine = DeepCarverEngine(config=CarveConfig(enabled_formats=["JPEG"]))
    artifacts = engine.carve_artifacts(disk_data)
    
    assert len(artifacts) == 1
    art = artifacts[0]
    assert art.file_type == "JPEG"
    assert art.state in (CandidateState.STRUCTURALLY_VALID, CandidateState.CONTENT_VALIDATED, CandidateState.RECOVERED_ARTIFACT)
    assert art.confidence >= 0.70
    assert art.total_size == len(raw_img)
    assert art.sha256 == hashlib.sha256(raw_img).hexdigest()
    assert "header_signature" in art.confidence_factors
    assert "structural_integrity" in art.confidence_factors


def test_02_png_chunk_crc_validation():
    """Verify PNG chunk CRC32 verification and length calculation."""
    png_data = create_valid_png()
    res = PngValidator.validate(png_data)
    
    assert res.is_valid is True
    assert res.length == len(png_data)
    assert res.evidence.structure >= 0.90
    assert res.metadata["width"] == 1
    assert res.metadata["height"] == 1


def test_03_png_corrupted_crc_rejection():
    """Verify rejection / incomplete classification on CRC checksum mismatch."""
    png_data = bytearray(create_valid_png())
    # Corrupt a byte in the IHDR data section
    png_data[16] = 0xAA
    res = PngValidator.validate(bytes(png_data))
    
    # Should flag structural issue or corruption
    assert res.evidence.structure < 0.90 or res.state in (CandidateState.CORRUPTED_INCOMPLETE, CandidateState.CANDIDATE)


def test_04_pdf_structure_and_eof_carving():
    """Verify PDF carving parsing %PDF- header, trailer, and %%EOF footer."""
    pdf_data = create_valid_pdf()
    disk_image = b"\xFF" * 512 + pdf_data + b"\x00" * 256
    
    engine = DeepCarverEngine(config=CarveConfig(enabled_formats=["PDF"]))
    artifacts = engine.carve_artifacts(disk_image)
    
    assert len(artifacts) == 1
    art = artifacts[0]
    assert art.file_type == "PDF"
    assert art.total_size == len(pdf_data)
    assert art.sha256 == hashlib.sha256(pdf_data).hexdigest()
    assert art.metadata.get("pdf_version") == "1.4"


def test_05_zip_container_and_member_tracking():
    """Verify ZIP central directory carving and member status extraction."""
    zip_data = create_valid_zip()
    disk_image = b"\x00" * 512 + zip_data
    
    engine = DeepCarverEngine(config=CarveConfig(enabled_formats=["ZIP"]))
    artifacts = engine.carve_artifacts(disk_image)
    
    assert len(artifacts) >= 1
    art = artifacts[0]
    assert art.file_type == "ZIP"
    assert "evidence.txt" in art.member_statuses or "evidence.txt" in art.metadata.get("members", [])


def test_06_ooxml_docx_identification():
    """Verify OOXML validator correctly classifies DOCX with [Content_Types].xml."""
    docx_data = create_valid_docx()
    res = OoxmlValidator.validate(docx_data)
    
    assert res.is_valid is True
    assert res.state in (CandidateState.CONTENT_VALIDATED, CandidateState.STRUCTURALLY_VALID, CandidateState.RECOVERED_ARTIFACT)
    assert res.evidence.structure >= 0.80


def test_07_sqlite_database_header_validation():
    """Verify SQLite database page size and schema format validation."""
    sqlite_data = create_valid_sqlite()
    res = SqliteValidator.validate(sqlite_data)
    
    assert res.is_valid is True
    assert res.metadata.get("page_size") == 512
    assert res.evidence.structure >= 0.80


def test_08_candidate_cryptographic_deduplication():
    """Verify identical candidate byte sequences are deduplicated by SHA-256 when configured."""
    img1 = create_valid_jpeg()
    disk_image = img1 + b"\x00" * 512 + img1  # Two identical JPEGs on disk
    
    engine = DeepCarverEngine(config=CarveConfig(enabled_formats=["JPEG"], deduplicate_by_hash=True))
    artifacts = engine.carve_artifacts(disk_image)
    
    # Second duplicate should be merged / deduplicated into the first
    assert len(artifacts) == 1
    assert "CARVER" in artifacts[0].discovery_sources


def test_09_sector_aligned_only_carving_filter():
    """Verify sector_aligned_only ignores signatures that do not align to sector boundaries."""
    img = create_valid_jpeg()
    unaligned_offset = 123  # Not aligned to 512
    disk_image = b"\x00" * unaligned_offset + img
    
    # With alignment filter enabled
    engine_aligned = DeepCarverEngine(config=CarveConfig(sector_aligned_only=True, sector_size=512))
    artifacts_aligned = engine_aligned.carve_artifacts(disk_image)
    assert len(artifacts_aligned) == 0
    
    # Without alignment filter
    engine_unaligned = DeepCarverEngine(config=CarveConfig(sector_aligned_only=False))
    artifacts_unaligned = engine_unaligned.carve_artifacts(disk_image)
    assert len(artifacts_unaligned) == 1


def test_10_streaming_readonly_source_carving():
    """Verify carving directly from a ReadOnlySource without loading full image into RAM."""
    pdf_data = create_valid_pdf()
    img_data = b"\x00" * 4096 + pdf_data + b"\x00" * 4096
    source = MemorySource(img_data, sector_size=512)
    
    engine = DeepCarverEngine(config=CarveConfig(window_size=2048, overlap_size=512, enabled_formats=["PDF"]))
    artifacts = engine.carve_artifacts(source)
    
    assert len(artifacts) == 1
    assert artifacts[0].file_type == "PDF"
    assert artifacts[0].extents[0].start_offset == 4096
    assert artifacts[0].total_size == len(pdf_data)
