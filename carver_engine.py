"""DREX-V2 Multi-Format Structure-Aware Carver & Streaming Carving Engine

Provides deep sector carving, streaming windowed scanning over ReadOnlySource handles,
modular format validation, and multi-dimensional evidence scoring.

Supported Formats & Structural Validators:
- JPEG: SOI (FF D8 FF), SOF0/SOF2, SOS, DHT, DQT, DRI, RST0..7, EOI (FF D9)
- PNG: 8-byte signature, IHDR (Adam7 & Non-interlaced), IDAT, IEND with chunk CRC32 verification
- PDF: %PDF- header, trailer/xref/obj parsing, %%EOF footer
- ZIP: PK\x03\x04 local header, Central Directory, PK\x05\x06 EOCD
- OOXML (DOCX/XLSX/PPTX): ZIP container with [Content_Types].xml & relationship validation
- SQLite: "SQLite format 3\x00", page size, change counter, reserved space, Page 1 B-tree
- GIF: GIF87a / GIF89a header, screen descriptor, trailer (0x3B)
- RIFF (WAV/AVI): RIFF header, chunk length consistency, WAVE/AVI signature
- MP3: ID3v2 tags and MPEG sync frame sequences (0xFFE0)
- MP4 / MOV: ISO base media box traversal (ftyp, moov, mdat)
- ELF / PE: Executable header, section table bounds
- TIFF / BMP / RAR / 7Z: Format-specific structural validation

Attribution & Provenance:
- ZIP delta arithmetic adapted from AKHANDA (PROV-001, MIT).
- PNG validation & completeness arithmetic adapted from AKHANDA (PROV-002, MIT).
- JPEG entropy/RST decoding adapted from Resurgence (PROV-003, MIT).
"""

from __future__ import annotations

import hashlib
import math
import struct
import time
import zlib
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from validators import (
    BaseFormatValidator,
    CandidateState,
    EvidenceScores,
    FormatCapability,
    FormatRegistry,
    MemberStatus,
    SupportLevel,
    ValidationResult,
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


# ─── 1. Legacy Candidate & Dataclasses (Preserved for compatibility) ──────────

@dataclass
class CarvedCandidate:
    candidate_id: str
    file_type: str
    offset: int
    length: int
    evidence: EvidenceScores
    confidence: float
    is_valid: bool
    data: bytes = field(repr=False)
    metadata: Dict[str, Any] = field(default_factory=dict)
    state: CandidateState = CandidateState.CANDIDATE
    limitations: List[str] = field(default_factory=list)


@dataclass
class FragmentExtent:
    start_offset: int
    length: int
    sequence_index: int
    entropy: float = 0.0
    sha256_hex: str = ""


@dataclass
class CarvedArtifact:
    """Forensic Carved Artifact with full provenance, multi-source fusion, and state tracking."""
    artifact_id: str
    file_type: str
    state: CandidateState
    extents: List[FragmentExtent]
    total_size: int
    evidence: EvidenceScores
    confidence: float
    sha256: str
    data: bytes = field(repr=False)
    metadata: Dict[str, Any] = field(default_factory=dict)
    limitations: List[str] = field(default_factory=list)
    reconstruction_method: str = "CONTIGUOUS"
    member_statuses: Dict[str, MemberStatus] = field(default_factory=dict)
    confidence_factors: Dict[str, float] = field(default_factory=dict)
    discovery_sources: List[str] = field(default_factory=lambda: ["CARVER"])


# ─── 2. FormatValidator Adapter Class (Preserved for compatibility) ──────────

class FormatValidator:
    """Legacy helper adapter delegating to modular validators."""

    @staticmethod
    def validate_jpeg(data: bytes) -> Tuple[bool, int, EvidenceScores, Dict[str, Any]]:
        res = JpegValidator.validate(data)
        return res.is_valid, res.length, res.evidence, res.metadata

    @staticmethod
    def validate_png(data: bytes) -> Tuple[bool, int, EvidenceScores, Dict[str, Any]]:
        res = PngValidator.validate(data)
        return res.is_valid, res.length, res.evidence, res.metadata

    @staticmethod
    def validate_pdf(data: bytes) -> Tuple[bool, int, EvidenceScores, Dict[str, Any]]:
        res = PdfValidator.validate(data)
        return res.is_valid, res.length, res.evidence, res.metadata

    @staticmethod
    def validate_sqlite(data: bytes) -> Tuple[bool, int, EvidenceScores, Dict[str, Any]]:
        res = SqliteValidator.validate(data)
        return res.is_valid, res.length, res.evidence, res.metadata

    @staticmethod
    def validate_zip(data: bytes) -> Tuple[bool, int, EvidenceScores, Dict[str, Any]]:
        res = ZipValidator.validate(data)
        return res.is_valid, res.length, res.evidence, res.metadata

    @staticmethod
    def validate_ooxml(data: bytes) -> Tuple[bool, int, EvidenceScores, Dict[str, Any]]:
        res = OoxmlValidator.validate(data)
        return res.is_valid, res.length, res.evidence, res.metadata

    @staticmethod
    def validate_mp4(data: bytes) -> Tuple[bool, int, EvidenceScores, Dict[str, Any]]:
        res = Mp4Validator.validate(data)
        return res.is_valid, res.length, res.evidence, res.metadata

    @staticmethod
    def validate_riff(data: bytes) -> Tuple[bool, int, EvidenceScores, Dict[str, Any]]:
        res = RiffValidator.validate(data)
        return res.is_valid, res.length, res.evidence, res.metadata

    @staticmethod
    def validate_mp3(data: bytes) -> Tuple[bool, int, EvidenceScores, Dict[str, Any]]:
        res = Mp3Validator.validate(data)
        return res.is_valid, res.length, res.evidence, res.metadata

    @staticmethod
    def validate_elf(data: bytes) -> Tuple[bool, int, EvidenceScores, Dict[str, Any]]:
        res = ElfValidator.validate(data)
        return res.is_valid, res.length, res.evidence, res.metadata

    @staticmethod
    def validate_pe(data: bytes) -> Tuple[bool, int, EvidenceScores, Dict[str, Any]]:
        res = PeValidator.validate(data)
        return res.is_valid, res.length, res.evidence, res.metadata

    @staticmethod
    def validate_tiff(data: bytes) -> Tuple[bool, int, EvidenceScores, Dict[str, Any]]:
        res = TiffValidator.validate(data)
        return res.is_valid, res.length, res.evidence, res.metadata

    @staticmethod
    def validate_bmp(data: bytes) -> Tuple[bool, int, EvidenceScores, Dict[str, Any]]:
        res = BmpValidator.validate(data)
        return res.is_valid, res.length, res.evidence, res.metadata

    @staticmethod
    def validate_gif(data: bytes) -> Tuple[bool, int, EvidenceScores, Dict[str, Any]]:
        res = GifValidator.validate(data)
        return res.is_valid, res.length, res.evidence, res.metadata


# ─── 3. Carve Configuration & Progress ───────────────────────────────────────

@dataclass
class CarveConfig:
    window_size: int = 1 * 1024 * 1024     # 1 MB streaming window
    overlap_size: int = 64 * 1024          # 64 KB overlap buffer
    sector_size: int = 512                 # 512 or 4096 byte sector alignment
    max_candidates: int = 1000             # Max candidate pool size
    max_file_size: int = 50 * 1024 * 1024  # 50 MB max single file size
    max_scan_bytes: Optional[int] = None   # Max total bytes to scan
    max_duration_seconds: float = 60.0     # Max execution timeout
    enabled_formats: Optional[List[str]] = None
    sector_aligned_only: bool = False      # If True, only search at sector boundaries
    deduplicate_by_hash: bool = False      # If True, merge duplicates with identical SHA-256


@dataclass
class CarveProgress:
    total_bytes: int = 0
    bytes_processed: int = 0
    candidates_discovered: int = 0
    artifacts_recovered: int = 0
    elapsed_seconds: float = 0.0
    throughput_mb_s: float = 0.0
    is_complete: bool = False
    cancelled: bool = False
    resource_limited: bool = False
    limit_reason: Optional[str] = None


# ─── 4. Streaming Carver Engine ──────────────────────────────────────────────

class DeepCarverEngine:
    """Forensic multi-format carver supporting in-memory buffers and streaming sources."""

    def __init__(self, max_candidates: int = 500, config: Optional[CarveConfig] = None):
        self.max_candidates = max_candidates
        self.config = config or CarveConfig(max_candidates=max_candidates)

    def carve_buffer(self, raw_buffer: bytes, max_candidates: Optional[int] = None) -> List[CarvedArtifact]:
        """Carve artifacts directly from an in-memory byte buffer."""
        if max_candidates is not None:
            self.config.max_candidates = max_candidates
        return self.carve_artifacts(raw_buffer)

    def carve(self, raw_buffer: bytes) -> List[CarvedCandidate]:
        """Carve candidates from an in-memory buffer (legacy interface)."""
        artifacts = self.carve_artifacts(raw_buffer)
        candidates: List[CarvedCandidate] = []
        for art in artifacts:
            candidates.append(
                CarvedCandidate(
                    candidate_id=art.artifact_id,
                    file_type=art.file_type.lower(),
                    offset=art.extents[0].start_offset if art.extents else 0,
                    length=art.total_size,
                    evidence=art.evidence,
                    confidence=art.confidence,
                    is_valid=(art.confidence >= 0.50 or art.state in (CandidateState.RECOVERED_ARTIFACT, CandidateState.CONTENT_VALIDATED, CandidateState.STRUCTURALLY_VALID)),
                    data=art.data,
                    metadata=art.metadata,
                    state=art.state,
                    limitations=art.limitations,
                )
            )
        return candidates

    def carve_artifacts(
        self,
        source: Any,
        progress_callback: Optional[Callable[[CarveProgress], None]] = None,
        cancel_check: Optional[Callable[[], bool]] = None,
    ) -> List[CarvedArtifact]:
        """Execute bounded-memory streaming carving across a byte buffer or ReadOnlySource."""
        start_time = time.time()
        artifacts: List[CarvedArtifact] = []
        seen_ranges: Set[Tuple[int, int]] = set()
        seen_hashes: Dict[str, CarvedArtifact] = {}

        # Handle ReadOnlySource or raw bytes
        if isinstance(source, (bytes, bytearray)):
            total_size = len(source)
            def read_fn(offset: int, size: int) -> bytes:
                return bytes(source[offset:offset + size])
        elif hasattr(source, "read") and (hasattr(source, "size") or hasattr(source, "get_size")):
            total_size = source.get_size() if hasattr(source, "get_size") else source.size
            def read_fn(offset: int, size: int) -> bytes:
                return source.read(offset, size)
        else:
            raise TypeError("Source must be bytes, bytearray, or a ReadOnlySource object")

        if total_size == 0:
            return []

        # Enforce max scan bytes bound if configured
        if self.config.max_scan_bytes is not None:
            total_size = min(total_size, self.config.max_scan_bytes)

        window_size = self.config.window_size
        overlap_size = self.config.overlap_size
        step_size = max(1, window_size - overlap_size)

        all_signatures = FormatRegistry.get_all_signatures()
        if self.config.enabled_formats:
            enabled_upper = {f.upper() for f in self.config.enabled_formats}
            all_signatures = [(fid, sig) for fid, sig in all_signatures if fid.upper() in enabled_upper]

        # Sort signatures by length descending to match longest specific signature first
        all_signatures.sort(key=lambda x: len(x[1]), reverse=True)

        current_offset = 0
        progress = CarveProgress(total_bytes=total_size)

        while current_offset < total_size and len(artifacts) < self.config.max_candidates:
            if cancel_check and cancel_check():
                progress.cancelled = True
                break

            # Check duration timeout bound
            if time.time() - start_time > self.config.max_duration_seconds:
                progress.resource_limited = True
                progress.limit_reason = f"Execution duration exceeded limit ({self.config.max_duration_seconds}s)"
                break

            chunk_len = min(window_size, total_size - current_offset)
            chunk_data = read_fn(current_offset, chunk_len)
            if not chunk_data:
                break

            # Scan chunk for all registered signatures
            for format_id, sig in all_signatures:
                pos = 0
                while pos < len(chunk_data) and len(artifacts) < self.config.max_candidates:
                    idx = chunk_data.find(sig, pos)
                    if idx == -1:
                        break

                    global_offset = current_offset + idx

                    # Sector alignment check if requested
                    if self.config.sector_aligned_only and (global_offset % self.config.sector_size != 0):
                        pos = idx + 1
                        continue

                    # Overlapping candidate deduplication check
                    if any(s_start <= global_offset < s_end for s_start, s_end in seen_ranges):
                        pos = idx + len(sig)
                        continue

                    # Fetch candidate data buffer up to max_file_size
                    fetch_size = min(self.config.max_file_size, total_size - global_offset)
                    if idx + fetch_size <= len(chunk_data):
                        cand_buffer = chunk_data[idx:idx + fetch_size]
                    else:
                        cand_buffer = read_fn(global_offset, fetch_size)

                    # Validate candidate buffer
                    val_res = FormatRegistry.validate_buffer(format_id, cand_buffer)
                    if val_res.is_valid and val_res.length > 0:
                        cand_len = min(val_res.length, len(cand_buffer))
                        actual_data = cand_buffer[:cand_len]
                        cand_hash = hashlib.sha256(actual_data).hexdigest()

                        # Check cryptographic duplicate identity if configured
                        if self.config.deduplicate_by_hash and cand_hash in seen_hashes:
                            existing_art = seen_hashes[cand_hash]
                            if "CARVER" not in existing_art.discovery_sources:
                                existing_art.discovery_sources.append("CARVER")
                            pos = idx + max(cand_len, len(sig))
                            continue

                        artifact_id = f"CARVE-{format_id.upper()}-{global_offset:08X}"
                        extent = FragmentExtent(
                            start_offset=global_offset,
                            length=cand_len,
                            sequence_index=0,
                            sha256_hex=cand_hash,
                        )

                        conf_factors = {
                            "header_signature": round(0.30 * val_res.evidence.sig_match, 4),
                            "structural_integrity": round(0.30 * val_res.evidence.structure, 4),
                            "entropy_continuity": round(0.20 * val_res.evidence.continuity, 4),
                            "metadata_consistency": round(0.10 * val_res.evidence.metadata, 4),
                            "size_bounded": round(0.10 * val_res.evidence.size_bounded, 4),
                        }

                        artifact = CarvedArtifact(
                            artifact_id=artifact_id,
                            file_type=format_id.upper(),
                            state=val_res.state,
                            extents=[extent],
                            total_size=cand_len,
                            evidence=val_res.evidence,
                            confidence=val_res.evidence.composite_score(),
                            sha256=cand_hash,
                            data=actual_data,
                            metadata=val_res.metadata,
                            limitations=val_res.limitations,
                            member_statuses=val_res.member_statuses,
                            confidence_factors=conf_factors,
                            discovery_sources=["CARVER"],
                        )

                        artifacts.append(artifact)
                        seen_ranges.add((global_offset, global_offset + cand_len))
                        seen_hashes[cand_hash] = artifact
                        pos = idx + max(cand_len, len(sig))
                    else:
                        pos = idx + len(sig)

            current_offset += step_size
            elapsed = max(0.001, time.time() - start_time)
            progress.bytes_processed = min(total_size, current_offset)
            progress.candidates_discovered = len(artifacts)
            progress.elapsed_seconds = round(elapsed, 3)
            progress.throughput_mb_s = round((progress.bytes_processed / (1024 * 1024)) / elapsed, 2)

            if progress_callback:
                progress_callback(progress)

        progress.is_complete = True
        if progress_callback:
            progress_callback(progress)

        # Sort artifacts by confidence descending
        artifacts.sort(key=lambda a: a.confidence, reverse=True)
        return artifacts


class StreamingCarver(DeepCarverEngine):
    """Alias for DeepCarverEngine providing streaming carver semantics."""
    pass
