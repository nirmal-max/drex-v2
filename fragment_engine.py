"""DREX-V2 Fragment Reconstruction & Stream Carving Engine

Provides specialized algorithmic modules for:
1. FragmentReassembler: Non-contiguous candidate reassembly via boundary seam entropy.
2. JpegEntropyDecoder: JPEG restart marker and MCU block boundary validation.
3. ZipCarveStream: Streaming ZIP archive reconstruction and Central Directory parsing.

Provenance & Attribution:
- Reassembly & ZIP stream heuristics adapted from AKHANDA (MIT License).
- JPEG entropy decoder structure adapted from Resurgence (MIT License).
"""

from __future__ import annotations

import io
import math
import struct
import zlib
from dataclasses import dataclass, field
from typing import Any, BinaryIO, Generator, List, Optional, Tuple


# ─── 1. Entropy & Seam Scoring ───────────────────────────────────────────────

def shannon_entropy(data: bytes) -> float:
    """Calculate the Shannon entropy of a byte buffer in bits per byte (0.0 to 8.0)."""
    if not data:
        return 0.0
    length = len(data)
    freq: dict[int, int] = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    entropy = 0.0
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def seam_continuity_score(tail: bytes, head: bytes, sample_size: int = 256) -> float:
    """Calculate seam continuity between two chunks based on boundary entropy gradient.
    
    Returns a score between 0.0 (high discontinuity) and 1.0 (smooth continuity).
    """
    if not tail or not head:
        return 0.0
    sample_tail = tail[-sample_size:] if len(tail) > sample_size else tail
    sample_head = head[:sample_size] if len(head) > sample_size else head

    ent_tail = shannon_entropy(sample_tail)
    ent_head = shannon_entropy(sample_head)
    ent_joint = shannon_entropy(sample_tail + sample_head)

    # Gradient difference: seamless continuity means joint entropy is close to average
    avg_ent = (ent_tail + ent_head) / 2.0
    diff = abs(ent_joint - avg_ent)
    # diff is usually between 0.0 and 2.0; normalize into [0.0, 1.0]
    score = max(0.0, 1.0 - (diff / 2.0))
    return score


# ─── 2. Fragment Reassembler ────────────────────────────────────────────────

@dataclass
class FragmentChunk:
    chunk_id: int
    offset: int
    data: bytes
    entropy: float = 0.0
    file_type: str = "raw"
    is_header: bool = False
    is_footer: bool = False

    def __post_init__(self):
        if self.entropy == 0.0 and self.data:
            self.entropy = shannon_entropy(self.data)


@dataclass
class ReassemblyCandidate:
    candidate_id: str
    chunks: List[FragmentChunk]
    total_size: int
    reconstruction_confidence: float
    is_valid_structure: bool
    assembled_bytes: bytes = field(repr=False)
    seam_scores: List[float] = field(default_factory=list)


class FragmentReassembler:
    """Reassembles fragmented, out-of-order sectors into coherent candidate files."""

    def __init__(self, chunk_size: int = 4096, max_candidate_size: int = 10 * 1024 * 1024):
        self.chunk_size = chunk_size
        self.max_candidate_size = max_candidate_size

    def analyze_chunks(self, raw_data: bytes, file_type: str = "jpeg") -> List[FragmentChunk]:
        """Slice raw buffer into indexed FragmentChunk objects."""
        chunks: List[FragmentChunk] = []
        num_chunks = (len(raw_data) + self.chunk_size - 1) // self.chunk_size
        for i in range(num_chunks):
            start = i * self.chunk_size
            end = min(start + self.chunk_size, len(raw_data))
            chunk_bytes = raw_data[start:end]
            chunk = FragmentChunk(
                chunk_id=i,
                offset=start,
                data=chunk_bytes,
                file_type=file_type,
            )
            # Detect header / footer indicators
            if file_type.lower() == "jpeg":
                if chunk_bytes.startswith(b"\xff\xd8\xff"):
                    chunk.is_header = True
                if b"\xff\xd9" in chunk_bytes:
                    chunk.is_footer = True
            elif file_type.lower() == "png":
                if chunk_bytes.startswith(b"\x89PNG\r\n\x1a\n"):
                    chunk.is_header = True
                if b"IEND\xaeB`\x82" in chunk_bytes:
                    chunk.is_footer = True
            elif file_type.lower() == "pdf":
                if chunk_bytes.startswith(b"%PDF-"):
                    chunk.is_header = True
                if b"%%EOF" in chunk_bytes:
                    chunk.is_footer = True
            elif file_type.lower() == "zip":
                if chunk_bytes.startswith(b"PK\x03\x04"):
                    chunk.is_header = True
                if b"PK\x05\x06" in chunk_bytes:
                    chunk.is_footer = True
            chunks.append(chunk)
        return chunks

    def reassemble(
        self,
        chunks: List[FragmentChunk],
        file_type: str = "jpeg",
        max_permutations: int = 100,
    ) -> List[ReassemblyCandidate]:
        """Rank and reassemble chunks into candidates based on seam evidence."""
        if not chunks:
            return []

        headers = [c for c in chunks if c.is_header]
        if not headers:
            # Fallback: Treat first chunk as header if no explicit header signature
            headers = [chunks[0]]

        candidates: List[ReassemblyCandidate] = []

        for h_idx, header in enumerate(headers):
            assembled = [header]
            remaining = [c for c in chunks if c.chunk_id != header.chunk_id]
            seam_scores: List[float] = []
            current_bytes = bytearray(header.data)

            while remaining and len(current_bytes) < self.max_candidate_size:
                # Find the next best chunk matching tail of current_bytes
                best_score = -1.0
                best_chunk = None
                for cand in remaining:
                    score = seam_continuity_score(current_bytes[-256:], cand.data[:256])
                    if score > best_score:
                        best_score = score
                        best_chunk = cand

                if best_chunk is None or best_score < 0.2:
                    break

                assembled.append(best_chunk)
                remaining.remove(best_chunk)
                seam_scores.append(best_score)
                current_bytes.extend(best_chunk.data)

                if best_chunk.is_footer:
                    break

            # Calculate overall reconstruction confidence
            avg_seam = sum(seam_scores) / max(len(seam_scores), 1) if seam_scores else 0.5
            has_valid_header = assembled[0].is_header
            has_valid_footer = assembled[-1].is_footer if len(assembled) > 1 else False

            # Defensible evidence confidence calculation
            confidence = (
                0.30 * (1.0 if has_valid_header else 0.0)
                + 0.30 * (1.0 if has_valid_footer else 0.0)
                + 0.40 * avg_seam
            )
            confidence = round(min(1.0, max(0.0, confidence)), 4)

            candidates.append(
                ReassemblyCandidate(
                    candidate_id=f"REASM-{file_type.upper()}-{h_idx+1:03d}",
                    chunks=assembled,
                    total_size=len(current_bytes),
                    reconstruction_confidence=confidence,
                    is_valid_structure=has_valid_header and (has_valid_footer or len(assembled) > 1),
                    assembled_bytes=bytes(current_bytes),
                    seam_scores=[round(s, 4) for s in seam_scores],
                )
            )

        return candidates


# ─── 3. JPEG Entropy & Restart Marker Decoder ───────────────────────────────

@dataclass
class JpegMarker:
    offset: int
    marker_code: int
    name: str
    length: int = 0
    payload: bytes = b""


class JpegEntropyDecoder:
    """Parses JPEG entropy streams, scan headers (SOS), and restart markers (RST0..RST7)."""

    MARKER_NAMES = {
        0xD8: "SOI",
        0xD9: "EOI",
        0xDA: "SOS",
        0xDB: "DQT",
        0xC0: "SOF0",
        0xC2: "SOF2",
        0xC4: "DHT",
        0xE0: "APP0",
        0xE1: "APP1",
        0xE2: "APP2",
        0xFE: "COM",
        0xD0: "RST0",
        0xD1: "RST1",
        0xD2: "RST2",
        0xD3: "RST3",
        0xD4: "RST4",
        0xD5: "RST5",
        0xD6: "RST6",
        0xD7: "RST7",
    }

    def __init__(self, data: bytes):
        self.data = data
        self.markers: List[JpegMarker] = []
        self.has_soi = False
        self.has_eoi = False
        self.has_sof = False
        self.has_sos = False
        self.restart_count = 0
        self.is_truncated = False

    def parse(self) -> bool:
        """Parse the JPEG stream and validate markers and entropy bounds."""
        if len(self.data) < 4:
            return False

        if not self.data.startswith(b"\xff\xd8"):
            return False

        self.has_soi = True
        pos = 2
        length = len(self.data)

        while pos < length:
            if self.data[pos] != 0xFF:
                # In entropy-coded scan data, 0xFF is byte-stuffed with 0x00
                pos += 1
                continue

            # Skip consecutive 0xFF fill bytes
            while pos < length and self.data[pos] == 0xFF:
                pos += 1

            if pos >= length:
                self.is_truncated = True
                break

            code = self.data[pos]
            pos += 1

            if code == 0x00:
                # Byte stuffing in scan data
                continue

            name = self.MARKER_NAMES.get(code, f"UNKNOWN_0x{code:02X}")

            if code == 0xD9:  # EOI
                self.has_eoi = True
                self.markers.append(JpegMarker(offset=pos - 2, marker_code=code, name=name))
                break

            if 0xD0 <= code <= 0xD7:  # RSTn
                self.restart_count += 1
                self.markers.append(JpegMarker(offset=pos - 2, marker_code=code, name=name))
                continue

            if code in (0xC0, 0xC2):
                self.has_sof = True
            elif code == 0xDA:
                self.has_sos = True

            # Markers with 16-bit length
            if pos + 2 > length:
                self.is_truncated = True
                break

            seg_len = struct.unpack(">H", self.data[pos:pos + 2])[0]
            if seg_len < 2 or pos + seg_len > length:
                self.is_truncated = True
                break

            payload = self.data[pos + 2:pos + seg_len]
            self.markers.append(
                JpegMarker(offset=pos - 2, marker_code=code, name=name, length=seg_len, payload=payload)
            )
            pos += seg_len

        return self.has_soi and (self.has_sof or self.has_sos)

    def structural_validity_score(self) -> float:
        """Returns explainable structural validity score for the JPEG stream."""
        if not self.has_soi:
            return 0.0
        score = 0.3  # SOI present
        if self.has_sof:
            score += 0.3
        if self.has_sos:
            score += 0.2
        if self.has_eoi:
            score += 0.2
        return round(score, 2)


# ─── 4. Streaming ZIP Carver ────────────────────────────────────────────────

@dataclass
class ZipMember:
    filename: str
    compressed_size: int
    uncompressed_size: int
    compression_method: int
    crc32: int
    header_offset: int
    is_valid_crc: bool = False


class ZipCarveStream:
    """Parses streaming ZIP central directory headers and validates member archives."""

    def __init__(self, data: bytes):
        self.data = data
        self.members: List[ZipMember] = []
        self.eocd_found = False
        self.eocd_offset = -1

    def parse(self) -> bool:
        """Locate End of Central Directory (EOCD) and parse central directory records."""
        if len(self.data) < 22:
            return False

        # Search for EOCD record signature: PK\x05\x06 (0x06054b50)
        eocd_sig = b"PK\x05\x06"
        pos = self.data.rfind(eocd_sig)
        if pos == -1:
            return False

        self.eocd_found = True
        self.eocd_offset = pos

        if pos + 22 > len(self.data):
            return False

        try:
            _, _, num_entries_disk, num_entries_total, cd_size, cd_offset = struct.unpack(
                "<HHHHII", self.data[pos + 4:pos + 20]
            )
        except struct.error:
            return False

        # Parse Central Directory records: PK\x01\x02 (0x02014b50)
        curr = cd_offset
        cd_end = cd_offset + cd_size

        if curr < 0 or cd_end > len(self.data):
            # Attempt fallback scanning for PK\x01\x02 if offset was relative
            curr = 0
            cd_end = self.eocd_offset

        while curr + 46 <= min(cd_end, len(self.data)):
            if self.data[curr:curr + 4] != b"PK\x01\x02":
                curr += 1
                continue

            try:
                (
                    _, _, _, method, _, _,
                    crc, comp_sz, uncomp_sz,
                    fn_len, extra_len, comment_len,
                    _, _, _, local_hdr_offset,
                ) = struct.unpack("<HHHHHHIIIHHHHHII", self.data[curr + 4:curr + 46])

                fn_start = curr + 46
                fn_end = fn_start + fn_len
                filename = self.data[fn_start:fn_end].decode("utf-8", errors="replace")

                member = ZipMember(
                    filename=filename,
                    compressed_size=comp_sz,
                    uncompressed_size=uncomp_sz,
                    compression_method=method,
                    crc32=crc,
                    header_offset=local_hdr_offset,
                )

                # Validate local header and CRC if within buffer
                if local_hdr_offset + 30 <= len(self.data):
                    if self.data[local_hdr_offset:local_hdr_offset + 4] == b"PK\x03\x04":
                        loc_fn_len, loc_extra_len = struct.unpack("<HH", self.data[local_hdr_offset + 26:local_hdr_offset + 30])
                        data_start = local_hdr_offset + 30 + loc_fn_len + loc_extra_len
                        data_end = data_start + comp_sz
                        if data_end <= len(self.data):
                            raw_member_data = self.data[data_start:data_end]
                            if method == 0:  # Stored
                                calc_crc = zlib.crc32(raw_member_data) & 0xFFFFFFFF
                                member.is_valid_crc = (calc_crc == crc)
                            elif method == 8:  # Deflated
                                try:
                                    decomp = zlib.decompress(raw_member_data, -15)
                                    calc_crc = zlib.crc32(decomp) & 0xFFFFFFFF
                                    member.is_valid_crc = (calc_crc == crc)
                                except zlib.error:
                                    member.is_valid_crc = False

                self.members.append(member)
                curr = fn_end + extra_len + comment_len
            except (struct.error, UnicodeDecodeError):
                curr += 1

        return len(self.members) > 0

    def structural_validity_score(self) -> float:
        """Calculate structural validity of ZIP container."""
        if not self.eocd_found:
            return 0.0
        if not self.members:
            return 0.4
        valid_crc_count = sum(1 for m in self.members if m.is_valid_crc)
        ratio = valid_crc_count / max(len(self.members), 1)
        return round(0.5 + (0.5 * ratio), 2)
