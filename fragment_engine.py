"""DREX-V2 Fragment Reconstruction & Stream Carving Engine

Provides specialized algorithmic modules for:
1. FragmentReassembler: Non-contiguous candidate reassembly via boundary seam entropy.
2. JpegEntropyDecoder & JpegRstStreamReassembler: JPEG restart marker and MCU block boundary validation (PROV-003).
3. ZipCarveStream & DeltaClusterReassembler: Streaming ZIP archive reconstruction and Central Directory delta clustering (PROV-001).
4. BoundedPermutationReconstructor: Branch-and-bound permutation hypothesis search with ambiguity containment.

Provenance & Attribution:
- Reassembly & ZIP stream heuristics adapted from AKHANDA (PROV-001, MIT).
- PNG validation adapted from AKHANDA (PROV-002, MIT).
- JPEG entropy decoder structure adapted from Resurgence (PROV-003, MIT).
"""

from __future__ import annotations

import hashlib
import io
import itertools
import math
import struct
import zlib
from dataclasses import dataclass, field
from typing import Any, BinaryIO, Dict, Generator, List, Optional, Set, Tuple

from validators.base import CandidateState, EvidenceScores, MemberStatus


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
    score = max(0.0, 1.0 - (diff / 2.0))
    return score


# ─── 2. Fragment Models ──────────────────────────────────────────────────────

@dataclass
class FragmentChunk:
    chunk_id: int
    offset: int
    data: bytes
    entropy: float = 0.0
    file_type: str = "raw"
    is_header: bool = False
    is_footer: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)

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
    state: CandidateState = CandidateState.CANDIDATE
    limitations: List[str] = field(default_factory=list)
    sha256: str = ""

    def __post_init__(self):
        if not self.sha256 and self.assembled_bytes:
            self.sha256 = hashlib.sha256(self.assembled_bytes).hexdigest()


# ─── 3. Basic Fragment Reassembler (Preserved & Extended) ─────────────────────

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
            ft = file_type.lower()
            if ft in ("jpeg", "jpg"):
                if chunk_bytes.startswith(b"\xff\xd8\xff"):
                    chunk.is_header = True
                if b"\xff\xd9" in chunk_bytes:
                    chunk.is_footer = True
            elif ft == "png":
                if chunk_bytes.startswith(b"\x89PNG\r\n\x1a\n"):
                    chunk.is_header = True
                if b"IEND" in chunk_bytes:
                    chunk.is_footer = True
            elif ft == "pdf":
                if chunk_bytes.startswith(b"%PDF-"):
                    chunk.is_header = True
                if b"%%EOF" in chunk_bytes:
                    chunk.is_footer = True
            elif ft == "zip":
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
            headers = [chunks[0]]

        candidates: List[ReassemblyCandidate] = []

        for h_idx, header in enumerate(headers):
            assembled = [header]
            remaining = [c for c in chunks if c.chunk_id != header.chunk_id]
            seam_scores: List[float] = []
            current_bytes = bytearray(header.data)

            while remaining and len(current_bytes) < self.max_candidate_size:
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

            avg_seam = sum(seam_scores) / max(len(seam_scores), 1) if seam_scores else 0.5
            has_valid_header = assembled[0].is_header
            has_valid_footer = assembled[-1].is_footer if len(assembled) > 1 else False

            confidence = (
                0.30 * (1.0 if has_valid_header else 0.0)
                + 0.30 * (1.0 if has_valid_footer else 0.0)
                + 0.40 * avg_seam
            )
            confidence = round(min(1.0, max(0.0, confidence)), 4)

            state = CandidateState.STRUCTURALLY_VALID if (has_valid_header and has_valid_footer) else CandidateState.CANDIDATE

            candidates.append(
                ReassemblyCandidate(
                    candidate_id=f"REASM-{file_type.upper()}-{h_idx+1:03d}",
                    chunks=assembled,
                    total_size=len(current_bytes),
                    reconstruction_confidence=confidence,
                    is_valid_structure=has_valid_header and (has_valid_footer or len(assembled) > 1),
                    assembled_bytes=bytes(current_bytes),
                    seam_scores=[round(s, 4) for s in seam_scores],
                    state=state,
                )
            )

        return candidates


# ─── 4. JPEG Entropy Decoder & Restart Marker Reassembler ────────────────────

@dataclass
class JpegMarker:
    offset: int
    marker_code: int
    name: str
    length: int = 0
    payload: bytes = b""


class JpegEntropyDecoder:
    """Parses JPEG entropy streams, scan headers (SOS), DRI, and restart markers (PROV-003)."""

    MARKER_NAMES = {
        0xD8: "SOI",
        0xD9: "EOI",
        0xDA: "SOS",
        0xDB: "DQT",
        0xDD: "DRI",
        0xC0: "SOF0",
        0xC2: "SOF2",
        0xC4: "DHT",
        0xE0: "APP0",
        0xE1: "APP1",
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
        self.has_dri = False
        self.restart_interval = 0
        self.restart_count = 0
        self.rst_sequence: List[int] = []
        self.is_truncated = False

    def parse(self) -> bool:
        if len(self.data) < 4 or not self.data.startswith(b"\xff\xd8"):
            return False

        self.has_soi = True
        pos = 2
        length = len(self.data)

        while pos < length:
            if self.data[pos] != 0xFF:
                pos += 1
                continue

            while pos < length and self.data[pos] == 0xFF:
                pos += 1

            if pos >= length:
                self.is_truncated = True
                break

            code = self.data[pos]
            pos += 1

            if code == 0x00:
                # Scan data byte stuffing
                continue

            name = self.MARKER_NAMES.get(code, f"UNKNOWN_0x{code:02X}")

            if code == 0xD9:  # EOI
                self.has_eoi = True
                self.markers.append(JpegMarker(offset=pos - 2, marker_code=code, name=name))
                break

            if 0xD0 <= code <= 0xD7:  # RSTn
                self.restart_count += 1
                self.rst_sequence.append(code - 0xD0)
                self.markers.append(JpegMarker(offset=pos - 2, marker_code=code, name=name))
                continue

            if code == 0xDD:  # DRI
                self.has_dri = True
                if pos + 4 <= length:
                    self.restart_interval = struct.unpack(">H", self.data[pos + 2:pos + 4])[0]

            if code in (0xC0, 0xC2):
                self.has_sof = True
            elif code == 0xDA:
                self.has_sos = True

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
        if not self.has_soi:
            return 0.0
        score = 0.3
        if self.has_sof:
            score += 0.3
        if self.has_sos:
            score += 0.2
        if self.has_eoi:
            score += 0.2
        return round(score, 2)


class JpegRstStreamReassembler:
    """Stitches non-contiguous JPEG fragments utilizing conditional restart markers and entropy seams."""

    @staticmethod
    def reassemble_rst_fragments(fragments: List[bytes]) -> Tuple[bytes, bool, List[int]]:
        """Reorder and concatenate JPEG fragments using restart marker sequence alignment."""
        if not fragments:
            return b"", False, []

        # Parse markers in each fragment
        parsed_frags: List[Tuple[int, bytes, List[int], bool, bool]] = []
        for idx, frag in enumerate(fragments):
            decoder = JpegEntropyDecoder(frag)
            decoder.parse()
            has_soi = frag.startswith(b"\xff\xd8")
            has_eoi = b"\xff\xd9" in frag
            parsed_frags.append((idx, frag, decoder.rst_sequence, has_soi, has_eoi))

        # Find header fragment
        header_candidates = [f for f in parsed_frags if f[3]]
        if not header_candidates:
            # Fallback to first fragment
            header_candidates = [parsed_frags[0]]

        best_order: List[bytes] = [header_candidates[0][1]]
        remaining = [f for f in parsed_frags if f[0] != header_candidates[0][0]]
        expected_rst = (header_candidates[0][2][-1] + 1) % 8 if header_candidates[0][2] else 0

        while remaining:
            matched = False
            for cand in list(remaining):
                if cand[2] and cand[2][0] == expected_rst:
                    best_order.append(cand[1])
                    remaining.remove(cand)
                    expected_rst = (cand[2][-1] + 1) % 8
                    matched = True
                    break

            if not matched:
                # If no RST match, select highest seam continuity
                best_seam = -1.0
                best_cand = None
                for cand in remaining:
                    score = seam_continuity_score(best_order[-1][-256:], cand[1][:256])
                    if score > best_seam:
                        best_seam = score
                        best_cand = cand
                if best_cand:
                    best_order.append(best_cand[1])
                    remaining.remove(best_cand)
                else:
                    break

        assembled = b"".join(best_order)
        final_decoder = JpegEntropyDecoder(assembled)
        is_valid = final_decoder.parse() and final_decoder.has_eoi

        return assembled, is_valid, final_decoder.rst_sequence


# ─── 5. ZIP Delta Cluster Reassembler (PROV-001) ─────────────────────────────

@dataclass
class ZipMember:
    filename: str
    compressed_size: int
    uncompressed_size: int
    compression_method: int
    crc32: int
    header_offset: int
    found_at: Optional[int] = None
    is_valid_crc: bool = False

    @property
    def delta(self) -> Optional[int]:
        """Image/buffer position minus archive-relative offset (PROV-001)."""
        return None if self.found_at is None else self.found_at - self.header_offset


class ZipCarveStream:
    """Parses streaming ZIP central directory headers and validates member archives (PROV-001)."""

    def __init__(self, data: bytes):
        self.data = data
        self.members: List[ZipMember] = []
        self.eocd_found = False
        self.eocd_offset = -1

    def parse(self) -> bool:
        if len(self.data) < 22:
            return False

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

        actual_cd_offset = self.eocd_offset - cd_size
        if 0 <= actual_cd_offset < len(self.data) and self.data[actual_cd_offset:actual_cd_offset + 4] == b"PK\x01\x02":
            curr = actual_cd_offset
            cd_end = self.eocd_offset
        elif 0 <= cd_offset < len(self.data) and self.data[cd_offset:cd_offset + 4] == b"PK\x01\x02":
            curr = cd_offset
            cd_end = cd_offset + cd_size
        else:
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

                actual_found = None
                if local_hdr_offset + 30 <= len(self.data) and self.data[local_hdr_offset:local_hdr_offset + 4] == b"PK\x03\x04":
                    (loc_nlen,) = struct.unpack("<H", self.data[local_hdr_offset + 26:local_hdr_offset + 28])
                    if self.data[local_hdr_offset + 30:local_hdr_offset + 30 + loc_nlen] == filename.encode("utf-8", "replace"):
                        actual_found = local_hdr_offset

                if actual_found is None:
                    search_needle = b"PK\x03\x04"
                    scan_pos = 0
                    while scan_pos < len(self.data):
                        scan_pos = self.data.find(search_needle, scan_pos)
                        if scan_pos == -1 or scan_pos + 30 > len(self.data):
                            break
                        (loc_nlen,) = struct.unpack("<H", self.data[scan_pos + 26:scan_pos + 28])
                        if scan_pos + 30 + loc_nlen <= len(self.data):
                            if self.data[scan_pos + 30:scan_pos + 30 + loc_nlen] == filename.encode("utf-8", "replace"):
                                actual_found = scan_pos
                                break
                        scan_pos += 1

                member = ZipMember(
                    filename=filename,
                    compressed_size=comp_sz,
                    uncompressed_size=uncomp_sz,
                    compression_method=method,
                    crc32=crc,
                    header_offset=local_hdr_offset,
                    found_at=actual_found,
                )

                loc_offset_to_use = actual_found if actual_found is not None else local_hdr_offset
                if loc_offset_to_use + 30 <= len(self.data):
                    if self.data[loc_offset_to_use:loc_offset_to_use + 4] == b"PK\x03\x04":
                        loc_fn_len, loc_extra_len = struct.unpack("<HH", self.data[loc_offset_to_use + 26:loc_offset_to_use + 30])
                        data_start = loc_offset_to_use + 30 + loc_fn_len + loc_extra_len
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

    def get_fragment_deltas(self) -> List[int]:
        deltas = {m.delta for m in self.members if m.delta is not None}
        return sorted(list(deltas))

    def structural_validity_score(self) -> float:
        if not self.eocd_found:
            return 0.0
        if not self.members:
            return 0.4
        valid_crc_count = sum(1 for m in self.members if m.is_valid_crc)
        ratio = valid_crc_count / max(len(self.members), 1)
        return round(0.5 + (0.5 * ratio), 2)


class DeltaClusterReassembler:
    """Clusters and reassembles fragmented ZIP / OOXML streams using relative CD deltas (PROV-001)."""

    @staticmethod
    def cluster_zip_extents(raw_image: bytes) -> List[Tuple[int, int]]:
        """Identify coherent contiguous chunk extents based on matching relative deltas."""
        carver = ZipCarveStream(raw_image)
        if not carver.parse():
            return []

        # Group members by delta
        delta_groups: Dict[int, List[ZipMember]] = {}
        for m in carver.members:
            if m.delta is not None:
                delta_groups.setdefault(m.delta, []).append(m)

        extents: List[Tuple[int, int]] = []
        for delta, members in delta_groups.items():
            min_offset = min(m.found_at for m in members if m.found_at is not None)
            max_offset = max(
                (m.found_at + 30 + len(m.filename) + m.compressed_size)
                for m in members if m.found_at is not None
            )
            extents.append((min_offset, max_offset - min_offset))

        return sorted(extents, key=lambda x: x[0])


# ─── 6. Bounded Permutation Reconstructor & Gap Search ───────────────────────

class BoundedPermutationReconstructor:
    """Branch-and-bound hypothesis search for multi-fragment reconstruction with ambiguity containment."""

    def __init__(self, max_depth: int = 8, max_evaluated_branches: int = 64):
        self.max_depth = max_depth
        self.max_evaluated_branches = max_evaluated_branches

    def reconstruct_with_ambiguity_check(
        self,
        fragments: List[bytes],
        validator_fn: Any,
    ) -> Tuple[bytes, CandidateState, List[str]]:
        """Reconstruct fragments and classify state strictly based on structural evidence."""
        if not fragments:
            return b"", CandidateState.CORRUPTED_INCOMPLETE, ["No fragments provided"]

        if len(fragments) == 1:
            res = validator_fn(fragments[0])
            if res.is_valid and res.state == CandidateState.RECOVERED_ARTIFACT:
                return fragments[0], CandidateState.RECOVERED_ARTIFACT, []
            return fragments[0], res.state, res.limitations

        # Bound combinatorial search
        if len(fragments) > self.max_depth:
            return b"".join(fragments), CandidateState.RESOURCE_LIMITED, [
                f"Fragment count ({len(fragments)}) exceeds branch-and-bound max depth ({self.max_depth})"
            ]

        valid_permutations: List[Tuple[bytes, ValidationResult]] = []
        evaluated = 0

        for perm in itertools.permutations(fragments):
            if evaluated >= self.max_evaluated_branches:
                break
            evaluated += 1

            candidate_payload = b"".join(perm)
            res = validator_fn(candidate_payload)
            if res.is_valid and res.state in (CandidateState.RECOVERED_ARTIFACT, CandidateState.CONTENT_VALIDATED):
                valid_permutations.append((candidate_payload, res))

        if not valid_permutations:
            return b"".join(fragments), CandidateState.CORRUPTED_INCOMPLETE, [
                "No evaluated fragment permutation satisfied format structural validator"
            ]

        if len(valid_permutations) == 1:
            # Unique reconstruction
            payload, res = valid_permutations[0]
            return payload, res.state, res.limitations

        # Multiple valid permutations -> check if byte payloads are identical or ambiguous
        unique_payloads = {p[0] for p in valid_permutations}
        if len(unique_payloads) == 1:
            payload, res = valid_permutations[0]
            return payload, res.state, res.limitations

        # Truly ambiguous reconstruction (multiple competing permutations pass validation)
        # Forensic rule: Never arbitrarily tie-break with heuristic score differences!
        first_payload = valid_permutations[0][0]
        return first_payload, CandidateState.AMBIGUOUS_RECONSTRUCTION, [
            f"Ambiguous reconstruction: {len(unique_payloads)} competing permutations satisfied structural validation"
        ]


class BiFragmentGapSearch:
    """Evaluates forward and backward candidate jumps for bi-fragment sector carving."""

    @staticmethod
    def evaluate_gap(
        head_data: bytes,
        tail_data: bytes,
        validator_fn: Any,
    ) -> Tuple[bool, CandidateState]:
        combined = head_data + tail_data
        res = validator_fn(combined)
        return res.is_valid, res.state
