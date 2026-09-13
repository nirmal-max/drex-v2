"""DREX-V2 PNG Format Validator (IHDR / Adam7 & Non-Interlaced / IDAT / IEND / CRC32)

Implements chunk sequence validation, 32-bit CRC verification on all chunks,
concatenated IDAT zlib decompression, and scanline/pass geometry validation (PROV-002).
"""

from __future__ import annotations

import math
import struct
import zlib
from typing import Any, Dict, List, Optional, Tuple

from validators.base import (
    BaseFormatValidator,
    CandidateState,
    EvidenceScores,
    FormatCapability,
    SupportLevel,
    ValidationResult,
)


class PngValidator(BaseFormatValidator):
    """Forensic structural and content validator for PNG images."""

    SIGNATURE = b"\x89PNG\r\n\x1a\n"

    @classmethod
    def get_capability(cls) -> FormatCapability:
        return FormatCapability(
            format_id="PNG",
            extensions=["png"],
            signatures=[cls.SIGNATURE],
            support_level=SupportLevel.SUPPORTED,
            structural_validation=True,
            content_validation=True,
            fragmentation_supported=True,
            corruption_detection=True,
            known_answer_verified=True,
            exact_hash_verified=True,
            limitations=[],
        )

    @classmethod
    def _calculate_adam7_expected_bytes(
        cls, width: int, height: int, channels: int, bit_depth: int
    ) -> int:
        """Calculate expected raw decompressed bytes across all 7 Adam7 interlaced passes."""
        # Adam7 pass grid parameters: (x_orig, y_orig, x_step, y_step)
        passes = [
            (0, 0, 8, 8),
            (4, 0, 8, 8),
            (0, 4, 4, 8),
            (2, 0, 4, 4),
            (0, 2, 2, 4),
            (1, 0, 2, 2),
            (0, 1, 1, 2),
        ]
        total_expected = 0
        for x_orig, y_orig, x_step, y_step in passes:
            pass_w = 0 if width <= x_orig else (width - x_orig + x_step - 1) // x_step
            pass_h = 0 if height <= y_orig else (height - y_orig + y_step - 1) // y_step
            if pass_w > 0 and pass_h > 0:
                row_bytes = math.ceil((pass_w * channels * bit_depth) / 8)
                total_expected += pass_h * (1 + row_bytes)
        return total_expected

    @classmethod
    def validate(cls, data: bytes) -> ValidationResult:
        if len(data) < 8 or not data.startswith(cls.SIGNATURE):
            return ValidationResult(
                is_valid=False,
                length=0,
                state=CandidateState.REJECTED_FALSE_POSITIVE,
                evidence=EvidenceScores(),
                limitations=["Invalid or missing PNG signature"],
            )

        curr = 8
        valid_chunks = 0
        total_chunks = 0
        has_ihdr = False
        has_idat = False
        has_iend = False
        width, height = 0, 0
        bit_depth, color_type = 8, 2
        compression_method = 0
        filter_method = 0
        interlace_method = 0
        idat_chunks: List[bytes] = []
        crc_errors = 0
        is_truncated = False
        chunk_types_seen: List[str] = []

        while curr + 12 <= len(data):
            try:
                chunk_len = struct.unpack(">I", data[curr:curr + 4])[0]
                chunk_type = data[curr + 4:curr + 8]
                chunk_type_str = chunk_type.decode("latin-1", errors="replace")
                chunk_types_seen.append(chunk_type_str)
                total_chunks += 1

                chunk_data_start = curr + 8
                chunk_data_end = chunk_data_start + chunk_len
                crc_offset = chunk_data_end

                if crc_offset + 4 > len(data):
                    is_truncated = True
                    break

                # CRC-32 Verification
                stored_crc = struct.unpack(">I", data[crc_offset:crc_offset + 4])[0]
                calc_crc = zlib.crc32(data[curr + 4:crc_offset]) & 0xFFFFFFFF
                if calc_crc == stored_crc:
                    valid_chunks += 1
                else:
                    crc_errors += 1

                if chunk_type == b"IHDR":
                    if chunk_len >= 13 and not has_ihdr:
                        has_ihdr = True
                        (
                            width,
                            height,
                            bit_depth,
                            color_type,
                            compression_method,
                            filter_method,
                            interlace_method,
                        ) = struct.unpack(">IIBBBBB", data[chunk_data_start:chunk_data_start + 13])
                elif chunk_type == b"IDAT":
                    has_idat = True
                    idat_chunks.append(data[chunk_data_start:chunk_data_end])
                elif chunk_type == b"IEND":
                    has_iend = True
                    curr = crc_offset + 4
                    break

                curr = crc_offset + 4
            except (struct.error, IndexError):
                is_truncated = True
                break

        carved_length = curr

        # Channels per color type:
        # 0: Greyscale (1), 2: RGB (3), 3: Indexed (1), 4: Greyscale+Alpha (2), 6: RGBA (4)
        channels_map = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}
        channels = channels_map.get(color_type, 3)

        # Content Validation via Complete Concatenated IDAT Decompression
        is_idat_decompressed = False
        decompressed_size = 0
        expected_size = 0
        geometry_matched = False

        if has_ihdr and has_idat and width > 0 and height > 0:
            concatenated_idat = b"".join(idat_chunks)
            if interlace_method == 0:
                expected_size = height * (1 + math.ceil((width * channels * bit_depth) / 8))
            elif interlace_method == 1:
                expected_size = cls._calculate_adam7_expected_bytes(width, height, channels, bit_depth)

            try:
                decomp = zlib.decompress(concatenated_idat)
                decompressed_size = len(decomp)
                is_idat_decompressed = True
                if decompressed_size == expected_size:
                    geometry_matched = True
            except zlib.error:
                is_idat_decompressed = False

        # Evidence Scoring
        sig_score = 1.0 if has_iend else 0.5
        struct_ratio = (valid_chunks / max(total_chunks, 1)) if total_chunks else 0.0
        struct_score = 1.0 if (struct_ratio == 1.0 and has_ihdr and has_iend) else round(struct_ratio * 0.8, 2)
        cont_score = 1.0 if geometry_matched else (0.7 if is_idat_decompressed else 0.2)
        meta_score = 1.0 if (width > 0 and height > 0 and color_type in channels_map) else 0.2
        size_score = 1.0 if carved_length >= 64 else 0.3

        evidence = EvidenceScores(
            sig_match=round(sig_score, 2),
            structure=round(struct_score, 2),
            continuity=round(cont_score, 2),
            metadata=round(meta_score, 2),
            size_bounded=round(size_score, 2),
        )

        metadata = {
            "width": width,
            "height": height,
            "bit_depth": bit_depth,
            "color_type": color_type,
            "interlace_method": interlace_method,
            "total_chunks": total_chunks,
            "valid_chunks": valid_chunks,
            "crc_errors": crc_errors,
            "has_ihdr": has_ihdr,
            "has_idat": has_idat,
            "has_iend": has_iend,
            "idat_chunks_count": len(idat_chunks),
            "decompressed_size": decompressed_size,
            "expected_size": expected_size,
            "geometry_matched": geometry_matched,
            "idat_complete": geometry_matched,
            "chunk_types": chunk_types_seen,
        }

        # State determination
        limitations: List[str] = []
        if not has_ihdr:
            state = CandidateState.REJECTED_FALSE_POSITIVE
            limitations.append("Missing IHDR header")
            is_valid = False
        elif is_truncated or not has_iend:
            state = CandidateState.CORRUPTED_INCOMPLETE
            limitations.append("PNG stream truncated before IEND footer")
            is_valid = False
        elif has_ihdr and has_idat and has_iend and geometry_matched and crc_errors == 0:
            state = CandidateState.RECOVERED_ARTIFACT
            is_valid = True
        elif has_ihdr and has_idat and has_iend and is_idat_decompressed and crc_errors == 0:
            state = CandidateState.CONTENT_VALIDATED
            limitations.append("Decompressed IDAT stream size diverged from expected geometry")
            is_valid = True
        elif crc_errors > 0:
            state = CandidateState.CORRUPTED_INCOMPLETE
            limitations.append(f"PNG chunk CRC mismatch ({crc_errors} error(s) detected)")
            is_valid = (valid_chunks >= 1 and has_iend)
        elif has_ihdr and has_iend:
            state = CandidateState.STRUCTURALLY_VALID
            limitations.append("Valid container structure but IDAT stream decompression incomplete")
            is_valid = True
        else:
            state = CandidateState.CORRUPTED_INCOMPLETE
            limitations.append("PNG structure is corrupted or unreadable")
            is_valid = False

        return ValidationResult(
            is_valid=is_valid,
            length=carved_length,
            state=state,
            evidence=evidence,
            metadata=metadata,
            limitations=limitations,
        )
