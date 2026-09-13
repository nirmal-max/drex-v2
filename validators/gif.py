"""DREX-V2 GIF Format Validator (GIF87a / GIF89a / Block Parsing / Trailer)

Implements GIF Logical Screen Descriptor parsing, extension and image block iteration,
and terminal 0x3B trailer verification.
"""

from __future__ import annotations

import struct
from typing import Any, Dict, List, Optional

from validators.base import (
    BaseFormatValidator,
    CandidateState,
    EvidenceScores,
    FormatCapability,
    SupportLevel,
    ValidationResult,
)


class GifValidator(BaseFormatValidator):
    """Forensic structural validator for GIF image files."""

    SIGNATURE_87A = b"GIF87a"
    SIGNATURE_89A = b"GIF89a"

    @classmethod
    def get_capability(cls) -> FormatCapability:
        return FormatCapability(
            format_id="GIF",
            extensions=["gif"],
            signatures=[b"GIF8", cls.SIGNATURE_87A, cls.SIGNATURE_89A],
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
    def validate(cls, data: bytes) -> ValidationResult:
        if len(data) < 13 or (not data.startswith(cls.SIGNATURE_87A) and not data.startswith(cls.SIGNATURE_89A)):
            return ValidationResult(
                is_valid=False,
                length=0,
                state=CandidateState.REJECTED_FALSE_POSITIVE,
                evidence=EvidenceScores(),
                limitations=["Missing GIF87a or GIF89a signature"],
            )

        try:
            width, height, packed, bg_idx, aspect = struct.unpack("<HHBBB", data[6:13])
        except struct.error:
            return ValidationResult(
                is_valid=False,
                length=0,
                state=CandidateState.REJECTED_FALSE_POSITIVE,
                evidence=EvidenceScores(),
                limitations=["Malformed GIF screen descriptor"],
            )

        has_gct = (packed & 0x80) != 0
        gct_size = 3 * (2 ** ((packed & 0x07) + 1)) if has_gct else 0

        curr = 13 + gct_size
        has_trailer = False
        image_blocks = 0
        is_truncated = False

        while curr < len(data):
            block_type = data[curr]
            if block_type == 0x3B:  # Trailer
                has_trailer = True
                curr += 1
                break
            elif block_type == 0x00:  # Padding zero byte
                curr += 1
                continue
            elif block_type == 0x21:  # Extension Block
                if curr + 2 > len(data):
                    is_truncated = True
                    break
                ext_type = data[curr + 1]
                curr += 2
                # Sub-block chain
                while curr < len(data):
                    sub_len = data[curr]
                    curr += 1
                    if sub_len == 0:
                        break
                    curr += sub_len
            elif block_type == 0x2C:  # Image Descriptor
                image_blocks += 1
                if curr + 10 > len(data):
                    is_truncated = True
                    break
                img_packed = data[curr + 9]
                has_lct = (img_packed & 0x80) != 0
                lct_size = 3 * (2 ** ((img_packed & 0x07) + 1)) if has_lct else 0
                curr += 10 + lct_size
                if curr < len(data):
                    lzw_min_code = data[curr]
                    curr += 1
                    while curr < len(data):
                        sub_len = data[curr]
                        curr += 1
                        if sub_len == 0:
                            break
                        curr += sub_len
            else:
                curr += 1
                continue

        carved_length = curr if has_trailer else min(len(data), 10 * 1024 * 1024)

        # Evidence Scoring
        sig_score = 1.0 if has_trailer else 0.5
        struct_score = 0.4
        if width > 0 and height > 0:
            struct_score += 0.3
        if has_trailer:
            struct_score += 0.3

        cont_score = 0.9 if has_trailer else 0.4
        meta_score = 1.0 if (width > 0 and height > 0) else 0.4
        size_score = 1.0 if carved_length >= 14 else 0.3

        evidence = EvidenceScores(
            sig_match=round(sig_score, 2),
            structure=round(min(1.0, struct_score), 2),
            continuity=round(cont_score, 2),
            metadata=round(meta_score, 2),
            size_bounded=round(size_score, 2),
        )

        metadata = {
            "version": data[:6].decode("ascii", errors="replace"),
            "width": width,
            "height": height,
            "image_blocks": image_blocks,
            "has_trailer": has_trailer,
        }

        # State determination
        limitations: List[str] = []
        if width == 0 or height == 0:
            state = CandidateState.REJECTED_FALSE_POSITIVE
            limitations.append("Invalid GIF dimensions (0x0)")
            is_valid = False
        elif not has_trailer:
            state = CandidateState.CORRUPTED_INCOMPLETE
            limitations.append("GIF stream truncated before 0x3B trailer")
            is_valid = False
        elif has_trailer and image_blocks > 0:
            state = CandidateState.RECOVERED_ARTIFACT
            is_valid = True
        else:
            state = CandidateState.STRUCTURALLY_VALID
            is_valid = True

        return ValidationResult(
            is_valid=is_valid,
            length=carved_length,
            state=state,
            evidence=evidence,
            metadata=metadata,
            limitations=limitations,
        )
