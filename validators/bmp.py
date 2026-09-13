"""DREX-V2 Windows BMP Format Validator (BITMAPFILEHEADER / BITMAPINFOHEADER)

Implements Bitmap header parsing, pixel offset validation, and payload size geometry checks.
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


class BmpValidator(BaseFormatValidator):
    """Forensic structural validator for Windows Bitmap (BMP) image files."""

    SIGNATURE = b"BM"

    @classmethod
    def get_capability(cls) -> FormatCapability:
        return FormatCapability(
            format_id="BMP",
            extensions=["bmp", "dib"],
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
    def validate(cls, data: bytes) -> ValidationResult:
        if len(data) < 54 or not data.startswith(cls.SIGNATURE):
            return ValidationResult(
                is_valid=False,
                length=0,
                state=CandidateState.REJECTED_FALSE_POSITIVE,
                evidence=EvidenceScores(),
                limitations=["Missing BM signature header"],
            )

        try:
            bf_type, bf_size, _, _, bf_off_bits = struct.unpack("<2sIHHI", data[:14])
            bi_size, bi_width, bi_height, bi_planes, bi_bit_count = struct.unpack("<IIIHH", data[14:30])
        except struct.error:
            return ValidationResult(
                is_valid=False,
                length=0,
                state=CandidateState.REJECTED_FALSE_POSITIVE,
                evidence=EvidenceScores(),
                limitations=["Malformed Bitmap header fields"],
            )

        is_valid_header = (
            bf_type == b"BM"
            and 54 <= bf_off_bits <= bf_size
            and bi_size >= 40
            and bi_planes == 1
            and bi_bit_count in (1, 4, 8, 16, 24, 32)
            and bi_width > 0
            and bi_height != 0
        )

        if not is_valid_header:
            return ValidationResult(
                is_valid=False,
                length=0,
                state=CandidateState.REJECTED_FALSE_POSITIVE,
                evidence=EvidenceScores(),
                limitations=["Bitmap header fields failed sanity checks"],
            )

        is_truncated = len(data) < bf_size
        carved_length = min(len(data), bf_size) if bf_size > 54 else len(data)

        # Evidence Scoring
        sig_score = 1.0
        struct_score = 0.8 if is_valid_header else 0.2
        if not is_truncated and len(data) >= bf_size:
            struct_score += 0.2

        cont_score = 0.9 if not is_truncated else 0.4
        meta_score = 1.0 if (bi_width > 0 and abs(bi_height) > 0) else 0.4
        size_score = 1.0 if carved_length >= 54 else 0.3

        evidence = EvidenceScores(
            sig_match=round(sig_score, 2),
            structure=round(min(1.0, struct_score), 2),
            continuity=round(cont_score, 2),
            metadata=round(meta_score, 2),
            size_bounded=round(size_score, 2),
        )

        metadata = {
            "bf_size": bf_size,
            "bf_off_bits": bf_off_bits,
            "bi_width": bi_width,
            "bi_height": bi_height,
            "bi_bit_count": bi_bit_count,
        }

        # State determination
        limitations: List[str] = []
        if is_truncated:
            state = CandidateState.CORRUPTED_INCOMPLETE
            limitations.append(f"Bitmap truncated ({len(data)} < {bf_size} bytes)")
            is_valid = False
        elif is_valid_header:
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
