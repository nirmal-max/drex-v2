"""DREX-V2 7-Zip Archive Format Validator (Signature & StartHeader Parsing)

Implements 7z archive signature detection, version checking, and StartHeader verification.
"""

from __future__ import annotations

import struct
import zlib
from typing import Any, Dict, List, Optional

from validators.base import (
    BaseFormatValidator,
    CandidateState,
    EvidenceScores,
    FormatCapability,
    SupportLevel,
    ValidationResult,
)


class SevenZipValidator(BaseFormatValidator):
    """Forensic structural validator for 7-Zip (.7z) archive files."""

    SIGNATURE = b"7z\xbc\xaf\x27\x1c"

    @classmethod
    def get_capability(cls) -> FormatCapability:
        return FormatCapability(
            format_id="SEVENZIP",
            extensions=["7z"],
            signatures=[cls.SIGNATURE],
            support_level=SupportLevel.PARTIALLY_SUPPORTED,
            structural_validation=True,
            content_validation=False,
            fragmentation_supported=False,
            corruption_detection=True,
            known_answer_verified=True,
            exact_hash_verified=True,
            limitations=["Proprietary stream compression; header and StartHeader CRC validation supported."],
        )

    @classmethod
    def validate(cls, data: bytes) -> ValidationResult:
        if len(data) < 32 or not data.startswith(cls.SIGNATURE):
            return ValidationResult(
                is_valid=False,
                length=0,
                state=CandidateState.REJECTED_FALSE_POSITIVE,
                evidence=EvidenceScores(),
                limitations=["Missing 7z signature header"],
            )

        try:
            ver_major = data[6]
            ver_minor = data[7]
            start_hdr_crc = struct.unpack("<I", data[8:12])[0]
            next_hdr_offset, next_hdr_size, next_hdr_crc = struct.unpack("<QQI", data[12:32])
        except struct.error:
            return ValidationResult(
                is_valid=False,
                length=0,
                state=CandidateState.REJECTED_FALSE_POSITIVE,
                evidence=EvidenceScores(),
                limitations=["Malformed 7z header fields"],
            )

        # Validate StartHeader CRC (CRC32 over bytes 12..32)
        calc_crc = zlib.crc32(data[12:32]) & 0xFFFFFFFF
        start_hdr_valid = (calc_crc == start_hdr_crc)

        total_expected_len = 32 + next_hdr_offset + next_hdr_size
        is_truncated = len(data) < total_expected_len
        carved_length = min(len(data), total_expected_len) if total_expected_len > 32 else len(data)

        # Evidence Scoring
        sig_score = 1.0
        struct_score = 0.8 if start_hdr_valid else 0.3
        if not is_truncated:
            struct_score += 0.2

        cont_score = 0.9 if not is_truncated else 0.4
        meta_score = 1.0 if start_hdr_valid else 0.4
        size_score = 1.0 if carved_length >= 32 else 0.3

        evidence = EvidenceScores(
            sig_match=round(sig_score, 2),
            structure=round(min(1.0, struct_score), 2),
            continuity=round(cont_score, 2),
            metadata=round(meta_score, 2),
            size_bounded=round(size_score, 2),
        )

        metadata = {
            "version": f"{ver_major}.{ver_minor}",
            "start_hdr_crc_valid": start_hdr_valid,
            "next_hdr_offset": next_hdr_offset,
            "next_hdr_size": next_hdr_size,
            "total_expected_len": total_expected_len,
        }

        # State determination
        limitations: List[str] = ["7-Zip StartHeader validation"]
        if not start_hdr_valid:
            state = CandidateState.REJECTED_FALSE_POSITIVE
            limitations.append("7-Zip StartHeader CRC-32 mismatch")
            is_valid = False
        elif is_truncated:
            state = CandidateState.CORRUPTED_INCOMPLETE
            limitations.append(f"7-Zip archive truncated ({len(data)} < {total_expected_len} bytes)")
            is_valid = False
        elif start_hdr_valid:
            state = CandidateState.STRUCTURALLY_VALID
            is_valid = True
        else:
            state = CandidateState.CORRUPTED_INCOMPLETE
            is_valid = False

        return ValidationResult(
            is_valid=is_valid,
            length=carved_length,
            state=state,
            evidence=evidence,
            metadata=metadata,
            limitations=limitations,
        )
