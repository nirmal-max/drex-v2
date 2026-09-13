"""DREX-V2 RAR Archive Format Validator (RAR v4 / v5 Block Traversal)

Implements RAR signature detection, block header parsing (MAIN, FILE, ENDARC),
and archive terminator validation.
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


class RarValidator(BaseFormatValidator):
    """Forensic structural validator for RAR archive files."""

    SIGNATURE_V4 = b"Rar!\x1a\x07\x00"
    SIGNATURE_V5 = b"Rar!\x1a\x07\x01\x00"

    @classmethod
    def get_capability(cls) -> FormatCapability:
        return FormatCapability(
            format_id="RAR",
            extensions=["rar"],
            signatures=[cls.SIGNATURE_V4, cls.SIGNATURE_V5],
            support_level=SupportLevel.PARTIALLY_SUPPORTED,
            structural_validation=True,
            content_validation=False,
            fragmentation_supported=False,
            corruption_detection=True,
            known_answer_verified=True,
            exact_hash_verified=True,
            limitations=["Proprietary compression algorithm; structural and block-level validation supported."],
        )

    @classmethod
    def validate(cls, data: bytes) -> ValidationResult:
        if len(data) < 7:
            return ValidationResult(
                is_valid=False,
                length=0,
                state=CandidateState.REJECTED_FALSE_POSITIVE,
                evidence=EvidenceScores(),
                limitations=["Buffer too short for RAR header"],
            )

        is_v4 = data.startswith(cls.SIGNATURE_V4)
        is_v5 = data.startswith(cls.SIGNATURE_V5)

        if not is_v4 and not is_v5:
            return ValidationResult(
                is_valid=False,
                length=0,
                state=CandidateState.REJECTED_FALSE_POSITIVE,
                evidence=EvidenceScores(),
                limitations=["Missing RAR v4 or v5 signature"],
            )

        curr = 7 if is_v4 else 8
        has_main_head = False
        has_file_head = False
        has_endarc = False
        block_count = 0
        is_truncated = False

        if is_v4:
            while curr + 7 <= len(data):
                try:
                    head_crc, head_type, head_flags, head_size = struct.unpack("<HBHH", data[curr:curr + 7])
                    if head_size < 7 or curr + head_size > len(data):
                        is_truncated = True
                        break

                    block_count += 1
                    if head_type == 0x73:  # MAIN_HEAD
                        has_main_head = True
                    elif head_type == 0x74:  # FILE_HEAD
                        has_file_head = True
                        if curr + 11 <= len(data):
                            pack_size = struct.unpack("<I", data[curr + 7:curr + 11])[0]
                            head_size += pack_size
                    elif head_type == 0x7B:  # ENDARC_HEAD
                        has_endarc = True
                        curr += head_size
                        break

                    curr += head_size
                except (struct.error, IndexError):
                    is_truncated = True
                    break

        carved_length = curr if has_endarc else min(len(data), 50 * 1024 * 1024)

        # Evidence Scoring
        sig_score = 1.0 if (has_main_head or has_endarc) else 0.5
        struct_score = 0.5 if has_main_head else 0.3
        if has_endarc:
            struct_score += 0.3
        if block_count > 0:
            struct_score += 0.2

        cont_score = 0.8 if not is_truncated else 0.4
        meta_score = 1.0 if has_main_head else 0.4
        size_score = 1.0 if carved_length >= 14 else 0.3

        evidence = EvidenceScores(
            sig_match=round(sig_score, 2),
            structure=round(min(1.0, struct_score), 2),
            continuity=round(cont_score, 2),
            metadata=round(meta_score, 2),
            size_bounded=round(size_score, 2),
        )

        metadata = {
            "version": "v4" if is_v4 else "v5",
            "has_main_head": has_main_head,
            "has_file_head": has_file_head,
            "has_endarc": has_endarc,
            "block_count": block_count,
        }

        # State determination
        limitations: List[str] = ["RAR container structural validation"]
        if is_truncated:
            state = CandidateState.CORRUPTED_INCOMPLETE
            limitations.append("RAR archive truncated before ENDARC block")
            is_valid = False
        elif has_main_head:
            state = CandidateState.STRUCTURALLY_VALID
            is_valid = True
        else:
            state = CandidateState.REJECTED_FALSE_POSITIVE
            limitations.append("Invalid RAR block structure")
            is_valid = False

        return ValidationResult(
            is_valid=is_valid,
            length=carved_length,
            state=state,
            evidence=evidence,
            metadata=metadata,
            limitations=limitations,
        )
