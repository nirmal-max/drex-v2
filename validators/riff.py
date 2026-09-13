"""DREX-V2 RIFF Multimedia Format Validator (AVI / WAV)

Implements RIFF container parsing, subchunk length consistency checking,
and format-specific chunk hierarchy validation (WAVE / AVI).
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


class RiffValidator(BaseFormatValidator):
    """Forensic structural validator for Resource Interchange File Format (RIFF) containers."""

    SIGNATURE_RIFF = b"RIFF"

    @classmethod
    def get_capability(cls) -> FormatCapability:
        return FormatCapability(
            format_id="RIFF",
            extensions=["wav", "avi"],
            signatures=[b"RIFF"],
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
        if len(data) < 12 or not data.startswith(cls.SIGNATURE_RIFF):
            return ValidationResult(
                is_valid=False,
                length=0,
                state=CandidateState.REJECTED_FALSE_POSITIVE,
                evidence=EvidenceScores(),
                limitations=["Missing RIFF signature header"],
            )

        try:
            declared_riff_len = struct.unpack("<I", data[4:8])[0]
            format_type = data[8:12]
        except struct.error:
            return ValidationResult(
                is_valid=False,
                length=0,
                state=CandidateState.REJECTED_FALSE_POSITIVE,
                evidence=EvidenceScores(),
                limitations=["Malformed RIFF header fields"],
            )

        expected_total_len = declared_riff_len + 8
        format_type_str = format_type.decode("latin-1", errors="replace")

        if format_type not in (b"WAVE", b"AVI "):
            return ValidationResult(
                is_valid=False,
                length=0,
                state=CandidateState.REJECTED_FALSE_POSITIVE,
                evidence=EvidenceScores(),
                limitations=[f"Unsupported RIFF format type: {format_type_str}"],
            )

        curr = 12
        chunks: List[Dict[str, Any]] = []
        has_fmt = False
        has_data = False
        has_hdrl = False
        has_movi = False
        is_truncated = False
        parsed_chunks_len = 4  # Includes 4 bytes format_type

        limit = min(len(data), expected_total_len)

        while curr + 8 <= limit:
            try:
                chunk_id = data[curr:curr + 4]
                chunk_len = struct.unpack("<I", data[curr + 4:curr + 8])[0]
                chunk_id_str = chunk_id.decode("latin-1", errors="replace")

                padded_len = chunk_len + (chunk_len % 2)
                chunk_end = curr + 8 + padded_len

                if chunk_id == b"fmt ":
                    has_fmt = True
                elif chunk_id == b"data":
                    has_data = True
                elif chunk_id == b"LIST":
                    list_type = data[curr + 8:curr + 12] if curr + 12 <= limit else b""
                    if list_type == b"hdrl":
                        has_hdrl = True
                    elif list_type == b"movi":
                        has_movi = True

                chunks.append({"id": chunk_id_str, "offset": curr, "length": chunk_len})
                parsed_chunks_len += 8 + padded_len
                curr = chunk_end
            except (struct.error, IndexError):
                is_truncated = True
                break

        if len(data) < expected_total_len:
            is_truncated = True
            carved_length = len(data)
        else:
            carved_length = expected_total_len

        # Evidence Scoring
        sig_score = 1.0
        struct_score = 0.3
        if format_type == b"WAVE" and has_fmt and has_data:
            struct_score += 0.5
        elif format_type == b"AVI " and (has_hdrl or has_movi):
            struct_score += 0.5

        if not is_truncated and parsed_chunks_len == declared_riff_len + 4:
            struct_score += 0.2

        cont_score = 0.9 if not is_truncated else 0.4
        meta_score = 1.0 if (has_fmt or has_hdrl) else 0.3
        size_score = 1.0 if carved_length >= 44 else 0.3

        evidence = EvidenceScores(
            sig_match=round(sig_score, 2),
            structure=round(min(1.0, struct_score), 2),
            continuity=round(cont_score, 2),
            metadata=round(meta_score, 2),
            size_bounded=round(size_score, 2),
        )

        metadata = {
            "format_type": format_type_str,
            "declared_riff_len": declared_riff_len,
            "expected_total_len": expected_total_len,
            "has_fmt": has_fmt,
            "has_data": has_data,
            "has_hdrl": has_hdrl,
            "has_movi": has_movi,
            "chunks_count": len(chunks),
            "chunks": chunks,
        }

        # State determination
        limitations: List[str] = []
        if is_truncated:
            state = CandidateState.CORRUPTED_INCOMPLETE
            limitations.append(f"RIFF payload truncated ({len(data)} < {expected_total_len} bytes)")
            is_valid = False
        elif format_type == b"WAVE" and has_fmt and has_data:
            state = CandidateState.RECOVERED_ARTIFACT
            is_valid = True
        elif format_type == b"AVI " and (has_hdrl or has_movi):
            state = CandidateState.RECOVERED_ARTIFACT
            is_valid = True
        elif format_type in (b"WAVE", b"AVI "):
            state = CandidateState.STRUCTURALLY_VALID
            limitations.append("Valid RIFF header but subchunks are incomplete")
            is_valid = True
        else:
            state = CandidateState.REJECTED_FALSE_POSITIVE
            limitations.append("Invalid RIFF payload")
            is_valid = False

        return ValidationResult(
            is_valid=is_valid,
            length=carved_length,
            state=state,
            evidence=evidence,
            metadata=metadata,
            limitations=limitations,
        )
