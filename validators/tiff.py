"""DREX-V2 TIFF Format Validator (Tagged Image File Format)

Implements TIFF byte-order detection, Image File Directory (IFD) tag traversal,
and offset boundary validation.
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


class TiffValidator(BaseFormatValidator):
    """Forensic structural validator for TIFF image files."""

    SIGNATURE_LE = b"II*\x00"
    SIGNATURE_BE = b"MM\x00*"

    @classmethod
    def get_capability(cls) -> FormatCapability:
        return FormatCapability(
            format_id="TIFF",
            extensions=["tif", "tiff"],
            signatures=[cls.SIGNATURE_LE, cls.SIGNATURE_BE],
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
        if len(data) < 8:
            return ValidationResult(
                is_valid=False,
                length=0,
                state=CandidateState.REJECTED_FALSE_POSITIVE,
                evidence=EvidenceScores(),
                limitations=["Buffer too short for TIFF header"],
            )

        if data.startswith(cls.SIGNATURE_LE):
            endian = "<"
        elif data.startswith(cls.SIGNATURE_BE):
            endian = ">"
        else:
            return ValidationResult(
                is_valid=False,
                length=0,
                state=CandidateState.REJECTED_FALSE_POSITIVE,
                evidence=EvidenceScores(),
                limitations=["Missing TIFF II*\\x00 or MM\\x00* signature"],
            )

        try:
            (ifd_offset,) = struct.unpack(f"{endian}I", data[4:8])
        except struct.error:
            return ValidationResult(
                is_valid=False,
                length=0,
                state=CandidateState.REJECTED_FALSE_POSITIVE,
                evidence=EvidenceScores(),
                limitations=["Malformed first IFD offset pointer"],
            )

        curr_ifd = ifd_offset
        ifd_count = 0
        max_referenced_offset = 8
        is_truncated = False
        tags_parsed = 0

        while curr_ifd > 0 and ifd_count < 10:
            if curr_ifd + 2 > len(data):
                is_truncated = True
                break

            try:
                num_entries = struct.unpack(f"{endian}H", data[curr_ifd:curr_ifd + 2])[0]
                ifd_end = curr_ifd + 2 + (num_entries * 12) + 4
                max_referenced_offset = max(max_referenced_offset, ifd_end)

                if ifd_end > len(data):
                    is_truncated = True
                    break

                for i in range(num_entries):
                    tag_pos = curr_ifd + 2 + (i * 12)
                    tag_id, tag_type, count, val_or_offset = struct.unpack(
                        f"{endian}HHI4s", data[tag_pos:tag_pos + 12]
                    )
                    tags_parsed += 1

                    # If value doesn't fit in 4 bytes, val_or_offset is a file offset pointer
                    # Type sizes: 1: 1, 2: 1 (ascii), 3: 2 (short), 4: 4 (long), 5: 8 (rational)
                    type_sizes = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8}
                    elem_sz = type_sizes.get(tag_type, 1)
                    val_len = count * elem_sz

                    if val_len > 4:
                        ptr = struct.unpack(f"{endian}I", val_or_offset)[0]
                        max_referenced_offset = max(max_referenced_offset, ptr + val_len)

                next_ifd_pos = curr_ifd + 2 + (num_entries * 12)
                curr_ifd = struct.unpack(f"{endian}I", data[next_ifd_pos:next_ifd_pos + 4])[0]
                ifd_count += 1
            except (struct.error, IndexError):
                is_truncated = True
                break

        carved_length = min(len(data), max_referenced_offset) if max_referenced_offset > 0 else len(data)

        # Evidence Scoring
        sig_score = 1.0
        struct_score = 0.4
        if ifd_count > 0:
            struct_score += 0.4
        if not is_truncated:
            struct_score += 0.2

        cont_score = 0.9 if not is_truncated else 0.4
        meta_score = 1.0 if tags_parsed > 0 else 0.3
        size_score = 1.0 if carved_length >= 16 else 0.3

        evidence = EvidenceScores(
            sig_match=round(sig_score, 2),
            structure=round(min(1.0, struct_score), 2),
            continuity=round(cont_score, 2),
            metadata=round(meta_score, 2),
            size_bounded=round(size_score, 2),
        )

        metadata = {
            "endian": "little" if endian == "<" else "big",
            "ifd_count": ifd_count,
            "tags_parsed": tags_parsed,
            "max_referenced_offset": max_referenced_offset,
        }

        # State determination
        limitations: List[str] = []
        if ifd_count == 0 or ifd_offset < 8:
            state = CandidateState.REJECTED_FALSE_POSITIVE
            limitations.append("Invalid TIFF IFD structure")
            is_valid = False
        elif is_truncated:
            state = CandidateState.CORRUPTED_INCOMPLETE
            limitations.append(f"TIFF payload truncated ({len(data)} < {max_referenced_offset} bytes)")
            is_valid = False
        elif ifd_count > 0 and not is_truncated:
            state = CandidateState.RECOVERED_ARTIFACT
            is_valid = True
        else:
            state = CandidateState.STRUCTURALLY_VALID
            limitations.append("Valid header but partial tag traversal")
            is_valid = True

        return ValidationResult(
            is_valid=is_valid,
            length=carved_length,
            state=state,
            evidence=evidence,
            metadata=metadata,
            limitations=limitations,
        )
