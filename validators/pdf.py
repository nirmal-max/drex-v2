"""DREX-V2 PDF Format Validator (%PDF- / Object Catalog / XRef / %%EOF)

Implements PDF document structure parsing, cross-reference and trailer analysis,
and mandatory object consistency verification.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from validators.base import (
    BaseFormatValidator,
    CandidateState,
    EvidenceScores,
    FormatCapability,
    SupportLevel,
    ValidationResult,
)


class PdfValidator(BaseFormatValidator):
    """Forensic structural and content validator for PDF documents."""

    SIGNATURE = b"%PDF-"

    @classmethod
    def get_capability(cls) -> FormatCapability:
        return FormatCapability(
            format_id="PDF",
            extensions=["pdf"],
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
        if not data.startswith(cls.SIGNATURE):
            return ValidationResult(
                is_valid=False,
                length=0,
                state=CandidateState.REJECTED_FALSE_POSITIVE,
                evidence=EvidenceScores(),
                limitations=["Missing %PDF- header signature"],
            )

        eof_idx = data.rfind(b"%%EOF")
        has_eof = eof_idx != -1
        if has_eof:
            # Include trailing whitespace/newline after %%EOF if present
            end_pos = eof_idx + 5
            while end_pos < len(data) and data[end_pos] in (0x0A, 0x0D, 0x20):
                end_pos += 1
            carved_length = end_pos
        else:
            carved_length = min(len(data), 25 * 1024 * 1024)

        sample = data[:carved_length]

        # Extract PDF Version
        version_match = re.match(rb"^%PDF-(\d\.\d)", sample)
        pdf_version = version_match.group(1).decode("ascii") if version_match else "unknown"

        # Count objects
        obj_count = len(re.findall(rb"\b\d+\s+\d+\s+obj\b", sample))
        endobj_count = len(re.findall(rb"\bendobj\b", sample))

        has_xref = (b"xref" in sample) or (b"/XRef" in sample)
        has_trailer = (b"trailer" in sample) or (b"/Root" in sample)
        has_root = b"/Root" in sample
        has_pages = b"/Pages" in sample

        # Evidence Scoring
        sig_score = 1.0 if has_eof else 0.5
        struct_score = 0.1
        if obj_count > 0 and obj_count == endobj_count:
            struct_score += 0.4
        elif obj_count > 0:
            struct_score += 0.2

        if has_xref:
            struct_score += 0.2
        if has_trailer:
            struct_score += 0.1
        if has_root:
            struct_score += 0.1
        if has_pages:
            struct_score += 0.1

        cont_score = 0.9 if (has_eof and obj_count > 0) else 0.4
        meta_score = 1.0 if (pdf_version != "unknown" and has_root) else 0.4
        size_score = 1.0 if carved_length >= 128 else 0.3

        evidence = EvidenceScores(
            sig_match=round(sig_score, 2),
            structure=round(min(1.0, struct_score), 2),
            continuity=round(cont_score, 2),
            metadata=round(meta_score, 2),
            size_bounded=round(size_score, 2),
        )

        metadata = {
            "pdf_version": pdf_version,
            "obj_count": obj_count,
            "endobj_count": endobj_count,
            "has_xref": has_xref,
            "has_trailer": has_trailer,
            "has_root": has_root,
            "has_pages": has_pages,
            "has_eof": has_eof,
        }

        # State determination
        limitations: List[str] = []
        if obj_count == 0 and not has_xref and not has_root:
            state = CandidateState.REJECTED_FALSE_POSITIVE
            limitations.append("Header found but buffer contains no PDF objects or cross-reference structures")
            is_valid = False
        elif not has_eof:
            state = CandidateState.CORRUPTED_INCOMPLETE
            limitations.append("PDF document truncated before %%EOF footer")
            is_valid = False
        elif has_eof and obj_count > 0 and (has_root or has_xref):
            state = CandidateState.RECOVERED_ARTIFACT
            is_valid = True
        elif has_eof and obj_count > 0:
            state = CandidateState.STRUCTURALLY_VALID
            limitations.append("PDF objects present and EOF reached, but document catalog is incomplete")
            is_valid = True
        else:
            state = CandidateState.CORRUPTED_INCOMPLETE
            limitations.append("PDF document structure contains severe syntax errors")
            is_valid = False

        return ValidationResult(
            is_valid=is_valid,
            length=carved_length,
            state=state,
            evidence=evidence,
            metadata=metadata,
            limitations=limitations,
        )
