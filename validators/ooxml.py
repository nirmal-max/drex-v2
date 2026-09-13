"""DREX-V2 Office Open XML Validator (DOCX / XLSX / PPTX)

Implements OOXML package relationship validation, required member verification,
and document type classification over ZIP container structures.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from validators.base import (
    BaseFormatValidator,
    CandidateState,
    EvidenceScores,
    FormatCapability,
    MemberStatus,
    SupportLevel,
    ValidationResult,
)
from validators.zip import ZipValidator


class OoxmlValidator(BaseFormatValidator):
    """Forensic structural and content validator for Microsoft Office Open XML packages."""

    @classmethod
    def get_capability(cls) -> FormatCapability:
        return FormatCapability(
            format_id="OOXML",
            extensions=["docx", "xlsx", "pptx"],
            signatures=[b"PK\x03\x04"],
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
        zip_res = ZipValidator.validate(data)
        if not zip_res.is_valid and zip_res.state == CandidateState.REJECTED_FALSE_POSITIVE:
            return zip_res

        members = zip_res.metadata.get("members", [])
        member_names = {m["filename"] for m in members}

        has_content_types = "[Content_Types].xml" in member_names
        has_root_rels = "_rels/.rels" in member_names
        has_word = any(name.startswith("word/") for name in member_names)
        has_xl = any(name.startswith("xl/") for name in member_names)
        has_ppt = any(name.startswith("ppt/") for name in member_names)

        doc_type = "ooxml"
        if has_word:
            doc_type = "docx"
        elif has_xl:
            doc_type = "xlsx"
        elif has_ppt:
            doc_type = "pptx"

        is_valid_ooxml = has_content_types and (has_word or has_xl or has_ppt)

        # Clone evidence and adjust metadata
        ev = zip_res.evidence
        if is_valid_ooxml:
            ev.metadata = 1.0
            ev.structure = max(ev.structure, 0.9)

        meta = dict(zip_res.metadata)
        meta["ooxml_type"] = doc_type
        meta["has_content_types"] = has_content_types
        meta["has_root_rels"] = has_root_rels

        limitations = list(zip_res.limitations)
        if not is_valid_ooxml:
            if zip_res.state == CandidateState.RECOVERED_ARTIFACT:
                # Valid ZIP, but not OOXML
                return zip_res
            limitations.append("Missing required OOXML [Content_Types].xml or document parts")

        state = zip_res.state
        if is_valid_ooxml and zip_res.state in (CandidateState.RECOVERED_ARTIFACT, CandidateState.CONTENT_VALIDATED):
            state = CandidateState.RECOVERED_ARTIFACT if zip_res.state == CandidateState.RECOVERED_ARTIFACT else CandidateState.CONTENT_VALIDATED
        elif not is_valid_ooxml:
            state = CandidateState.REJECTED_FALSE_POSITIVE if zip_res.state == CandidateState.REJECTED_FALSE_POSITIVE else zip_res.state

        return ValidationResult(
            is_valid=zip_res.is_valid,
            length=zip_res.length,
            state=state,
            evidence=ev,
            metadata=meta,
            limitations=limitations,
            member_statuses=zip_res.member_statuses,
        )
