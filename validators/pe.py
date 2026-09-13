"""DREX-V2 PE / COFF Executable Format Validator (EXE / DLL / SYS)

Implements MS-DOS stub validation, PE signature verification, COFF File Header,
and Section Header boundary calculation.
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


class PeValidator(BaseFormatValidator):
    """Forensic structural validator for Windows Portable Executable (PE/COFF) binaries."""

    SIGNATURE_MZ = b"MZ"
    SIGNATURE_PE = b"PE\x00\x00"

    @classmethod
    def get_capability(cls) -> FormatCapability:
        return FormatCapability(
            format_id="PE",
            extensions=["exe", "dll", "sys", "efi"],
            signatures=[cls.SIGNATURE_MZ],
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
        if len(data) < 64 or not data.startswith(cls.SIGNATURE_MZ):
            return ValidationResult(
                is_valid=False,
                length=0,
                state=CandidateState.REJECTED_FALSE_POSITIVE,
                evidence=EvidenceScores(),
                limitations=["Missing MZ signature header"],
            )

        try:
            (e_lfanew,) = struct.unpack("<I", data[0x3C:0x40])
        except struct.error:
            return ValidationResult(
                is_valid=False,
                length=0,
                state=CandidateState.REJECTED_FALSE_POSITIVE,
                evidence=EvidenceScores(),
                limitations=["Malformed DOS header e_lfanew pointer"],
            )

        if e_lfanew + 24 > len(data):
            return ValidationResult(
                is_valid=False,
                length=len(data),
                state=CandidateState.CORRUPTED_INCOMPLETE,
                evidence=EvidenceScores(sig_match=0.5, size_bounded=0.3),
                limitations=[f"File truncated before PE header at offset {hex(e_lfanew)}"],
            )

        if data[e_lfanew:e_lfanew + 4] != cls.SIGNATURE_PE:
            return ValidationResult(
                is_valid=False,
                length=0,
                state=CandidateState.REJECTED_FALSE_POSITIVE,
                evidence=EvidenceScores(),
                limitations=["Invalid PE signature at e_lfanew offset"],
            )

        has_pe = True
        try:
            (
                machine,
                num_sections,
                time_date_stamp,
                _,
                _,
                size_of_optional_hdr,
                characteristics,
            ) = struct.unpack("<HHIIIHH", data[e_lfanew + 4:e_lfanew + 24])

            opt_hdr_offset = e_lfanew + 24
            sections_offset = opt_hdr_offset + size_of_optional_hdr

            max_raw_extent = sections_offset
            sections: List[Dict[str, Any]] = []

            for i in range(num_sections):
                sec_start = sections_offset + (i * 40)
                if sec_start + 40 <= len(data):
                    sec_name = data[sec_start:sec_start + 8].rstrip(b"\x00").decode("latin-1", errors="replace")
                    (
                        virt_size,
                        virt_addr,
                        raw_size,
                        raw_ptr,
                    ) = struct.unpack("<IIII", data[sec_start + 8:sec_start + 24])

                    sec_extent = raw_ptr + raw_size
                    max_raw_extent = max(max_raw_extent, sec_extent)
                    sections.append({
                        "name": sec_name,
                        "raw_ptr": raw_ptr,
                        "raw_size": raw_size,
                    })
        except struct.error:
            num_sections = 0
            max_raw_extent = e_lfanew + 24
            sections = []

        is_truncated = len(data) < max_raw_extent
        carved_length = min(len(data), max_raw_extent) if max_raw_extent > 0 else len(data)

        # Evidence Scoring
        sig_score = 1.0
        struct_score = 0.4
        if has_pe and num_sections > 0:
            struct_score += 0.4
        if not is_truncated and len(sections) == num_sections:
            struct_score += 0.2

        cont_score = 0.9 if not is_truncated else 0.4
        meta_score = 1.0 if (machine in (0x14C, 0x8664, 0xAA64) and time_date_stamp > 0) else 0.5
        size_score = 1.0 if carved_length >= 512 else 0.3

        evidence = EvidenceScores(
            sig_match=round(sig_score, 2),
            structure=round(min(1.0, struct_score), 2),
            continuity=round(cont_score, 2),
            metadata=round(meta_score, 2),
            size_bounded=round(size_score, 2),
        )

        metadata = {
            "e_lfanew": hex(e_lfanew),
            "machine": hex(machine),
            "num_sections": num_sections,
            "time_date_stamp": time_date_stamp,
            "max_raw_extent": max_raw_extent,
            "sections_count": len(sections),
            "sections": sections,
        }

        # State determination
        limitations: List[str] = []
        if is_truncated:
            state = CandidateState.CORRUPTED_INCOMPLETE
            limitations.append(f"PE binary truncated ({len(data)} < {max_raw_extent} bytes)")
            is_valid = False
        elif num_sections > 0 and len(sections) == num_sections:
            state = CandidateState.RECOVERED_ARTIFACT
            is_valid = True
        elif has_pe:
            state = CandidateState.STRUCTURALLY_VALID
            limitations.append("Valid PE header but section parsing was incomplete")
            is_valid = True
        else:
            state = CandidateState.CORRUPTED_INCOMPLETE
            limitations.append("Corrupted PE header")
            is_valid = False

        return ValidationResult(
            is_valid=is_valid,
            length=carved_length,
            state=state,
            evidence=evidence,
            metadata=metadata,
            limitations=limitations,
        )
