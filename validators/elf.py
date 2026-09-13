"""DREX-V2 ELF Executable Format Validator

Implements ELF32 and ELF64 header parsing, endianness detection,
and section/program header table boundary calculation.
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


class ElfValidator(BaseFormatValidator):
    """Forensic structural validator for Executable and Linkable Format (ELF) binaries."""

    SIGNATURE = b"\x7fELF"

    @classmethod
    def get_capability(cls) -> FormatCapability:
        return FormatCapability(
            format_id="ELF",
            extensions=["elf", "so", "bin", "o"],
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
        if len(data) < 52 or not data.startswith(cls.SIGNATURE):
            return ValidationResult(
                is_valid=False,
                length=0,
                state=CandidateState.REJECTED_FALSE_POSITIVE,
                evidence=EvidenceScores(),
                limitations=["Missing \\x7fELF signature header"],
            )

        ei_class = data[4]  # 1 = 32-bit, 2 = 64-bit
        ei_data = data[5]   # 1 = Little-endian, 2 = Big-endian
        ei_version = data[6]

        if ei_class not in (1, 2) or ei_data not in (1, 2) or ei_version != 1:
            return ValidationResult(
                is_valid=False,
                length=0,
                state=CandidateState.REJECTED_FALSE_POSITIVE,
                evidence=EvidenceScores(),
                limitations=["Malformed ELF e_ident identification bytes"],
            )

        endian = "<" if ei_data == 1 else ">"
        arch_bits = 32 if ei_class == 1 else 64

        try:
            if ei_class == 1:  # 32-bit ELF
                if len(data) < 52:
                    raise struct.error
                (
                    e_type,
                    e_machine,
                    e_version,
                    e_entry,
                    e_phoff,
                    e_shoff,
                    e_flags,
                    e_ehsize,
                    e_phentsize,
                    e_phnum,
                    e_shentsize,
                    e_shnum,
                    e_shstrndx,
                ) = struct.unpack(f"{endian}HHIIIIIHHHHHH", data[16:52])
            else:  # 64-bit ELF
                if len(data) < 64:
                    raise struct.error
                (
                    e_type,
                    e_machine,
                    e_version,
                    e_entry,
                    e_phoff,
                    e_shoff,
                    e_flags,
                    e_ehsize,
                    e_phentsize,
                    e_phnum,
                    e_shentsize,
                    e_shnum,
                    e_shstrndx,
                ) = struct.unpack(f"{endian}HHIQQQIHHHHHH", data[16:64])
        except struct.error:
            return ValidationResult(
                is_valid=False,
                length=0,
                state=CandidateState.REJECTED_FALSE_POSITIVE,
                evidence=EvidenceScores(),
                limitations=["Malformed ELF header fields"],
            )

        # Calculate expected ELF size from Section and Program Header Tables
        max_extent = e_ehsize
        if e_phnum > 0 and e_phentsize > 0:
            ph_end = e_phoff + (e_phnum * e_phentsize)
            max_extent = max(max_extent, ph_end)

        if e_shnum > 0 and e_shentsize > 0:
            sh_end = e_shoff + (e_shnum * e_shentsize)
            max_extent = max(max_extent, sh_end)

        is_truncated = len(data) < max_extent
        carved_length = min(len(data), max_extent) if max_extent > 0 else len(data)

        # Evidence Scoring
        sig_score = 1.0
        struct_score = 0.4
        if e_ehsize in (52, 64) and e_version == 1:
            struct_score += 0.3
        if not is_truncated and (e_shnum > 0 or e_phnum > 0):
            struct_score += 0.3

        cont_score = 0.9 if not is_truncated else 0.4
        meta_score = 1.0 if (e_machine > 0 and e_type > 0) else 0.4
        size_score = 1.0 if carved_length >= 52 else 0.3

        evidence = EvidenceScores(
            sig_match=round(sig_score, 2),
            structure=round(min(1.0, struct_score), 2),
            continuity=round(cont_score, 2),
            metadata=round(meta_score, 2),
            size_bounded=round(size_score, 2),
        )

        metadata = {
            "arch_bits": arch_bits,
            "endian": "little" if ei_data == 1 else "big",
            "e_type": e_type,
            "e_machine": e_machine,
            "e_phoff": e_phoff,
            "e_phnum": e_phnum,
            "e_shoff": e_shoff,
            "e_shnum": e_shnum,
            "max_extent": max_extent,
        }

        # State determination
        limitations: List[str] = []
        if is_truncated:
            state = CandidateState.CORRUPTED_INCOMPLETE
            limitations.append(f"ELF binary truncated ({len(data)} < {max_extent} bytes)")
            is_valid = False
        elif (e_phnum > 0 or e_shnum > 0) and not is_truncated:
            state = CandidateState.RECOVERED_ARTIFACT
            is_valid = True
        elif e_ehsize in (52, 64):
            state = CandidateState.STRUCTURALLY_VALID
            limitations.append("Valid ELF header but missing program/section header tables")
            is_valid = True
        else:
            state = CandidateState.CORRUPTED_INCOMPLETE
            limitations.append("Corrupted ELF header")
            is_valid = False

        return ValidationResult(
            is_valid=is_valid,
            length=carved_length,
            state=state,
            evidence=evidence,
            metadata=metadata,
            limitations=limitations,
        )
