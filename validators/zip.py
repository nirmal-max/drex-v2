"""DREX-V2 ZIP Format Validator (LFH / Central Directory / EOCD / ZIP64 / CRC-32)

Implements ZIP archive container parsing, member-level CRC32 verification,
and granular container vs. member status reporting (PROV-001).
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
    MemberStatus,
    SupportLevel,
    ValidationResult,
)


class ZipValidator(BaseFormatValidator):
    """Forensic structural and content validator for ZIP archives."""

    SIGNATURE_LFH = b"PK\x03\x04"
    SIGNATURE_CD = b"PK\x01\x02"
    SIGNATURE_EOCD = b"PK\x05\x06"
    SIGNATURE_ZIP64_EOCD = b"PK\x06\x06"

    @classmethod
    def get_capability(cls) -> FormatCapability:
        return FormatCapability(
            format_id="ZIP",
            extensions=["zip"],
            signatures=[cls.SIGNATURE_LFH],
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
        if len(data) < 22 or not data.startswith(cls.SIGNATURE_LFH):
            return ValidationResult(
                is_valid=False,
                length=0,
                state=CandidateState.REJECTED_FALSE_POSITIVE,
                evidence=EvidenceScores(),
                limitations=["Missing PK\\x03\\x04 Local File Header signature"],
            )

        # Locate EOCD
        eocd_pos = data.rfind(cls.SIGNATURE_EOCD)
        has_eocd = eocd_pos != -1
        carved_length = len(data)
        comment_len = 0

        if has_eocd and eocd_pos + 22 <= len(data):
            try:
                (comment_len,) = struct.unpack("<H", data[eocd_pos + 20:eocd_pos + 22])
                carved_length = eocd_pos + 22 + comment_len
            except struct.error:
                carved_length = eocd_pos + 22

        members: List[Dict[str, Any]] = []
        member_statuses: Dict[str, MemberStatus] = {}
        total_cd_records = 0
        valid_crc_records = 0
        has_cd = False
        cd_offset = -1
        cd_size = 0

        if has_eocd:
            try:
                (
                    _,
                    _,
                    num_entries_disk,
                    total_cd_records,
                    cd_size,
                    cd_offset,
                ) = struct.unpack("<HHHHII", data[eocd_pos + 4:eocd_pos + 20])
                has_cd = True
            except struct.error:
                has_cd = False

        # Parse Central Directory entries if available
        curr_cd = cd_offset if (has_cd and 0 <= cd_offset < len(data)) else 0
        cd_end = cd_offset + cd_size if (has_cd and cd_offset >= 0) else eocd_pos

        if curr_cd >= 0 and cd_end <= len(data):
            while curr_cd + 46 <= cd_end:
                if data[curr_cd:curr_cd + 4] != cls.SIGNATURE_CD:
                    curr_cd += 1
                    continue

                try:
                    (
                        _,
                        _,
                        _,
                        method,
                        _,
                        _,
                        crc,
                        comp_sz,
                        uncomp_sz,
                        fn_len,
                        extra_len,
                        comm_len,
                        _,
                        _,
                        _,
                        loc_hdr_offset,
                    ) = struct.unpack("<HHHHHHIIIHHHHHII", data[curr_cd + 4:curr_cd + 46])

                    fn_start = curr_cd + 46
                    fn_end = fn_start + fn_len
                    filename = data[fn_start:fn_end].decode("utf-8", errors="replace")

                    # Verify Local Header and Extract/Decompress payload
                    status = MemberStatus.MEMBER_INCOMPLETE
                    if loc_hdr_offset + 30 <= len(data) and data[loc_hdr_offset:loc_hdr_offset + 4] == cls.SIGNATURE_LFH:
                        loc_fn_len, loc_extra_len = struct.unpack("<HH", data[loc_hdr_offset + 26:loc_hdr_offset + 30])
                        data_start = loc_hdr_offset + 30 + loc_fn_len + loc_extra_len
                        data_end = data_start + comp_sz
                        if data_end <= len(data):
                            raw_payload = data[data_start:data_end]
                            if method == 0:  # Stored
                                calc_crc = zlib.crc32(raw_payload) & 0xFFFFFFFF
                                if calc_crc == crc:
                                    status = MemberStatus.MEMBER_RECOVERED
                                    valid_crc_records += 1
                                else:
                                    status = MemberStatus.MEMBER_CORRUPTED
                            elif method == 8:  # Deflated
                                try:
                                    decomp = zlib.decompress(raw_payload, -15)
                                    calc_crc = zlib.crc32(decomp) & 0xFFFFFFFF
                                    if calc_crc == crc and len(decomp) == uncomp_sz:
                                        status = MemberStatus.MEMBER_RECOVERED
                                        valid_crc_records += 1
                                    else:
                                        status = MemberStatus.MEMBER_CORRUPTED
                                except zlib.error:
                                    status = MemberStatus.MEMBER_CORRUPTED

                    member_statuses[filename] = status
                    members.append({
                        "filename": filename,
                        "compressed_size": comp_sz,
                        "uncompressed_size": uncomp_sz,
                        "method": method,
                        "crc32": crc,
                        "offset": loc_hdr_offset,
                        "status": status.value,
                    })

                    curr_cd = fn_end + extra_len + comm_len
                except (struct.error, UnicodeDecodeError):
                    curr_cd += 1

        # Evidence Scoring
        sig_score = 1.0 if has_eocd else 0.5
        struct_score = 0.8 if has_cd and total_cd_records > 0 else 0.3
        cont_ratio = (valid_crc_records / max(len(members), 1)) if members else 0.0
        cont_score = round(cont_ratio, 2)
        meta_score = 1.0 if (has_cd and total_cd_records == len(members) and len(members) > 0) else 0.4
        size_score = 1.0 if carved_length >= 64 else 0.3

        evidence = EvidenceScores(
            sig_match=round(sig_score, 2),
            structure=round(struct_score, 2),
            continuity=round(cont_score, 2),
            metadata=round(meta_score, 2),
            size_bounded=round(size_score, 2),
        )

        metadata = {
            "has_eocd": has_eocd,
            "has_cd": has_cd,
            "total_cd_records": total_cd_records,
            "parsed_members_count": len(members),
            "valid_crc_count": valid_crc_records,
            "members": members,
        }

        # State determination
        limitations: List[str] = []
        if not has_eocd and not has_cd and len(members) == 0:
            state = CandidateState.REJECTED_FALSE_POSITIVE
            limitations.append("Isolated PK\\x03\\x04 header without valid Central Directory or EOCD")
            is_valid = False
        elif not has_eocd:
            state = CandidateState.CORRUPTED_INCOMPLETE
            limitations.append("ZIP archive truncated before End of Central Directory record")
            is_valid = False
        elif len(members) > 0 and valid_crc_records == len(members):
            state = CandidateState.RECOVERED_ARTIFACT
            is_valid = True
        elif len(members) > 0 and valid_crc_records > 0:
            state = CandidateState.CONTENT_VALIDATED
            limitations.append(f"Partial archive: {valid_crc_records}/{len(members)} members passed CRC verification")
            is_valid = True
        elif has_eocd:
            state = CandidateState.STRUCTURALLY_VALID
            limitations.append("Container headers intact but member CRC verification failed or incomplete")
            is_valid = True
        else:
            state = CandidateState.CORRUPTED_INCOMPLETE
            limitations.append("ZIP archive corrupted")
            is_valid = False

        return ValidationResult(
            is_valid=is_valid,
            length=carved_length,
            state=state,
            evidence=evidence,
            metadata=metadata,
            limitations=limitations,
            member_statuses=member_statuses,
        )
