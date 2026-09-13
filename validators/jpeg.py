"""DREX-V2 JPEG Format Validator (SOF/SOS/DRI/RST/EOI & Entropy Validation)

Implements deep marker parsing, conditional restart marker verification (PROV-003),
scan byte-stuffing validation, and structural evidence scoring.
"""

from __future__ import annotations

import math
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


class JpegValidator(BaseFormatValidator):
    """Forensic structural and content validator for JPEG / JFIF / EXIF images."""

    MARKER_NAMES = {
        0xD8: "SOI",
        0xD9: "EOI",
        0xDA: "SOS",
        0xDB: "DQT",
        0xDD: "DRI",
        0xC0: "SOF0",
        0xC2: "SOF2",
        0xC4: "DHT",
        0xFE: "COM",
    }

    @classmethod
    def get_capability(cls) -> FormatCapability:
        return FormatCapability(
            format_id="JPEG",
            extensions=["jpg", "jpeg", "jfif"],
            signatures=[b"\xff\xd8\xff"],
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
        if len(data) < 4 or not data.startswith(b"\xff\xd8\xff"):
            return ValidationResult(
                is_valid=False,
                length=0,
                state=CandidateState.REJECTED_FALSE_POSITIVE,
                evidence=EvidenceScores(),
                limitations=["Invalid or missing JPEG SOI marker"],
            )

        length = len(data)
        pos = 2
        has_soi = True
        has_sof = False
        has_sos = False
        has_eoi = False
        has_dri = False
        restart_interval = 0
        rst_markers: List[int] = []
        width, height = 0, 0
        components = 0
        is_truncated = False
        scan_started = False
        rst_seq_valid = True

        try:
            while pos < length:
                if not scan_started:
                    if data[pos] != 0xFF:
                        # Non-marker byte outside scan data -> malformed
                        is_truncated = True
                        break

                    # Skip consecutive fill bytes
                    while pos < length and data[pos] == 0xFF:
                        pos += 1

                    if pos >= length:
                        is_truncated = True
                        break

                    code = data[pos]
                    pos += 1

                    if code == 0xD8:  # Embedded SOI
                        continue
                    elif code == 0xD9:  # EOI
                        has_eoi = True
                        break
                    elif code in (0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7):
                        rst_markers.append(code - 0xD0)
                        continue
                    elif code == 0xDD:  # DRI
                        if pos + 4 <= length:
                            seg_len = struct.unpack(">H", data[pos:pos + 2])[0]
                            if seg_len == 4:
                                restart_interval = struct.unpack(">H", data[pos + 2:pos + 4])[0]
                                has_dri = True
                            pos += seg_len
                            continue
                    elif code in (0xC0, 0xC2):  # SOF0 / SOF2
                        has_sof = True
                        if pos + 8 <= length:
                            seg_len = struct.unpack(">H", data[pos:pos + 2])[0]
                            precision, height, width, components = struct.unpack(">BHHB", data[pos + 2:pos + 8])
                            pos += seg_len
                            continue
                    elif code == 0xDA:  # SOS
                        has_sos = True
                        if pos + 2 <= length:
                            seg_len = struct.unpack(">H", data[pos:pos + 2])[0]
                            pos += seg_len
                            scan_started = True
                            continue

                    # Generic marker with length
                    if pos + 2 <= length:
                        seg_len = struct.unpack(">H", data[pos:pos + 2])[0]
                        if seg_len < 2 or pos + seg_len > length:
                            is_truncated = True
                            break
                        pos += seg_len
                    else:
                        is_truncated = True
                        break
                else:
                    # Scan data parsing (entropy stream with 0xFF00 byte stuffing)
                    if data[pos] != 0xFF:
                        pos += 1
                        continue

                    # Found 0xFF in scan data
                    while pos < length and data[pos] == 0xFF:
                        pos += 1

                    if pos >= length:
                        is_truncated = True
                        break

                    code = data[pos]
                    pos += 1

                    if code == 0x00:
                        # Byte stuffing - valid entropy byte
                        continue
                    elif code == 0xD9:  # EOI
                        has_eoi = True
                        break
                    elif 0xD0 <= code <= 0xD7:  # RSTn
                        rst_idx = code - 0xD0
                        if rst_markers:
                            expected_next = (rst_markers[-1] + 1) % 8
                            if rst_idx != expected_next:
                                rst_seq_valid = False
                        rst_markers.append(rst_idx)
                        continue
                    elif code in (0xC0, 0xC2, 0xC4, 0xDB, 0xDA, 0xDD, 0xE0, 0xE1):
                        # Next frame or metadata marker encountered
                        continue
                    else:
                        # Malformed marker in scan data
                        is_truncated = True
                        break
        except (struct.error, IndexError):
            is_truncated = True

        carved_length = pos if has_eoi else min(len(data), 15 * 1024 * 1024)

        # Entropy calculation on scan payload
        ent = 0.0
        if carved_length > 128:
            sample = data[128:min(carved_length, 4096)]
            freq = {}
            for b in sample:
                freq[b] = freq.get(b, 0) + 1
            for count in freq.values():
                p = count / len(sample)
                ent -= p * math.log2(p)

        # Evidence Scoring
        sig_score = 1.0 if (has_soi and has_eoi) else (0.5 if has_soi else 0.0)
        struct_score = 0.0
        if has_soi:
            struct_score += 0.2
        if has_sof:
            struct_score += 0.3
        if has_sos:
            struct_score += 0.3
        if has_eoi:
            struct_score += 0.2

        if has_dri and not rst_seq_valid:
            struct_score = max(0.0, struct_score - 0.4)

        cont_score = min(1.0, ent / 7.5) if ent > 5.0 else 0.4
        meta_score = 1.0 if (width > 0 and height > 0) else 0.3
        size_score = 1.0 if 512 <= carved_length <= 50 * 1024 * 1024 else 0.5

        evidence = EvidenceScores(
            sig_match=round(sig_score, 2),
            structure=round(struct_score, 2),
            continuity=round(cont_score, 2),
            metadata=round(meta_score, 2),
            size_bounded=round(size_score, 2),
        )

        metadata = {
            "width": width,
            "height": height,
            "components": components,
            "has_soi": has_soi,
            "has_sof": has_sof,
            "has_sos": has_sos,
            "has_eoi": has_eoi,
            "has_dri": has_dri,
            "restart_interval": restart_interval,
            "rst_count": len(rst_markers),
            "rst_seq_valid": rst_seq_valid,
            "entropy": round(ent, 3),
        }

        # Determine Candidate State
        if not has_soi or (not has_sof and not has_sos and not has_eoi):
            state = CandidateState.REJECTED_FALSE_POSITIVE
            limitations = ["Lacks basic JPEG structural markers (SOF/SOS)"]
            is_valid = False
        elif not has_eoi or is_truncated:
            state = CandidateState.CORRUPTED_INCOMPLETE
            limitations = ["JPEG stream is truncated before EOI marker"]
            is_valid = False
        elif has_dri and not rst_seq_valid:
            state = CandidateState.CORRUPTED_INCOMPLETE
            limitations = ["JPEG restart marker sequence is desynchronized"]
            is_valid = False
        elif has_soi and has_sof and has_sos and has_eoi and width > 0 and height > 0:
            state = CandidateState.RECOVERED_ARTIFACT
            limitations = []
            is_valid = True
        else:
            state = CandidateState.STRUCTURALLY_VALID
            limitations = ["Partial structural compliance"]
            is_valid = True

        return ValidationResult(
            is_valid=is_valid,
            length=carved_length,
            state=state,
            evidence=evidence,
            metadata=metadata,
            limitations=limitations,
        )
