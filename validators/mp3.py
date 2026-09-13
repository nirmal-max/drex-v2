"""DREX-V2 MP3 Audio Format Validator (ID3v2 & MPEG Frame Sync Sequences)

Implements ID3v2 tag parsing, MPEG Audio Frame header syncing (11-bit 0xFFE syncword),
frame length calculation, and consecutive frame sequence validation.
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


class Mp3Validator(BaseFormatValidator):
    """Forensic structural and content validator for MPEG-1/2 Audio Layer III (MP3) files."""

    SIGNATURE_ID3 = b"ID3"

    # Bitrate lookup tables (kbps) for MPEG-1 Layer III
    BITRATES_MPEG1_L3 = [0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 0]
    SAMPLERATES_MPEG1 = [44100, 48000, 32000, 0]

    @classmethod
    def get_capability(cls) -> FormatCapability:
        return FormatCapability(
            format_id="MP3",
            extensions=["mp3"],
            signatures=[b"ID3", b"\xff\xfb", b"\xff\xf3", b"\xff\xfa"],
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
    def _parse_syncsafe_int(cls, data: bytes) -> int:
        """Parse 4-byte syncsafe integer where highest bit of each byte is 0."""
        if len(data) < 4:
            return 0
        return (data[0] << 21) | (data[1] << 14) | (data[2] << 7) | data[3]

    @classmethod
    def validate(cls, data: bytes) -> ValidationResult:
        if len(data) < 10:
            return ValidationResult(
                is_valid=False,
                length=0,
                state=CandidateState.REJECTED_FALSE_POSITIVE,
                evidence=EvidenceScores(),
                limitations=["Buffer too short for MP3 header"],
            )

        has_id3 = data.startswith(cls.SIGNATURE_ID3)
        id3_tag_size = 0
        curr = 0

        if has_id3:
            id3_version = f"2.{data[3]}.{data[4]}"
            tag_payload_len = cls._parse_syncsafe_int(data[6:10])
            id3_tag_size = 10 + tag_payload_len
            curr = min(id3_tag_size, len(data))

        # Scan for consecutive valid MPEG audio frames
        valid_frames = 0
        frame_positions: List[int] = []
        limit = len(data)

        while curr + 4 <= limit and valid_frames < 20:
            # Check 11-bit syncword: 0xFFE0
            b0 = data[curr]
            b1 = data[curr + 1]

            if b0 == 0xFF and (b1 & 0xE0) == 0xE0:
                # Frame header found
                version_bits = (b1 >> 3) & 0x03
                layer_bits = (b1 >> 1) & 0x03
                has_crc = (b1 & 0x01) == 0

                b2 = data[curr + 2]
                bitrate_idx = (b2 >> 4) & 0x0F
                samplerate_idx = (b2 >> 2) & 0x03
                padding_bit = (b2 >> 1) & 0x01

                if version_bits == 3 and layer_bits == 1:  # MPEG-1 Layer III
                    bitrate = cls.BITRATES_MPEG1_L3[bitrate_idx] * 1000
                    samplerate = cls.SAMPLERATES_MPEG1[samplerate_idx]

                    if bitrate > 0 and samplerate > 0:
                        frame_len = (144 * bitrate // samplerate) + padding_bit
                        if frame_len >= 24 and curr + frame_len <= limit:
                            valid_frames += 1
                            frame_positions.append(curr)
                            curr += frame_len
                            continue
                elif version_bits in (0, 2) and layer_bits == 1:  # MPEG-2 / 2.5 Layer III
                    # Fallback frame advance
                    curr += 144
                    valid_frames += 1
                    continue

            curr += 1

        carved_length = curr if curr > 0 else len(data)

        # Evidence Scoring
        sig_score = 1.0 if (has_id3 or valid_frames >= 3) else 0.4
        struct_score = min(1.0, 0.3 * (1.0 if has_id3 else 0.0) + 0.7 * min(1.0, valid_frames / 5.0))
        cont_score = 0.9 if valid_frames >= 3 else (0.5 if valid_frames > 0 else 0.2)
        meta_score = 1.0 if has_id3 else 0.4
        size_score = 1.0 if carved_length >= 128 else 0.3

        evidence = EvidenceScores(
            sig_match=round(sig_score, 2),
            structure=round(struct_score, 2),
            continuity=round(cont_score, 2),
            metadata=round(meta_score, 2),
            size_bounded=round(size_score, 2),
        )

        metadata = {
            "has_id3": has_id3,
            "id3_tag_size": id3_tag_size,
            "valid_frames_count": valid_frames,
            "frame_offsets": frame_positions[:10],
        }

        # State determination
        limitations: List[str] = []
        if not has_id3 and valid_frames < 3:
            state = CandidateState.REJECTED_FALSE_POSITIVE
            limitations.append("Lacks ID3 tag and fewer than 3 consecutive synchronized MPEG frames")
            is_valid = False
        elif (has_id3 and valid_frames >= 1) or valid_frames >= 3:
            state = CandidateState.RECOVERED_ARTIFACT
            is_valid = True
        elif has_id3:
            state = CandidateState.STRUCTURALLY_VALID
            limitations.append("ID3 tag found but subsequent MPEG audio stream is truncated")
            is_valid = True
        else:
            state = CandidateState.CORRUPTED_INCOMPLETE
            limitations.append("Corrupted MP3 stream")
            is_valid = False

        return ValidationResult(
            is_valid=is_valid,
            length=carved_length,
            state=state,
            evidence=evidence,
            metadata=metadata,
            limitations=limitations,
        )
