"""DREX-V2 Format Validators Package & Global Registry

Provides registry dispatch and capability discovery for all supported forensic formats.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Tuple, Type

from validators.base import (
    BaseFormatValidator,
    CandidateState,
    EvidenceScores,
    FormatCapability,
    MemberStatus,
    SupportLevel,
    ValidationResult,
)
from validators.bmp import BmpValidator
from validators.elf import ElfValidator
from validators.gif import GifValidator
from validators.jpeg import JpegValidator
from validators.mp3 import Mp3Validator
from validators.mp4 import Mp4Validator
from validators.ooxml import OoxmlValidator
from validators.pdf import PdfValidator
from validators.pe import PeValidator
from validators.png import PngValidator
from validators.rar import RarValidator
from validators.riff import RiffValidator
from validators.sevenzip import SevenZipValidator
from validators.sqlite import SqliteValidator
from validators.tiff import TiffValidator
from validators.zip import ZipValidator


class FormatRegistry:
    """Global registry mapping forensic format identifiers and signatures to validators."""

    _VALIDATORS: Dict[str, Type[BaseFormatValidator]] = {
        "JPEG": JpegValidator,
        "PNG": PngValidator,
        "PDF": PdfValidator,
        "ZIP": ZipValidator,
        "OOXML": OoxmlValidator,
        "MP4": Mp4Validator,
        "RIFF": RiffValidator,
        "MP3": Mp3Validator,
        "SQLITE": SqliteValidator,
        "ELF": ElfValidator,
        "PE": PeValidator,
        "TIFF": TiffValidator,
        "BMP": BmpValidator,
        "GIF": GifValidator,
        "RAR": RarValidator,
        "SEVENZIP": SevenZipValidator,
    }

    @classmethod
    def list_capabilities(cls) -> List[FormatCapability]:
        """Return list of all registered format capabilities."""
        return [v.get_capability() for v in cls._VALIDATORS.values()]

    @classmethod
    def get_validator(cls, format_id: str) -> Optional[Type[BaseFormatValidator]]:
        """Get validator class for a given format ID."""
        return cls._VALIDATORS.get(format_id.upper())

    @classmethod
    def get_all_signatures(cls) -> List[Tuple[str, bytes]]:
        """Return list of (format_id, signature_bytes) for all registered validators."""
        sigs: List[Tuple[str, bytes]] = []
        for fid, val_cls in cls._VALIDATORS.items():
            cap = val_cls.get_capability()
            for s in cap.signatures:
                sigs.append((fid, s))
        return sigs

    @classmethod
    def validate_buffer(cls, format_id: str, data: bytes) -> ValidationResult:
        """Validate buffer using registered validator for the format."""
        val_cls = cls.get_validator(format_id)
        if val_cls is None:
            return ValidationResult(
                is_valid=False,
                length=0,
                state=CandidateState.UNSUPPORTED,
                evidence=EvidenceScores(),
                limitations=[f"No registered validator for format: {format_id}"],
            )
        return val_cls.validate(data)


__all__ = [
    "BaseFormatValidator",
    "CandidateState",
    "EvidenceScores",
    "FormatCapability",
    "MemberStatus",
    "SupportLevel",
    "ValidationResult",
    "FormatRegistry",
    "JpegValidator",
    "PngValidator",
    "PdfValidator",
    "ZipValidator",
    "OoxmlValidator",
    "Mp4Validator",
    "RiffValidator",
    "Mp3Validator",
    "SqliteValidator",
    "ElfValidator",
    "PeValidator",
    "TiffValidator",
    "BmpValidator",
    "GifValidator",
    "RarValidator",
    "SevenZipValidator",
]
