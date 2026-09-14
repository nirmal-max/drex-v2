"""DREX-V2 Modular Format Validation Base Architecture

Provides base dataclasses, capability definitions, and abstract validator interface
for structure-aware forensic carving and fragment reconstruction.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple


class CandidateState(Enum):
    """Forensic candidate state lifecycle."""
    DISCOVERED = "DISCOVERED"
    CANDIDATE = "CANDIDATE"
    GROUPED = "GROUPED"
    ORDER_HYPOTHESIS = "ORDER_HYPOTHESIS"
    RECONSTRUCTING = "RECONSTRUCTING"
    STRUCTURALLY_VALID = "STRUCTURALLY_VALID"
    CONTENT_VALIDATED = "CONTENT_VALIDATED"
    RECOVERED_ARTIFACT = "RECOVERED_ARTIFACT"
    REJECTED = "REJECTED"
    REJECTED_FALSE_POSITIVE = "REJECTED_FALSE_POSITIVE"
    CORRUPTED_INCOMPLETE = "CORRUPTED_INCOMPLETE"
    AMBIGUOUS_RECONSTRUCTION = "AMBIGUOUS_RECONSTRUCTION"
    UNSUPPORTED = "UNSUPPORTED"
    RESOURCE_LIMITED = "RESOURCE_LIMITED"


class RecoveryOutcome(str, Enum):
    """Explicit corruption and recovery outcome classification."""
    RECOVERED = "RECOVERED"
    RECOVERED_WITH_GAP = "RECOVERED_WITH_GAP"
    STRUCTURALLY_VALID_ONLY = "STRUCTURALLY_VALID_ONLY"
    PARTIAL_RECOVERY = "PARTIAL_RECOVERY"
    CANDIDATE_ONLY = "CANDIDATE_ONLY"
    REJECTED = "REJECTED"


class SupportLevel(Enum):
    """Format support classification based on verified capability."""
    SUPPORTED = "SUPPORTED"
    PARTIALLY_SUPPORTED = "PARTIALLY_SUPPORTED"
    STRUCTURAL_ONLY = "STRUCTURAL_ONLY"
    UNSUPPORTED = "UNSUPPORTED"


class MemberStatus(Enum):
    """Granular archive member status for compound containers."""
    MEMBER_RECOVERED = "MEMBER_RECOVERED"
    MEMBER_CORRUPTED = "MEMBER_CORRUPTED"
    MEMBER_INCOMPLETE = "MEMBER_INCOMPLETE"


@dataclass
class AuditableEvidenceScore:
    """Auditable multi-dimensional evidence confidence score with raw facts.
    
    Represents EVIDENCE CONFIDENCE (0.0 to 100.0), NOT percentage of file recovered.
    Explicitly records both score breakdown and underlying raw verified facts.
    """
    confidence_score: float = 0.0
    scoring_breakdown: Dict[str, float] = field(default_factory=dict)
    raw_evidence_facts: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "confidence_score": round(self.confidence_score, 2),
            "scoring_breakdown": self.scoring_breakdown,
            "raw_evidence_facts": self.raw_evidence_facts,
        }


@dataclass
class EvidenceScores:
    """Multi-dimensional explainable evidence scores.
    
    Each dimension is normalized to [0.0, 1.0].
    Note: Heuristic score is recorded for analytical ranking only and
    NEVER independently promotes a candidate to RECOVERED_ARTIFACT.
    """
    sig_match: float = 0.0        # Magic byte header and footer verification
    structure: float = 0.0        # Internal chunk / table / container validity
    continuity: float = 0.0       # Entropy continuity and seam integrity
    metadata: float = 0.0         # Header / dimension / timestamp metadata consistency
    size_bounded: float = 0.0     # Size within realistic format limits

    def composite_score(self) -> float:
        """Calculate analytical evidence confidence score."""
        score = (
            0.30 * self.sig_match
            + 0.30 * self.structure
            + 0.20 * self.continuity
            + 0.10 * self.metadata
            + 0.10 * self.size_bounded
        )
        return round(min(1.0, max(0.0, score)), 4)


@dataclass
class ValidationResult:
    """Result of format-specific structural and content validation."""
    is_valid: bool
    length: int
    state: CandidateState
    evidence: EvidenceScores
    metadata: Dict[str, Any] = field(default_factory=dict)
    limitations: List[str] = field(default_factory=list)
    member_statuses: Dict[str, MemberStatus] = field(default_factory=dict)


@dataclass
class FormatCapability:
    """Format forensic capability registration."""
    format_id: str
    extensions: List[str]
    signatures: List[bytes]
    support_level: SupportLevel
    structural_validation: bool
    content_validation: bool
    fragmentation_supported: bool
    corruption_detection: bool
    known_answer_verified: bool
    exact_hash_verified: bool
    limitations: List[str] = field(default_factory=list)


class BaseFormatValidator(ABC):
    """Abstract base class for format-specific structural validators."""

    @classmethod
    @abstractmethod
    def get_capability(cls) -> FormatCapability:
        """Return the forensic capability declaration for this format."""
        raise NotImplementedError

    @classmethod
    @abstractmethod
    def validate(cls, data: bytes) -> ValidationResult:
        """Validate buffer and extract length, state, evidence, and metadata."""
        raise NotImplementedError
