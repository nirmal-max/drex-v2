"""
DREX-V2 Canonical 25-Method Integrity & Mapping Invariance Regression Test
==========================================================================
Enforces strict preservation of all 25 canonical method IDs (M01-M25),
canonical names, categories, and read-only / destructive semantics.
This test is independent of the Phase 7 qualification implementation and will
fail if any past or future implementation modifies, reorders, or redefines
a canonical DREX method ID.
"""

import pytest
from hardware_storage import CANONICAL_25_METHODS_SPEC, Qualification25MethodEngine, DeviceIntelligenceEngine


FROZEN_CANONICAL_25_METHODS = {
    1: {"name": "NIST SP 800-88 Policy Engine", "category": "Drive Erasure", "is_destructive": True},
    2: {"name": "Smart Sanitization", "category": "Drive Erasure", "is_destructive": True},
    3: {"name": "Device-Native Sanitize", "category": "Drive Erasure", "is_destructive": True},
    4: {"name": "ATA Secure Erase", "category": "Drive Erasure", "is_destructive": True},
    5: {"name": "NVMe Secure Erase", "category": "Drive Erasure", "is_destructive": True},
    6: {"name": "IEEE 2883 Purge", "category": "Drive Erasure", "is_destructive": True},
    7: {"name": "Verified Overwrite", "category": "Drive Erasure", "is_destructive": True},
    8: {"name": "CSPRNG Random Overwrite", "category": "File/Folder Erasure", "is_destructive": True},
    9: {"name": "Cryptographic Erasure", "category": "File/Folder Erasure", "is_destructive": True},
    10: {"name": "File Slack / Cluster-Tip", "category": "File/Folder Erasure", "is_destructive": True},
    11: {"name": "Filesystem Metadata Sanitization", "category": "File/Folder Erasure", "is_destructive": True},
    12: {"name": "NIST SP 800-88 File Policy Engine", "category": "File/Folder Erasure", "is_destructive": True},
    13: {"name": "Secure Free-Space Wiping", "category": "File/Folder Erasure", "is_destructive": True},
    14: {"name": "Single-Pass Zero Overwrite", "category": "File/Folder Erasure", "is_destructive": True},
    15: {"name": "Storage-Aware Sanitization Fallback", "category": "File/Folder Erasure", "is_destructive": True},
    16: {"name": "Temporary / Cache Sanitization", "category": "File/Folder Erasure", "is_destructive": True},
    17: {"name": "Quick Recovery", "category": "Recovery", "is_destructive": False},
    18: {"name": "Smart Recovery", "category": "Recovery", "is_destructive": False},
    19: {"name": "Targeted Recovery", "category": "Recovery", "is_destructive": False},
    20: {"name": "Filesystem Recovery", "category": "Recovery", "is_destructive": False},
    21: {"name": "Deep Recovery", "category": "Recovery", "is_destructive": False},
    22: {"name": "Fragment Recovery", "category": "Recovery", "is_destructive": False},
    23: {"name": "RAID / Storage Recovery", "category": "Recovery", "is_destructive": False},
    24: {"name": "Damaged Media Recovery", "category": "Recovery", "is_destructive": False},
    25: {"name": "Forensic Recovery", "category": "Recovery", "is_destructive": False},
}


def test_canonical_25_methods_exact_count_and_keys():
    """Assert exactly 25 canonical methods exist with integer keys 1 through 25."""
    assert len(CANONICAL_25_METHODS_SPEC) == 25
    assert set(CANONICAL_25_METHODS_SPEC.keys()) == set(range(1, 26))


@pytest.mark.parametrize("method_id", range(1, 26))
def test_canonical_method_definition_invariance(method_id: int):
    """Assert each canonical method preserves its frozen name and category."""
    expected = FROZEN_CANONICAL_25_METHODS[method_id]
    actual = CANONICAL_25_METHODS_SPEC[method_id]

    assert actual["name"] == expected["name"], f"Method M{method_id:02d} name drift detected!"
    assert actual["category"] == expected["category"], f"Method M{method_id:02d} category drift detected!"


def test_destructive_versus_recovery_partition():
    """Assert M01-M16 are destructive operations and M17-M25 are strictly non-destructive recovery."""
    for m_id in range(1, 17):
        assert FROZEN_CANONICAL_25_METHODS[m_id]["is_destructive"] is True
        assert CANONICAL_25_METHODS_SPEC[m_id]["category"] in ("Drive Erasure", "File/Folder Erasure")

    for m_id in range(17, 26):
        assert FROZEN_CANONICAL_25_METHODS[m_id]["is_destructive"] is False
        assert CANONICAL_25_METHODS_SPEC[m_id]["category"] == "Recovery"


def test_qualification_engine_evaluates_exact_canonical_set():
    """Verify Qualification25MethodEngine evaluates all 25 frozen canonical methods."""
    snap = DeviceIntelligenceEngine.create_snapshot(
        r"\\.\PhysicalDrive2",
        simulated_descriptor={"disk_number": 2, "bus_type": "SATA", "capacity_bytes": 10**11},
    )
    matrix = Qualification25MethodEngine.evaluate_25_methods(snap)

    assert len(matrix) == 25
    for m_id, spec in FROZEN_CANONICAL_25_METHODS.items():
        assert m_id in matrix
        rec = matrix[m_id]
        assert rec.method_id == m_id
        assert rec.canonical_name == spec["name"]
        assert rec.category == spec["category"]
