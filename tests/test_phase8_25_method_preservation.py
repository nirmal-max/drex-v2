"""
DREX-V2 Phase 8 Canonical 25 Methods Preservation Tests
========================================================
Validates that:
1. All canonical 25 methods M01-M25 remain intact with exact IDs and names.
2. Dual NIST SP 800-88 profile support (Rev. 1 Legacy & Rev. 2 Current) is preserved.
3. Truth model physical boundary (physical_execution = NOT_EXECUTED, physical_qualification = NOT_ESTABLISHED) is preserved.
"""

from certificate_engine import (
    CertificateMethodInfo,
    CertificateTargetInfo,
    CertificateVerificationInfo,
    ForensicCertificateEngine,
)
from hardware_storage import (
    CANONICAL_25_METHODS_SPEC,
    DeviceIdentitySnapshot,
    Qualification25MethodEngine,
)


def test_all_25_methods_canonical_mapping_preservation():
    """Verify that all 25 methods have exact canonical IDs and names."""
    expected_methods = {
        1: "NIST SP 800-88 Policy Engine",
        2: "Smart Sanitization",
        3: "Device-Native Sanitize",
        4: "ATA Secure Erase",
        5: "NVMe Secure Erase",
        6: "IEEE 2883 Purge",
        7: "Verified Overwrite",
        8: "CSPRNG Random Overwrite",
        9: "Cryptographic Erasure",
        10: "File Slack / Cluster-Tip",
        11: "Filesystem Metadata Sanitization",
        12: "NIST SP 800-88 File Policy Engine",
        13: "Secure Free-Space Wiping",
        14: "Single-Pass Zero Overwrite",
        15: "Storage-Aware Sanitization Fallback",
        16: "Temporary / Cache Sanitization",
        17: "Quick Recovery",
        18: "Smart Recovery",
        19: "Targeted Recovery",
        20: "Filesystem Recovery",
        21: "Deep Recovery",
        22: "Fragment Recovery",
        23: "RAID / Storage Recovery",
        24: "Damaged Media Recovery",
        25: "Forensic Recovery",
    }

    assert len(CANONICAL_25_METHODS_SPEC) == 25
    for mid, name in expected_methods.items():
        assert mid in CANONICAL_25_METHODS_SPEC
        assert CANONICAL_25_METHODS_SPEC[mid]["name"] == name


def test_dual_nist_profile_certificates_preservation():
    """Verify that both NIST Rev. 1 and Rev. 2 certificates preserve their explicit profile without substitution."""
    target = CertificateTargetInfo("Test Target", "FILE")
    verif = CertificateVerificationInfo("EXACT_BYTE_READBACK", post_wipe_sha256="0" * 64)

    # 1. Rev. 1 Legacy Profile
    method_rev1 = CertificateMethodInfo(
        method_id=1,
        canonical_name="NIST SP 800-88 Policy Engine",
        standard_reference="NIST SP 800-88 Rev. 1 aligned",
        nist_profile="REV_1",
    )
    cert_rev1 = ForensicCertificateEngine.create_certificate(
        case_id="CASE-REV1",
        case_name="Rev1 Case",
        examiner_name="Examiner",
        organization="Org",
        target_info=target,
        method_info=method_rev1,
        verification_info=verif,
    )
    assert cert_rev1.method.nist_profile == "REV_1"
    assert "Rev. 1" in cert_rev1.method.standard_reference

    # 2. Rev. 2 Current Profile
    method_rev2 = CertificateMethodInfo(
        method_id=1,
        canonical_name="NIST SP 800-88 Policy Engine",
        standard_reference="NIST SP 800-88 Rev. 2 aligned",
        nist_profile="REV_2",
    )
    cert_rev2 = ForensicCertificateEngine.create_certificate(
        case_id="CASE-REV2",
        case_name="Rev2 Case",
        examiner_name="Examiner",
        organization="Org",
        target_info=target,
        method_info=method_rev2,
        verification_info=verif,
    )
    assert cert_rev2.method.nist_profile == "REV_2"
    assert "Rev. 2" in cert_rev2.method.standard_reference


def test_truth_model_physical_qualification_boundary():
    """Verify that truth model retains physical_execution = NOT_EXECUTED and physical_qualification = NOT_ESTABLISHED."""
    target = CertificateTargetInfo("Test Target", "FILE")
    method = CertificateMethodInfo(method_id=8, canonical_name="CSPRNG Random Overwrite")
    verif = CertificateVerificationInfo("EXACT_BYTE_READBACK")

    cert = ForensicCertificateEngine.create_certificate(
        case_id="CASE-TM",
        case_name="Truth Model Case",
        examiner_name="Examiner",
        organization="Org",
        target_info=target,
        method_info=method,
        verification_info=verif,
    )

    assert cert.truth_model.physical_execution == "NOT_EXECUTED"
    assert cert.truth_model.physical_qualification == "NOT_ESTABLISHED"
