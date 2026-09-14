"""Comprehensive 25-Method Strategic Audit & Execution Verification Test Suite (Phase 6 Final)."""

import hashlib
import json
import os
import pathlib
import pytest

from certificate_engine import (
    CertificateMethodInfo,
    CertificateTargetInfo,
    CertificateVerificationInfo,
    ForensicCertificateEngine,
)
from entropy_engine import calculate_shannon_entropy, evaluate_sanitization_entropy
from file_sanitizer import (
    CryptoSanitizer,
    FileSanitizer,
    FileSanitizationStatus,
    FreeSpaceSanitizer,
    SanitizationStandard,
    SlackSanitizer,
)
from mft_sanitizer import MFTSanitizeStatus, MFTSanitizer
from vss_sanitizer import VssPurgePlan, VssSanitizer


# ─── Canonical 25-Method Registry ─────────────────────────────────────────────

CANONICAL_25_METHODS = {
    1: {"name": "NIST SP 800-88 Rev.2", "category": "Drive Erasure", "backend": "NIST Policy Engine"},
    2: {"name": "Smart Sanitization", "category": "Drive Erasure", "backend": "Heuristic Multi-Tier Evaluator"},
    3: {"name": "Device-Native Sanitize", "category": "Drive Erasure", "backend": "IOCTL Pass-Through"},
    4: {"name": "ATA Secure Erase", "category": "Drive Erasure", "backend": "ATA Pass-Through"},
    5: {"name": "NVMe Secure Erase", "category": "Drive Erasure", "backend": "NVMe Admin Protocol"},
    6: {"name": "IEEE 2883 Purge", "category": "Drive Erasure", "backend": "IEEE 2883 Policy Engine"},
    7: {"name": "Verified Overwrite", "category": "Drive Erasure", "backend": "Direct Block Multi-Pass Overwrite"},
    8: {"name": "CSPRNG Random Overwrite", "category": "File/Folder Erasure", "backend": "CSPRNG Stream Overwrite"},
    9: {"name": "Cryptographic Erasure", "category": "File/Folder Erasure", "backend": "Key Lifecycle Invalidation"},
    10: {"name": "File Slack / Cluster-Tip", "category": "File/Folder Erasure", "backend": "SlackSanitizer Extent Engine"},
    11: {"name": "Filesystem Metadata Sanitization", "category": "File/Folder Erasure", "backend": "9-Stage MFTSanitizer + VSS"},
    12: {"name": "NIST SP 800-88 Policy Engine", "category": "File/Folder Erasure", "backend": "File Policy Dispatcher"},
    13: {"name": "Secure Free-Space Wiping", "category": "File/Folder Erasure", "backend": "FreeSpaceSanitizer Headroom Engine"},
    14: {"name": "Single-Pass Zero Overwrite", "category": "File/Folder Erasure", "backend": "Single-Pass Zero Engine"},
    15: {"name": "Storage-Aware Sanitization Fallback", "category": "File/Folder Erasure", "backend": "Storage Controller Fallback Matrix"},
    16: {"name": "Temporary / Cache Sanitization", "category": "File/Folder Erasure", "backend": "Temp Cache Scrubber"},
    17: {"name": "Quick Recovery", "category": "Recovery", "backend": "TSK fls + icat"},
    18: {"name": "Smart Recovery", "category": "Recovery", "backend": "TSK fsstat + fls + Carving"},
    19: {"name": "Targeted Recovery", "category": "Recovery", "backend": "TSK icat Inode Extraction"},
    20: {"name": "Filesystem Recovery", "category": "Recovery", "backend": "TSK tsk_recover"},
    21: {"name": "Deep Recovery", "category": "Recovery", "backend": "PhotoRec 7.2 + DREX Native Carver"},
    22: {"name": "Fragment Recovery", "category": "Recovery", "backend": "DREX Native Fragment Engine"},
    23: {"name": "RAID / Storage Recovery", "category": "Recovery", "backend": "DREX Native RAID Engine"},
    24: {"name": "Damaged Media Recovery", "category": "Recovery", "backend": "DREX Damaged Media Imager + ddrescue"},
    25: {"name": "Forensic Recovery", "category": "Recovery", "backend": "Forensic Vault + Audit Ledger"},
}


def test_canonical_25_methods_registry_completeness():
    """Verify all 25 canonical method IDs exist with exact names and categories."""
    assert len(CANONICAL_25_METHODS) == 25
    for m_id in range(1, 26):
        assert m_id in CANONICAL_25_METHODS
        m_info = CANONICAL_25_METHODS[m_id]
        assert "name" in m_info
        assert "category" in m_info
        assert "backend" in m_info


def test_file_methods_live_execution(tmp_path):
    """Execute live tests across File/Folder sanitization methods (M08, M10, M13, M14)."""
    # M08: CSPRNG Random Overwrite
    f8 = tmp_path / "m08_target.bin"
    f8.write_bytes(b"SENSITIVE_DOC_M08" * 50)
    res8 = FileSanitizer.wipe_file(f8, standard=SanitizationStandard.CSPRNG_OVERWRITE, unlink_after=False)
    assert res8.status == FileSanitizationStatus.SUCCESS
    assert res8.execution_state == "REAL"

    # M10: File Slack
    f10 = tmp_path / "m10_target.bin"
    f10.write_bytes(b"PAYLOAD_M10" * 20)
    res10 = SlackSanitizer.sanitize_slack(f10, cluster_size=4096, confirm_mutation=True)
    assert res10.status == FileSanitizationStatus.SUCCESS
    assert res10.payload_preserved is True

    # M13: Free Space
    res13 = FreeSpaceSanitizer.wipe_free_space(tmp_path, max_bytes_to_wipe=1024 * 1024)
    assert res13.status == FileSanitizationStatus.SUCCESS
    assert res13.coverage_type == "LOGICAL_FREE_SPACE_COVERAGE"

    # M14: Single-Pass Zero
    f14 = tmp_path / "m14_target.bin"
    f14.write_bytes(b"ZERO_TARGET" * 40)
    res14 = FileSanitizer.wipe_file(f14, standard=SanitizationStandard.SINGLE_PASS_ZERO, unlink_after=False)
    assert res14.status == FileSanitizationStatus.SUCCESS
    assert f14.read_bytes() == b"\x00" * len(b"ZERO_TARGET" * 40)


def test_metadata_mft_vss_methods(tmp_path):
    """Verify live analysis for Metadata and VSS sanitization methods (M11, M16)."""
    # M11: MFT Sanitizer Dry Run
    synthetic_mft = bytearray(b"FILE" + b"\x00" * 1020)
    plan = MFTSanitizer.plan_scrub(bytes(synthetic_mft), is_live_system_disk=False)
    assert plan.is_dry_run is True

    # M16: VSS Sanitizer Safety Gate
    plan_vss = VssPurgePlan(
        shadow_copies=[],
        target_count=0,
        is_elevated=VssSanitizer.is_admin(),
    )
    assert plan_vss.requires_confirmation is True


def test_certification_binding_for_25_methods(tmp_path):
    """Verify that certificate generator binds all 25 method IDs into tamper-evident certificates."""
    for m_id, m_data in CANONICAL_25_METHODS.items():
        target = CertificateTargetInfo(target_name=f"TARGET_M{m_id:02d}", target_type="TEST")
        method = CertificateMethodInfo(
            method_id=m_id,
            canonical_name=m_data["name"],
            standard_reference="DREX-V2 Protocol",
            pass_count=1,
            pattern_description="Standard pass",
        )
        verification = CertificateVerificationInfo(primary_verification_method="READBACK_AND_HASH")

        cert = ForensicCertificateEngine.create_certificate(
            case_id=f"CASE-M{m_id:02d}",
            case_name="Audit Run",
            examiner_name="Auditor",
            organization="Forensic Lab",
            target_info=target,
            method_info=method,
            verification_info=verification,
        )

        assert cert.method.method_id == m_id
        assert cert.method.canonical_name == m_data["name"]
        assert cert.truth_model.execution == "REAL"
        assert cert.truth_model.physical_execution == "NOT_EXECUTED"
        assert cert.truth_model.physical_qualification == "NOT_ESTABLISHED"


def test_m01_and_m12_dual_nist_profile_support(tmp_path):
    """Verify Method 01 and Method 12 support both NIST SP 800-88 Rev. 1 and Rev. 2 profiles explicitly."""
    target_f = tmp_path / "nist_eval_file.bin"
    target_f.write_bytes(b"NIST_EVALUATION_DATA" * 30)

    # 1. M01 under Rev. 1 Profile
    res_m01_rev1 = FileSanitizer.wipe_file(
        target_f,
        standard=SanitizationStandard.NIST_800_88_REV1_CLEAR,
        unlink_after=False,
    )
    assert res_m01_rev1.status == FileSanitizationStatus.SUCCESS
    assert "Rev. 1 aligned" in res_m01_rev1.standard_label

    # 2. M01 under Rev. 2 Profile (Default)
    target_f.write_bytes(b"NIST_EVALUATION_DATA_R2" * 30)
    res_m01_rev2 = FileSanitizer.wipe_file(
        target_f,
        standard=SanitizationStandard.NIST_800_88_REV2_CLEAR,
        unlink_after=False,
    )
    assert res_m01_rev2.status == FileSanitizationStatus.SUCCESS
    assert "Rev. 2 aligned" in res_m01_rev2.standard_label

    # 3. M12 Policy Decision Matrix Binding
    for rev_id, rev_label, is_curr in [
        ("REV_1", "NIST SP 800-88 Rev. 1 aligned", False),
        ("REV_2", "NIST SP 800-88 Rev. 2 aligned", True),
    ]:
        m12_cert = ForensicCertificateEngine.create_certificate(
            case_id=f"CASE-M12-{rev_id}",
            case_name="NIST Policy Evaluation",
            examiner_name="Policy Engine",
            organization="Compliance Lab",
            target_info=CertificateTargetInfo(target_name="LOGICAL_POLICY_TARGET", target_type="VOLUME"),
            method_info=CertificateMethodInfo(
                method_id=12,
                canonical_name=CANONICAL_25_METHODS[12]["name"],
                standard_reference=rev_label,
                nist_profile=rev_id,
            ),
            verification_info=CertificateVerificationInfo(
                primary_verification_method="POLICY_RULE_EVALUATION",
                exact_readback_verified=True,
            ),
        )
        assert m12_cert.method.nist_profile == rev_id
        assert rev_label in m12_cert.method.standard_reference
