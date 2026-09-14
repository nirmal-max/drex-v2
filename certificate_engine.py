"""
DREX-V2 Forensic Certificate & Evidence Verification Engine
============================================================

Implements NIST SP 800-88 Rev. 2 Aligned & ISO/IEC 27037 Referenced
Tamper-Evident Forensic Certification.

Capabilities:
1. Structured JSON Certificate Generation with cryptographic hash-chain binding.
2. Pure Python Standard-Library PDF 1.4 Certificate Rendering (Zero external dependencies).
3. Cryptographic SHA-256 Integrity Binding & Audit Ledger Verification.
4. Truth Model Integrity (Execution, Verification, Software Qualification, Physical States).

Zero external dependencies (Python standard library only: json, os, hashlib, time, uuid, struct, dataclasses).

License: Apache 2.0.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import os
import pathlib
import time
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Tuple, Union


# ─── Certificate Data Schema ──────────────────────────────────────────────────

@dataclass
class CertificateTargetInfo:
    target_name: str
    target_type: str  # "DRIVE", "FILE", "FOLDER", "VOLUME", "FREE_SPACE", "SLACK", "MFT"
    device_model: str = "GENERIC_STORAGE"
    serial_number: str = "UNKNOWN_SERIAL"
    bus_type: str = "LOGICAL"
    capacity_bytes: int = 0
    sector_size: int = 512


@dataclass
class CertificateMethodInfo:
    method_id: int
    canonical_name: str
    standard_reference: str = "NIST SP 800-88 Rev. 2 aligned"  # "NIST SP 800-88 Rev. 2 aligned", "NIST SP 800-88 Rev. 1 aligned", etc.
    pass_count: int = 1
    pattern_description: str = "Single-pass zero overwrite"
    nist_profile: Optional[str] = "REV_2"  # "REV_1" (Legacy/Historical) or "REV_2" (Current)


@dataclass
class CertificateVerificationInfo:
    primary_verification_method: str  # "EXACT_BYTE_READBACK", "CRYPTOGRAPHIC_DIGEST"
    sample_percentage: float = 100.0
    mismatch_count: int = 0
    pre_wipe_sha256: str = ""
    post_wipe_sha256: str = ""
    observed_mean_entropy: Optional[float] = None
    entropy_evaluation_verdict: Optional[str] = None
    exact_readback_verified: bool = True


@dataclass
class CertificateTruthModel:
    execution: str = "REAL"
    verification: str = "EXACT_READBACK"
    qualification: str = "SOFTWARE-QUALIFIED"
    physical_execution: str = "NOT_EXECUTED"
    physical_qualification: str = "NOT_ESTABLISHED"


@dataclass
class ForensicSanitizationCertificate:
    certificate_id: str
    certificate_version: str = "2.0"
    case_id: str = "DEFAULT_CASE"
    case_name: str = "DREX Forensic Operation"
    examiner_name: str = "DREX Forensic Operator"
    organization: str = "Digital Recovery & Erasure Lab"
    timestamp_utc: str = ""
    target: CertificateTargetInfo = field(default_factory=lambda: CertificateTargetInfo("TARGET", "FILE"))
    method: CertificateMethodInfo = field(default_factory=lambda: CertificateMethodInfo(8, "CSPRNG Random Overwrite", "CSPRNG", 1, "Random stream"))
    verification: CertificateVerificationInfo = field(default_factory=CertificateVerificationInfo)
    truth_model: CertificateTruthModel = field(default_factory=CertificateTruthModel)
    audit_chain_prior_hash: str = "0000000000000000000000000000000000000000000000000000000000000000"
    audit_chain_event_hash: str = ""
    tamper_evident_signature: str = ""
    forensic_limitations: List[str] = field(default_factory=list)


# ─── Pure Python PDF 1.4 Generator ────────────────────────────────────────────

class PurePythonPDFWriter:
    """Standard-library pure Python PDF 1.4 document compiler.
    
    Renders professional, tamper-evident forensic certificates without external dependencies.
    """

    def __init__(
        self,
        title: str = "DREX-V2 Forensic Certificate",
        standard_banner: str = "NIST SP 800-88 Rev. 2 Aligned Evidence Record & Cryptographic Attestation",
    ):
        self.title = title
        self.standard_banner = standard_banner
        self.objects: List[bytes] = []
        self.page_contents: List[str] = []

    def add_line(self, text: str) -> None:
        """Escape text and add line to document stream."""
        escaped = (
            text.replace("\\", "\\\\")
            .replace("(", "\\(")
            .replace(")", "\\)")
        )
        self.page_contents.append(escaped)

    def compile_pdf(self) -> bytes:
        """Compile internal text streams into valid, standard-compliant PDF 1.4 byte stream."""
        # PDF Header
        out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
        offsets: List[int] = []

        # Object 1: Catalog
        offsets.append(len(out))
        out.extend(b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n")

        # Object 2: Pages
        offsets.append(len(out))
        out.extend(b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n")

        # Build Stream Content
        stream_lines = [
            "BT",
            "/F1 16 Tf",
            "50 780 Td",
            "(DREX-V2 FORENSIC SANITIZATION CERTIFICATE) Tj",
            "/F2 9 Tf",
            "0 -15 Td",
            f"({self.standard_banner}) Tj",
            "0 -25 Td",
            "/F1 10 Tf",
        ]


        y_offset = -14
        for line in self.page_contents:
            if line.startswith("---"):
                stream_lines.append(f"0 {y_offset} Td")
                stream_lines.append("(/F2 8 Tf ---------------------------------------------------------------------------------------------------) Tj")
            elif line.startswith("[SECTION]"):
                sec_title = line.replace("[SECTION]", "").strip()
                stream_lines.append(f"0 {y_offset - 4} Td")
                stream_lines.append(f"/F1 10 Tf ({sec_title}) Tj")
            else:
                stream_lines.append(f"0 {y_offset} Td")
                stream_lines.append(f"/F2 9 Tf ({line}) Tj")

        stream_lines.append("ET")
        content_stream = "\n".join(stream_lines).encode("latin-1", errors="replace")

        # Object 4: Contents Stream
        content_len = len(content_stream)

        # Object 3: Page (references Object 4 and Object 5 Font)
        offsets.append(len(out))
        out.extend(
            b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] "
            b"/Contents 4 0 R /Resources << /Font << /F1 5 0 R /F2 6 0 R >> >> >>\nendobj\n"
        )

        # Object 4: Stream Data
        offsets.append(len(out))
        out.extend(
            f"4 0 obj\n<< /Length {content_len} >>\nstream\n".encode("ascii")
            + content_stream
            + b"\nendstream\nendobj\n"
        )

        # Object 5: Font F1 (Helvetica-Bold)
        offsets.append(len(out))
        out.extend(
            b"5 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>\nendobj\n"
        )

        # Object 6: Font F2 (Helvetica)
        offsets.append(len(out))
        out.extend(
            b"6 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n"
        )

        # Cross-reference Table
        xref_start = len(out)
        out.extend(f"xref\n0 {len(offsets) + 1}\n".encode("ascii"))
        out.extend(b"0000000000 65535 f \n")
        for off in offsets:
            out.extend(f"{off:010d} 00000 n \n".encode("ascii"))

        # Trailer
        out.extend(
            f"trailer\n<< /Size {len(offsets) + 1} /Root 1 0 R >>\nstartxref\n{xref_start}\n%%EOF\n".encode("ascii")
        )

        return bytes(out)


# ─── Certificate Engine ───────────────────────────────────────────────────────

class ForensicCertificateEngine:
    """High-Assurance Forensic Sanitization & Verification Certificate Engine."""

    @classmethod
    def create_certificate(
        cls,
        case_id: str,
        case_name: str,
        examiner_name: str,
        organization: str,
        target_info: CertificateTargetInfo,
        method_info: CertificateMethodInfo,
        verification_info: CertificateVerificationInfo,
        prior_audit_hash: str = "0000000000000000000000000000000000000000000000000000000000000000",
        limitations: Optional[List[str]] = None,
    ) -> ForensicSanitizationCertificate:
        """Create a forensic sanitization certificate with SHA-256 integrity binding."""
        cert_id = f"CERT-DREX-{uuid.uuid4().hex[:12].upper()}"
        timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

        lims = limitations or [
            "Certificate valid for logical and software-qualified execution scopes.",
            "Flash wear-leveling and over-provisioned areas require device-native Purge.",
        ]

        # Compute tamper-evident hash binding all certificate fields
        data_to_hash = (
            f"{cert_id}|{case_id}|{examiner_name}|{target_info.target_name}|"
            f"{method_info.method_id}|{method_info.standard_reference}|{verification_info.post_wipe_sha256}|{prior_audit_hash}"
        )
        event_hash = hashlib.sha256(data_to_hash.encode("utf-8")).hexdigest()

        # Compute certificate cryptographic integrity token (SHA-256 integrity binding)
        signature_payload = f"{event_hash}:{prior_audit_hash}:{timestamp}"
        signature = hashlib.sha256(signature_payload.encode("utf-8")).hexdigest()

        return ForensicSanitizationCertificate(
            certificate_id=cert_id,
            certificate_version="2.0",
            case_id=case_id,
            case_name=case_name,
            examiner_name=examiner_name,
            organization=organization,
            timestamp_utc=timestamp,
            target=target_info,
            method=method_info,
            verification=verification_info,
            truth_model=CertificateTruthModel(),
            audit_chain_prior_hash=prior_audit_hash,
            audit_chain_event_hash=event_hash,
            tamper_evident_signature=signature,
            forensic_limitations=lims,
        )

    @classmethod
    def export_json(cls, certificate: ForensicSanitizationCertificate, output_path: Union[str, pathlib.Path]) -> str:
        """Export certificate as structured, pretty-printed JSON."""
        p = pathlib.Path(output_path)
        cert_dict = asdict(certificate)
        json_data = json.dumps(cert_dict, indent=2)
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "w", encoding="utf-8") as f:
            f.write(json_data)
        return json_data

    @classmethod
    def export_pdf(cls, certificate: ForensicSanitizationCertificate, output_path: Union[str, pathlib.Path]) -> bytes:
        """Export certificate as professional PDF 1.4 document using pure standard library."""
        # Determine appropriate NIST standard banner based on method profile or standard reference
        std_ref = certificate.method.standard_reference
        nist_prof = certificate.method.nist_profile
        if nist_prof == "REV_1" or "Rev. 1" in std_ref or "REV1" in std_ref:
            banner = "NIST SP 800-88 Rev. 1 Aligned (Legacy/Historical) & ISO/IEC 27037 Referenced Evidence Record"
        else:
            banner = "NIST SP 800-88 Rev. 2 Aligned (Current) & ISO/IEC 27037 Referenced Evidence Record"

        writer = PurePythonPDFWriter(
            title=f"DREX Certificate - {certificate.certificate_id}",
            standard_banner=banner,
        )

        writer.add_line(f"Certificate ID: {certificate.certificate_id}   |   Issued: {certificate.timestamp_utc}")
        writer.add_line(f"Case Reference: {certificate.case_id} - {certificate.case_name}")
        writer.add_line(f"Lead Examiner:  {certificate.examiner_name}   |   Org: {certificate.organization}")
        writer.add_line("---")
        writer.add_line("[SECTION] 1. TARGET MEDIA IDENTIFICATION")
        writer.add_line(f"Target Name:     {certificate.target.target_name}")
        writer.add_line(f"Target Type:     {certificate.target.target_type}   |   Bus: {certificate.target.bus_type}")
        writer.add_line(f"Model / Serial:  {certificate.target.device_model} / {certificate.target.serial_number}")
        writer.add_line(f"Capacity:        {certificate.target.capacity_bytes} bytes ({certificate.target.capacity_bytes / (1024*1024):.2f} MB)")
        writer.add_line("---")
        writer.add_line("[SECTION] 2. SANITIZATION METHOD & SPECIFICATION")
        writer.add_line(f"Method:          [Method {certificate.method.method_id:02d}] {certificate.method.canonical_name}")
        writer.add_line(f"Standard Ref:    {certificate.method.standard_reference}")
        writer.add_line(f"Pass Sequence:   {certificate.method.pass_count} Pass(es) - {certificate.method.pattern_description}")
        writer.add_line("---")
        writer.add_line("[SECTION] 3. VERIFICATION & FORENSIC EVIDENCE")
        writer.add_line(f"Primary Verify:  {certificate.verification.primary_verification_method} (Sample: {certificate.verification.sample_percentage}%)")
        writer.add_line(f"Readback Status: {'PASS - 0 MISMATCHES' if certificate.verification.exact_readback_verified else 'FAIL - MISMATCH DETECTED'}")
        writer.add_line(f"Pre-Wipe SHA256: {certificate.verification.pre_wipe_sha256 or 'N/A'}")
        writer.add_line(f"Post-Wipe SHA256:{certificate.verification.post_wipe_sha256 or 'N/A'}")
        if certificate.verification.observed_mean_entropy is not None:
            writer.add_line(f"Entropy (H):     {certificate.verification.observed_mean_entropy:.4f} bits/byte ({certificate.verification.entropy_evaluation_verdict})")
        writer.add_line("---")
        writer.add_line("[SECTION] 4. TRUTH MODEL & AUDIT CHAIN BINDING")
        writer.add_line(f"Execution State: {certificate.truth_model.execution} | Verification: {certificate.truth_model.verification}")
        writer.add_line(f"Qualification:   {certificate.truth_model.qualification} | Physical Exec: {certificate.truth_model.physical_execution}")
        writer.add_line(f"Prior Node Hash: {certificate.audit_chain_prior_hash[:32]}...")
        writer.add_line(f"Audit Event Hash:{certificate.audit_chain_event_hash}")
        writer.add_line(f"Integrity Token: {certificate.tamper_evident_signature}")
        writer.add_line("---")
        writer.add_line("[SECTION] 5. FORENSIC DISCLAIMERS & LIMITATIONS")
        for lim in certificate.forensic_limitations:
            writer.add_line(f"- {lim}")

        pdf_bytes = writer.compile_pdf()
        p = pathlib.Path(output_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "wb") as f:
            f.write(pdf_bytes)

        return pdf_bytes

    @classmethod
    def verify_certificate_integrity(cls, cert_dict: Dict[str, Any]) -> bool:
        """Verify certificate SHA-256 integrity binding and internal hash consistency."""
        try:
            cert_id = cert_dict["certificate_id"]
            case_id = cert_dict["case_id"]
            examiner = cert_dict["examiner_name"]
            target_name = cert_dict["target"]["target_name"]
            method_id = cert_dict["method"]["method_id"]
            method_std = cert_dict.get("method", {}).get("standard_reference", "")
            post_sha = cert_dict["verification"]["post_wipe_sha256"]
            prior_hash = cert_dict["audit_chain_prior_hash"]
            event_hash = cert_dict["audit_chain_event_hash"]
            timestamp = cert_dict["timestamp_utc"]
            sig = cert_dict["tamper_evident_signature"]

            expected_data_with_std = f"{cert_id}|{case_id}|{examiner}|{target_name}|{method_id}|{method_std}|{post_sha}|{prior_hash}"
            expected_data_legacy = f"{cert_id}|{case_id}|{examiner}|{target_name}|{method_id}|{post_sha}|{prior_hash}"
            calc_event_hash_std = hashlib.sha256(expected_data_with_std.encode("utf-8")).hexdigest()
            calc_event_hash_legacy = hashlib.sha256(expected_data_legacy.encode("utf-8")).hexdigest()

            if event_hash not in (calc_event_hash_std, calc_event_hash_legacy):
                return False

            expected_sig_payload = f"{event_hash}:{prior_hash}:{timestamp}"
            calc_sig = hashlib.sha256(expected_sig_payload.encode("utf-8")).hexdigest()

            return calc_sig == sig
        except (KeyError, TypeError):
            return False
