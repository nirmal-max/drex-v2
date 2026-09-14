"""
DREX-V2 Standalone Independent Evidence Verifier
=================================================
Independent forensic verifier for DREX-V2 Evidence Packages (Schema 2.0).

STRICT ARCHITECTURAL GUARANTEE:
This module is 100% self-contained and uses ONLY the Python standard library.
It MUST NOT import or depend on any DREX application modules, GUI code,
execution engines, hardware controllers, or destructive backends.

Trust Model:
- Integrity is NOT authenticity of origin (SHA-256 binds bit-level immutability).
- Stored status fields are NEVER trusted; all digests and relationships are recomputed from raw bytes.
- Pre-extraction safety validation is enforced on all archive members before extraction.
- Deterministic verdict precedence: INVALID -> INCOMPLETE -> TAMPERED -> INDETERMINATE -> PASS.

Exit Codes:
  0 = PASS
  1 = TAMPERED
  2 = INCOMPLETE
  3 = INVALID
  4 = INDETERMINATE

Zero external dependencies.
License: Apache 2.0.
"""

from __future__ import annotations

import argparse
import dataclasses
import enum
import hashlib
import json
import os
import re
import shutil
import sys
import tarfile
import tempfile
import zipfile
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union


# ─── Constants & Schema Definitions ──────────────────────────────────────────

VERIFIER_NAME = "DREX Standalone Independent Verifier"
VERIFIER_VERSION = "1.0.0"
SUPPORTED_SCHEMA_VERSIONS = {"2.0"}
HISTORICAL_SCHEMA_VERSIONS = {"1.0"}
GENESIS_HASH = "0" * 64
STREAMING_CHUNK_SIZE = 64 * 1024  # 64 KB memory-bounded buffer

STRUCTURAL_PACKAGE_FILES = {
    "manifest.json",
    "manifest.sha256",
    "README.txt",
    "readme.txt",
}

RESERVED_DEVICE_NAMES = {
    "CON", "PRN", "AUX", "NUL",
    "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
    "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
}


# ─── Verdict & Status Enumerations ───────────────────────────────────────────

class VerificationVerdict(enum.Enum):
    PASS = "PASS"
    TAMPERED = "TAMPERED"
    INCOMPLETE = "INCOMPLETE"
    INVALID = "INVALID"
    INDETERMINATE = "INDETERMINATE"


class ExitCode(enum.IntEnum):
    PASS = 0
    TAMPERED = 1
    INCOMPLETE = 2
    INVALID = 3
    INDETERMINATE = 4


# ─── Data Models ─────────────────────────────────────────────────────────────

@dataclass
class DiagnosticRecord:
    level: str  # "ERROR", "WARNING", "INFO"
    category: str  # "ARCHIVE_SAFETY", "SCHEMA", "MANIFEST", "OBJECT", "AUDIT", "CUSTODY", "CERTIFICATE", "CROSSLINK"
    target: str
    message: str
    details: Optional[Dict[str, Any]] = None


@dataclass
class VerificationSummary:
    objects_declared: int = 0
    objects_verified: int = 0
    objects_missing: int = 0
    objects_tampered: int = 0
    objects_unexpected: int = 0
    audit_events_verified: int = 0
    audit_events_tampered: int = 0
    custody_records_verified: int = 0
    custody_records_tampered: int = 0
    certificates_verified: int = 0
    certificates_tampered: int = 0
    cross_link_errors: int = 0


@dataclass
class VerificationReport:
    report_schema_version: str = "1.0"
    verifier_name: str = VERIFIER_NAME
    verifier_version: str = VERIFIER_VERSION
    verification_timestamp_utc: str = ""
    package_path: str = ""
    package_schema_version: str = ""
    package_id: Optional[str] = None
    case_id: Optional[str] = None
    manifest_sha256: Optional[str] = None
    final_verdict: VerificationVerdict = VerificationVerdict.INVALID
    exit_code: int = int(ExitCode.INVALID)
    summary: VerificationSummary = field(default_factory=VerificationSummary)
    diagnostics: List[DiagnosticRecord] = field(default_factory=list)
    truth_model_summary: Dict[str, str] = field(default_factory=lambda: {
        "physical_execution": "NOT_EXECUTED",
        "physical_qualification": "NOT_ESTABLISHED",
    })
    limitations: List[str] = field(default_factory=lambda: [
        "Independent verification validates package internal integrity only.",
        "Verification does not prove physical hardware qualification or physical destruction.",
        "SHA-256 integrity binding does not prove the real-world identity of the package creator without asymmetric signatures.",
    ])

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["final_verdict"] = self.final_verdict.value if isinstance(self.final_verdict, VerificationVerdict) else str(self.final_verdict)
        return d

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True, ensure_ascii=False)


# ─── Independent Canonical Cryptographic Primitives ──────────────────────────

def canonical_json_bytes(data: Any) -> bytes:
    """DREX canonical JSON serialization using UTF-8, sorted object keys, and compact separators."""
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def hash_file_streaming(file_path: Union[str, Path], chunk_size: int = STREAMING_CHUNK_SIZE) -> Tuple[str, int]:
    """Calculate SHA-256 digest and byte size of a file using test-verified bounded streaming (fixed 64 KB chunk size)."""
    path = Path(file_path)
    hasher = hashlib.sha256()
    total_bytes = 0
    with open(path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            hasher.update(chunk)
            total_bytes += len(chunk)
    return hasher.hexdigest(), total_bytes


def hash_bytes_sha256(data: bytes) -> str:
    """Calculate SHA-256 hex digest of a byte sequence."""
    return hashlib.sha256(data).hexdigest()


def compute_envelope_audit_hash(
    previous_hash: str,
    sequence_number: int,
    event_id: str,
    case_id: str,
    timestamp: str,
    actor: str,
    event_type: str,
    payload: Dict[str, Any],
    operation_id: Optional[str] = None,
) -> str:
    """Calculate deterministic SHA-256 hash for an audit event covering the entire canonical envelope."""
    envelope = {
        "sequence_number": sequence_number,
        "event_id": event_id,
        "case_id": case_id,
        "timestamp": timestamp,
        "actor": actor,
        "event_type": event_type,
        "operation_id": operation_id,
        "payload": payload,
    }
    canon_bytes = canonical_json_bytes(envelope)
    preimage = previous_hash.encode("utf-8") + canon_bytes
    return hashlib.sha256(preimage).hexdigest()


def compute_custody_record_hash(record: Dict[str, Any]) -> str:
    """Calculate deterministic SHA-256 hash for a chain-of-custody record."""
    payload = {
        "custody_event_id": record.get("custody_event_id"),
        "evidence_id": record.get("evidence_id"),
        "case_id": record.get("case_id"),
        "custodian": record.get("custodian"),
        "action": record.get("action"),
        "timestamp": record.get("timestamp"),
        "reason": record.get("reason"),
        "source_location": record.get("source_location"),
        "destination": record.get("destination"),
        "hash_before": record.get("hash_before"),
        "hash_after": record.get("hash_after"),
        "notes": record.get("notes", ""),
    }
    return hashlib.sha256(canonical_json_bytes(payload)).hexdigest()


def verify_certificate_token(cert: Dict[str, Any]) -> Tuple[bool, str]:
    """
    Recompute and verify the SHA-256 integrity binding on a forensic certificate.
    Returns (is_valid, reason).
    """
    try:
        cert_id = cert.get("certificate_id", "")
        case_id = cert.get("case_id", "")
        examiner = cert.get("examiner_name", "")
        target_info = cert.get("target", {})
        target_name = target_info.get("target_name", "")
        method_info = cert.get("method", {})
        method_id = method_info.get("method_id", 0)
        method_std = method_info.get("standard_reference", "")
        verif_info = cert.get("verification", {})
        post_sha = verif_info.get("post_wipe_sha256", "")
        prior_hash = cert.get("audit_chain_prior_hash", "")
        event_hash = cert.get("audit_chain_event_hash", "")
        timestamp = cert.get("timestamp_utc", "")
        sig = cert.get("tamper_evident_signature", "")

        # Canonical integrity preimage with standard reference
        expected_data_std = f"{cert_id}|{case_id}|{examiner}|{target_name}|{method_id}|{method_std}|{post_sha}|{prior_hash}"
        expected_data_legacy = f"{cert_id}|{case_id}|{examiner}|{target_name}|{method_id}|{post_sha}|{prior_hash}"
        calc_event_std = hashlib.sha256(expected_data_std.encode("utf-8")).hexdigest()
        calc_event_leg = hashlib.sha256(expected_data_legacy.encode("utf-8")).hexdigest()

        if event_hash not in (calc_event_std, calc_event_leg):
            return False, f"Certificate event_hash mismatch: expected {calc_event_std[:16]}..., found {event_hash[:16]}..."

        expected_sig_payload = f"{event_hash}:{prior_hash}:{timestamp}"
        calc_sig = hashlib.sha256(expected_sig_payload.encode("utf-8")).hexdigest()

        if calc_sig != sig:
            return False, f"Certificate integrity token mismatch: expected {calc_sig[:16]}..., found {sig[:16]}..."

        return True, "Certificate SHA-256 integrity binding valid."
    except Exception as exc:
        return False, f"Certificate structure malformed: {exc}"


# ─── Archive Safety Pre-Extraction Validator ─────────────────────────────────

class ArchiveSafetyValidator:
    """
    Inspects archive members BEFORE extraction to reject malicious paths,
    path traversal, drive letters, UNC paths, reserved names, and symlinks.
    """

    @classmethod
    def validate_tar_members(cls, tar: tarfile.TarFile) -> Tuple[bool, List[str]]:
        errors = []
        for member in tar.getmembers():
            name = member.name
            err = cls._check_path_safety(name)
            if err:
                errors.append(f"Unsafe TAR member '{name}': {err}")

            if member.issym():
                errors.append(f"Security violation: TAR member '{name}' is a symbolic link (target: '{member.linkname}')")
            elif member.islnk():
                errors.append(f"Security violation: TAR member '{name}' is a hard link (target: '{member.linkname}')")
            elif member.ischr() or member.isblk() or member.isfifo():
                errors.append(f"Security violation: TAR member '{name}' is a special device file")

        return len(errors) == 0, errors

    @classmethod
    def validate_zip_members(cls, zf: zipfile.ZipFile) -> Tuple[bool, List[str]]:
        errors = []
        for info in zf.infolist():
            name = info.filename
            err = cls._check_path_safety(name)
            if err:
                errors.append(f"Unsafe ZIP member '{name}': {err}")

            # Check for symlink attribute in ZIP (Unix mode symlink)
            hi_word = info.external_attr >> 16
            if (hi_word & 0o170000) == 0o120000:
                errors.append(f"Security violation: ZIP member '{name}' is a symbolic link")

        return len(errors) == 0, errors

    @classmethod
    def _check_path_safety(cls, path_str: str) -> Optional[str]:
        if not path_str or path_str.strip() == "":
            return "Empty member path"

        # Normalized check
        norm = os.path.normpath(path_str)
        if norm.startswith("..") or norm.startswith("/..") or norm.startswith("\\.."):
            return "Path traversal (.. leading)"
        if ".." in norm.split(os.sep) or ".." in path_str.split("/"):
            return "Path traversal (.. component)"

        # Absolute paths
        if os.path.isabs(path_str) or path_str.startswith("/") or path_str.startswith("\\"):
            return "Absolute path not permitted"

        # Windows Drive letters
        if bool(re.match(r'^[a-zA-Z]:', path_str)):
            return "Windows drive letter path not permitted"

        # Colons (NTFS Alternate Data Streams or drive specifiers)
        if ":" in path_str:
            return "Colon character not permitted in member path"

        # UNC paths
        if path_str.startswith("\\\\") or path_str.startswith("//"):
            return "UNC network path not permitted"

        # Check path components for reserved device names
        parts = re.split(r'[/\\+]', path_str)
        for p in parts:
            clean_p = p.strip()
            # Strip file extension for base device name check (e.g. NUL.txt)
            base_p = clean_p.split(".")[0].upper()
            if base_p in RESERVED_DEVICE_NAMES:
                return f"Reserved DOS/Windows device name '{base_p}' not permitted"

        return None


# ─── Independent Package Verification Engine ─────────────────────────────────

class IndependentPackageVerifier:
    """
    Stateless, standalone independent evidence package verifier.
    Recomputes assurance from ground-truth package bytes without trusting stored statuses.
    """

    def __init__(self, package_path: Union[str, Path]):
        self.raw_path = Path(package_path).resolve()
        self.report = VerificationReport(
            verification_timestamp_utc=datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
            package_path=str(self.raw_path),
        )
        self._temp_dir: Optional[Path] = None
        self._package_root: Optional[Path] = None

    def verify(self) -> VerificationReport:
        """Execute full 8-phase independent verification pipeline."""
        try:
            # ── Phase 1: Archive Safety & Container Resolution ───────────────
            if not self.raw_path.exists():
                self._add_diag("ERROR", "ARCHIVE_SAFETY", str(self.raw_path), "Target package path does not exist.")
                return self._finalize(VerificationVerdict.INVALID, ExitCode.INVALID)

            if self.raw_path.is_dir():
                self._package_root = self.raw_path
            else:
                # Compressed archive: validate members before extraction
                ok, errs = self._inspect_and_extract_archive()
                if not ok:
                    for e in errs:
                        self._add_diag("ERROR", "ARCHIVE_SAFETY", str(self.raw_path), e)
                    return self._finalize(VerificationVerdict.INVALID, ExitCode.INVALID)

            assert self._package_root is not None

            # ── Phase 2: Structural File & Schema Validation ─────────────────
            manifest_file = self._package_root / "manifest.json"
            if not manifest_file.is_file():
                self._add_diag("ERROR", "MANIFEST", "manifest.json", "manifest.json is missing from package root.")
                return self._finalize(VerificationVerdict.INVALID, ExitCode.INVALID)

            try:
                manifest_data = json.loads(manifest_file.read_text(encoding="utf-8"))
            except Exception as exc:
                self._add_diag("ERROR", "SCHEMA", "manifest.json", f"manifest.json is not valid JSON: {exc}")
                return self._finalize(VerificationVerdict.INVALID, ExitCode.INVALID)

            if not isinstance(manifest_data, dict):
                self._add_diag("ERROR", "SCHEMA", "manifest.json", "manifest.json root must be a JSON object.")
                return self._finalize(VerificationVerdict.INVALID, ExitCode.INVALID)

            # Schema version evaluation (4-way deterministic model)
            schema_ver = manifest_data.get("schema_version")
            if schema_ver is None:
                self._add_diag("ERROR", "SCHEMA", "schema_version", "schema_version is missing from manifest.json.")
                return self._finalize(VerificationVerdict.INVALID, ExitCode.INVALID)

            schema_ver_str = str(schema_ver).strip()
            self.report.package_schema_version = schema_ver_str
            self.report.package_id = manifest_data.get("package_id")
            self.report.case_id = manifest_data.get("case_id")

            if schema_ver_str in HISTORICAL_SCHEMA_VERSIONS:
                self._add_diag("ERROR", "SCHEMA", "schema_version", f"Known historical schema version '{schema_ver_str}' is unsupported without compatibility adapter.")
                return self._finalize(VerificationVerdict.INVALID, ExitCode.INVALID)
            elif schema_ver_str not in SUPPORTED_SCHEMA_VERSIONS:
                # Unknown future / newer schema version -> INDETERMINATE
                self._add_diag("WARNING", "SCHEMA", "schema_version", f"Unknown/future package schema version '{schema_ver_str}' cannot be interpreted.")
                return self._finalize(VerificationVerdict.INDETERMINATE, ExitCode.INDETERMINATE)

            # ── Phase 3: Manifest Root Hash Binding ──────────────────────────
            manifest_sha_file = self._package_root / "manifest.sha256"
            if not manifest_sha_file.is_file():
                self._add_diag("ERROR", "MANIFEST", "manifest.sha256", "manifest.sha256 root digest is missing from package root.")
                return self._finalize(VerificationVerdict.INVALID, ExitCode.INVALID)

            recorded_root_sha = manifest_sha_file.read_text(encoding="utf-8").strip().split()[0]
            self.report.manifest_sha256 = recorded_root_sha
            actual_manifest_sha, _ = hash_file_streaming(manifest_file)
            if actual_manifest_sha.lower() != recorded_root_sha.lower():
                self._add_diag(
                    "ERROR", "MANIFEST", "manifest.sha256",
                    f"Root manifest digest mismatch: expected {recorded_root_sha[:16]}..., actual manifest.json is {actual_manifest_sha[:16]}...",
                )
                return self._finalize(VerificationVerdict.TAMPERED, ExitCode.TAMPERED)

            # ── Phase 4: Declared Objects vs Package Files Verification ──────
            declared_objects = manifest_data.get("objects", [])
            if not isinstance(declared_objects, list):
                self._add_diag("ERROR", "SCHEMA", "objects", "'objects' field in manifest.json must be a JSON array.")
                return self._finalize(VerificationVerdict.INVALID, ExitCode.INVALID)

            self.report.summary.objects_declared = len(declared_objects)
            declared_paths: Set[str] = set()
            has_missing_object = False
            has_tampered_object = False

            for idx, obj in enumerate(declared_objects):
                if not isinstance(obj, dict):
                    self._add_diag("ERROR", "SCHEMA", f"objects[{idx}]", "Object entry must be a dictionary.")
                    return self._finalize(VerificationVerdict.INVALID, ExitCode.INVALID)

                rel_path = obj.get("relative_path")
                if not rel_path or not isinstance(rel_path, str):
                    self._add_diag("ERROR", "SCHEMA", f"objects[{idx}]", "Object missing required 'relative_path'.")
                    return self._finalize(VerificationVerdict.INVALID, ExitCode.INVALID)

                norm_rel = Path(rel_path).as_posix()
                declared_paths.add(norm_rel)

                target_file = self._package_root / Path(norm_rel)
                if not target_file.is_file():
                    has_missing_object = True
                    self.report.summary.objects_missing += 1
                    self._add_diag("ERROR", "OBJECT", norm_rel, f"Declared object file missing from package: {norm_rel}")
                    continue

                actual_sha, actual_size = hash_file_streaming(target_file)
                exp_sha = obj.get("sha256", "")
                exp_size = obj.get("size_bytes")

                mismatch = False
                if exp_size is not None and actual_size != exp_size:
                    mismatch = True
                    self._add_diag(
                        "ERROR", "OBJECT", norm_rel,
                        f"Byte size mismatch for '{norm_rel}': declared {exp_size} bytes, actual {actual_size} bytes.",
                    )
                if actual_sha.lower() != str(exp_sha).lower():
                    mismatch = True
                    self._add_diag(
                        "ERROR", "OBJECT", norm_rel,
                        f"SHA-256 digest mismatch for '{norm_rel}': declared {exp_sha[:16]}..., actual {actual_sha[:16]}...",
                    )

                if mismatch:
                    has_tampered_object = True
                    self.report.summary.objects_tampered += 1
                else:
                    self.report.summary.objects_verified += 1

            # Check for undeclared / unexpected extra files in package
            for root, _, files in os.walk(self._package_root):
                for f in files:
                    full_p = Path(root) / f
                    rel_p = full_p.relative_to(self._package_root).as_posix()
                    if rel_p in STRUCTURAL_PACKAGE_FILES or rel_p in declared_paths:
                        continue
                    # Any undeclared file is flagged as an unexpected extra object
                    self.report.summary.objects_unexpected += 1
                    self._add_diag("ERROR", "MANIFEST", rel_p, f"Undeclared unexpected file present in package: {rel_p}")
                    has_tampered_object = True

            # ── Phase 5: Cryptographically Hash-Linked Audit Chain ───────────
            audit_file = self._package_root / "audit" / "audit_chain.json"
            if not audit_file.is_file():
                audit_file = self._package_root / "audit_chain.json"
            audit_events: List[Dict[str, Any]] = []
            if audit_file.is_file():
                audit_ok, a_events = self._verify_audit_chain(audit_file)
                if not audit_ok:
                    has_tampered_object = True
                else:
                    audit_events = a_events

            # ── Phase 6: Chain of Custody Verification ───────────────────────
            custody_file = self._package_root / "custody" / "custody_ledger.json"
            if not custody_file.is_file():
                custody_file = self._package_root / "custody.json"
            if custody_file.is_file():
                custody_ok = self._verify_custody_ledger(custody_file, audit_events)
                if not custody_ok:
                    has_tampered_object = True

            # ── Phase 7: Certificate Integrity & Cross-Link Verification ─────
            certs_dir = self._package_root / "certificates"
            if certs_dir.is_dir():
                certs_ok = self._verify_certificates(certs_dir, audit_events)
                if not certs_ok:
                    has_tampered_object = True

            # ── Phase 8: Referential Cross-Link Validation ───────────────────
            cross_ok = self._verify_cross_references(manifest_data, audit_events)
            if not cross_ok:
                has_tampered_object = True

            # ── Final Verdict Precedence Synthesis ───────────────────────────
            # Precedence: INVALID -> INCOMPLETE -> TAMPERED -> INDETERMINATE -> PASS
            if has_missing_object:
                return self._finalize(VerificationVerdict.INCOMPLETE, ExitCode.INCOMPLETE)
            if has_tampered_object or self.report.summary.cross_link_errors > 0:
                return self._finalize(VerificationVerdict.TAMPERED, ExitCode.TAMPERED)

            return self._finalize(VerificationVerdict.PASS, ExitCode.PASS)

        finally:
            self._cleanup_temp()

    def _inspect_and_extract_archive(self) -> Tuple[bool, List[str]]:
        """Validate archive members before extracting to temporary sandbox."""
        self._temp_dir = Path(tempfile.mkdtemp(prefix="drex_independent_verify_"))
        errs = []

        if tarfile.is_tarfile(self.raw_path):
            with tarfile.open(self.raw_path, "r:*") as tar:
                ok, member_errs = ArchiveSafetyValidator.validate_tar_members(tar)
                if not ok:
                    return False, member_errs
                tar.extractall(self._temp_dir)
            self._package_root = self._temp_dir
            return True, []

        elif zipfile.is_zipfile(self.raw_path):
            with zipfile.ZipFile(self.raw_path, "r") as zf:
                ok, member_errs = ArchiveSafetyValidator.validate_zip_members(zf)
                if not ok:
                    return False, member_errs
                zf.extractall(self._temp_dir)
            self._package_root = self._temp_dir
            return True, []

        else:
            return False, [f"Unsupported package container format: '{self.raw_path.name}'. Expected directory, tar.gz, or zip."]

    def _verify_audit_chain(self, audit_file: Path) -> Tuple[bool, List[Dict[str, Any]]]:
        """Recompute every node in the hash-chained audit ledger."""
        try:
            data = json.loads(audit_file.read_text(encoding="utf-8"))
            if not isinstance(data, list):
                self._add_diag("ERROR", "AUDIT", "audit_chain.json", "audit_chain.json must be a JSON array of events.")
                self.report.summary.audit_events_tampered += 1
                return False, []

            expected_prev = GENESIS_HASH
            for idx, ev in enumerate(data):
                if not isinstance(ev, dict):
                    self._add_diag("ERROR", "AUDIT", f"audit_chain.json[{idx}]", "Audit event must be a JSON object.")
                    self.report.summary.audit_events_tampered += 1
                    return False, []

                seq = ev.get("sequence_number")
                if seq != idx:
                    self._add_diag("ERROR", "AUDIT", f"audit_chain.json[{idx}]", f"Broken sequence number: expected {idx}, found {seq}")
                    self.report.summary.audit_events_tampered += 1
                    return False, []

                prev_hash = ev.get("previous_hash", "")
                if prev_hash != expected_prev:
                    self._add_diag(
                        "ERROR", "AUDIT", f"audit_chain.json[{idx}]",
                        f"Previous hash mismatch at sequence {idx}: expected {expected_prev[:16]}..., found {prev_hash[:16]}...",
                    )
                    self.report.summary.audit_events_tampered += 1
                    return False, []

                cur_hash = ev.get("current_hash", "")
                recomputed = compute_envelope_audit_hash(
                    previous_hash=prev_hash,
                    sequence_number=seq,
                    event_id=ev.get("event_id", ""),
                    case_id=ev.get("case_id", ""),
                    timestamp=ev.get("timestamp", ""),
                    actor=ev.get("actor", ""),
                    event_type=ev.get("event_type", ""),
                    payload=ev.get("canonical_payload", {}),
                    operation_id=ev.get("operation_id"),
                )

                if cur_hash != recomputed:
                    self._add_diag(
                        "ERROR", "AUDIT", f"audit_chain.json[{idx}]",
                        f"Tampered audit envelope hash at sequence {idx} ({ev.get('event_id')}): recomputed {recomputed[:16]}..., recorded {cur_hash[:16]}...",
                    )
                    self.report.summary.audit_events_tampered += 1
                    return False, []

                expected_prev = cur_hash
                self.report.summary.audit_events_verified += 1

            return True, data
        except Exception as exc:
            self._add_diag("ERROR", "AUDIT", "audit_chain.json", f"Failed to parse audit ledger: {exc}")
            self.report.summary.audit_events_tampered += 1
            return False, []

    def _verify_custody_ledger(self, custody_file: Path, audit_events: List[Dict[str, Any]]) -> bool:
        """Recompute custody record integrity hashes and verify alignment with audit ledger."""
        try:
            data = json.loads(custody_file.read_text(encoding="utf-8"))
            if not isinstance(data, list):
                self._add_diag("ERROR", "CUSTODY", "custody_ledger.json", "custody_ledger.json must be a JSON array.")
                self.report.summary.custody_records_tampered += 1
                return False

            all_ok = True
            for idx, rec in enumerate(data):
                if not isinstance(rec, dict):
                    self._add_diag("ERROR", "CUSTODY", f"custody_ledger.json[{idx}]", "Custody record must be a JSON object.")
                    self.report.summary.custody_records_tampered += 1
                    return False

                calc_hash = compute_custody_record_hash(rec)
                recorded_hash = rec.get("integrity_reference", "")
                if calc_hash != recorded_hash:
                    self._add_diag(
                        "ERROR", "CUSTODY", f"custody_ledger.json[{idx}]",
                        f"Tampered custody record ({rec.get('custody_event_id')}): expected {calc_hash[:16]}..., recorded {recorded_hash[:16]}...",
                    )
                    self.report.summary.custody_records_tampered += 1
                    all_ok = False
                else:
                    self.report.summary.custody_records_verified += 1

            # Match against CUSTODY_CHANGE audit events if audit ledger was present
            if audit_events:
                custody_audits = [e for e in audit_events if e.get("event_type") == "CUSTODY_CHANGE"]
                if len(custody_audits) != len(data):
                    self._add_diag(
                        "ERROR", "CUSTODY", "custody_ledger.json",
                        f"Custody record count ({len(data)}) does not match audit ledger CUSTODY_CHANGE count ({len(custody_audits)}).",
                    )
                    all_ok = False

            return all_ok
        except Exception as exc:
            self._add_diag("ERROR", "CUSTODY", "custody_ledger.json", f"Failed to parse custody ledger: {exc}")
            self.report.summary.custody_records_tampered += 1
            return False

    def _verify_certificates(self, certs_dir: Path, audit_events: List[Dict[str, Any]]) -> bool:
        """Verify SHA-256 integrity binding on all JSON certificates."""
        all_ok = True
        for c_file in sorted(certs_dir.glob("*.json")):
            try:
                cert_data = json.loads(c_file.read_text(encoding="utf-8"))
                valid, msg = verify_certificate_token(cert_data)
                if not valid:
                    self._add_diag("ERROR", "CERTIFICATE", c_file.name, msg)
                    self.report.summary.certificates_tampered += 1
                    all_ok = False
                else:
                    # Check that certificate audit reference links to an audit event if audit is present
                    cert_prior_hash = cert_data.get("audit_chain_prior_hash")
                    cert_event_hash = cert_data.get("audit_chain_event_hash")
                    if audit_events:
                        audit_hashes = {e.get("current_hash") for e in audit_events}
                        has_link = False
                        if cert_prior_hash and (cert_prior_hash in audit_hashes or cert_prior_hash == GENESIS_HASH):
                            has_link = True
                        elif cert_event_hash and cert_event_hash in audit_hashes:
                            has_link = True
                        else:
                            cert_id = cert_data.get("certificate_id")
                            if any(cert_id == (e.get("canonical_payload") or {}).get("certificate_id") for e in audit_events):
                                has_link = True

                        if not has_link:
                            self._add_diag(
                                "ERROR", "CERTIFICATE", c_file.name,
                                f"Certificate audit reference '{str(cert_prior_hash)[:16]}...' does not link to any audit ledger event.",
                            )
                            self.report.summary.certificates_tampered += 1
                            all_ok = False
                            continue
                    self.report.summary.certificates_verified += 1
            except Exception as exc:
                self._add_diag("ERROR", "CERTIFICATE", c_file.name, f"Failed to parse certificate: {exc}")
                self.report.summary.certificates_tampered += 1
                all_ok = False
        return all_ok

    def _verify_cross_references(self, manifest_data: Dict[str, Any], audit_events: List[Dict[str, Any]]) -> bool:
        """Validate relational cross-references between case, evidence, operations, audit, and certs."""
        all_ok = True
        pkg_case_id = manifest_data.get("case_id")

        # 1. Verify case.json if present
        case_file = self._package_root / "case" / "case.json"
        if not case_file.is_file():
            case_file = self._package_root / "case.json"  # Support root case.json
        if case_file.is_file():
            try:
                c_data = json.loads(case_file.read_text(encoding="utf-8"))
                c_id = c_data.get("case_id")
                if pkg_case_id and c_id and pkg_case_id != c_id:
                    self._add_diag("ERROR", "CROSSLINK", "case.json", f"Manifest case_id '{pkg_case_id}' does not match case.json '{c_id}'.")
                    self.report.summary.cross_link_errors += 1
                    all_ok = False
            except Exception:
                pass

        # 2. Verify audit event case IDs
        for idx, ev in enumerate(audit_events):
            ev_case_id = ev.get("case_id")
            if pkg_case_id and ev_case_id and pkg_case_id != ev_case_id:
                self._add_diag(
                    "ERROR", "CROSSLINK", f"audit_chain.json[{idx}]",
                    f"Audit event {ev.get('event_id')} case_id '{ev_case_id}' does not match package case_id '{pkg_case_id}'.",
                )
                self.report.summary.cross_link_errors += 1
                all_ok = False

        return all_ok

    def _add_diag(self, level: str, category: str, target: str, message: str) -> None:
        self.report.diagnostics.append(DiagnosticRecord(
            level=level, category=category, target=target, message=message,
        ))

    def _finalize(self, verdict: VerificationVerdict, exit_code: ExitCode) -> VerificationReport:
        self.report.final_verdict = verdict
        self.report.exit_code = int(exit_code)
        return self.report

    def _cleanup_temp(self) -> None:
        if self._temp_dir and self._temp_dir.exists():
            shutil.rmtree(self._temp_dir, ignore_errors=True)
            self._temp_dir = None


# ─── Verification Report Exporter ────────────────────────────────────────────

def write_verification_report(report: VerificationReport, output_json_path: Union[str, Path]) -> Tuple[Path, Path]:
    """
    Write machine-readable verification_report.json and non-recursive verification_report.sha256.
    Returns (report_json_path, report_sha256_path).
    """
    out_json = Path(output_json_path).resolve()
    out_json.parent.mkdir(parents=True, exist_ok=True)
    json_bytes = canonical_json_bytes(report.to_dict())

    # Write JSON report
    out_json.write_bytes(json_bytes)

    # Write non-recursive standalone SHA-256 digest
    digest = hash_bytes_sha256(json_bytes)
    out_sha = out_json.with_suffix(".sha256")
    out_sha.write_text(f"{digest}  {out_json.name}\n", encoding="utf-8")

    return out_json, out_sha


# ─── Command-Line Interface Entry Point ──────────────────────────────────────

def format_human_report(report: VerificationReport) -> str:
    """Format human-readable verification console summary."""
    lines = [
        "=" * 78,
        f"  DREX-V2 INDEPENDENT EVIDENCE VERIFICATION REPORT",
        "=" * 78,
        f"  Verifier:        {report.verifier_name} v{report.verifier_version}",
        f"  Timestamp (UTC): {report.verification_timestamp_utc}",
        f"  Package Path:    {report.package_path}",
        f"  Package Schema:  {report.package_schema_version or 'N/A'}",
        f"  Package ID:      {report.package_id or 'N/A'}",
        f"  Case ID:         {report.case_id or 'N/A'}",
        f"  Manifest SHA256: {report.manifest_sha256 or 'N/A'}",
        "-" * 78,
        f"  FINAL VERDICT:   [{report.final_verdict.value}] (Exit Code: {report.exit_code})",
        "-" * 78,
        f"  Summary Metrics:",
        f"    - Objects Declared:     {report.summary.objects_declared}",
        f"    - Objects Verified:     {report.summary.objects_verified}",
        f"    - Objects Missing:      {report.summary.objects_missing}",
        f"    - Objects Tampered:     {report.summary.objects_tampered}",
        f"    - Unexpected Objects:   {report.summary.objects_unexpected}",
        f"    - Audit Events Valid:   {report.summary.audit_events_verified}",
        f"    - Custody Records Valid:{report.summary.custody_records_verified}",
        f"    - Certificates Valid:   {report.summary.certificates_verified}",
        f"    - Cross-Link Failures:  {report.summary.cross_link_errors}",
        "-" * 78,
        f"  Truth Model Disclaimers:",
        f"    - Physical Execution:     {report.truth_model_summary.get('physical_execution')}",
        f"    - Physical Qualification: {report.truth_model_summary.get('physical_qualification')}",
    ]

    if report.diagnostics:
        lines.append("-" * 78)
        lines.append("  Diagnostics / Anomalies Detected:")
        for diag in report.diagnostics:
            lines.append(f"    [{diag.level}] [{diag.category}] {diag.target}: {diag.message}")

    lines.append("=" * 78)
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="DREX-V2 Standalone Headless Evidence Package Verifier (Zero Dependencies)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("package", help="Path to evidence package directory or archive (.tar, .tar.gz, .zip)")
    parser.add_argument("--json", action="store_true", help="Output machine-readable JSON report to stdout")
    parser.add_argument("--out", "-o", help="Optional output path to write verification_report.json and .sha256")
    parser.add_argument("--verbose", "-v", action="store_true", help="Display verbose diagnostic details")

    args = parser.parse_args()

    verifier = IndependentPackageVerifier(args.package)
    report = verifier.verify()

    if args.out:
        write_verification_report(report, args.out)

    if args.json:
        print(report.to_json())
    else:
        print(format_human_report(report))

    return report.exit_code


if __name__ == "__main__":
    sys.exit(main())
