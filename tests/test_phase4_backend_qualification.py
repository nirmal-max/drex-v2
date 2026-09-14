"""
DREX-V2 Phase 4 Hardening: Forensic Recovery Backend Qualification Test Suite
=============================================================================
Tests mature forensic recovery engines (The Sleuth Kit 4.15.0, PhotoRec 7.2 fidentify)
as execution engines, and DREX custom format validators and forensic vault as the
independent assurance and validation layer.

Test Categories Covered:
A. Backend discovery
B. Backend version capture
C. Backend invocation safety
D. Source immutability (ΔHash == 0, ΔSize == 0)
E. Destination isolation & path safety
F. Known-answer recovery (FAT32, Ext4, NTFS)
G. SHA-256 byte-for-byte verification (EXPECTED == RECOVERED)
H. TSK differential validation
I. DREX independent format validation
J. ForensicVault persistence
K. Audit-chain registration & tamper detection
L. Malformed backend output handling
M. Backend execution failure handling
N. Backend unavailable handling
O. Timeout and resource bounds
P. Unsafe target rejection
"""

import hashlib
import json
import os
import struct
import subprocess
import tempfile
import time
from pathlib import Path
import pytest

from recovery_backends import (
    BACKENDS,
    METHOD_BACKENDS,
    backend_status,
    find_backend_executable,
)
from backend_adapters import (
    build_fls_command,
    build_icat_command,
    build_fsstat_command,
    build_tsk_recover_command,
    build_fidentify_command,
    parse_fidentify_output,
    CentralProcessRunner,
)
from recovery_adapter import (
    MatureBackendOrchestrator,
    BackendRecoveryExecution,
    RecoveredArtifactRecord,
    RecoveryError,
    RecoveryTarget,
    TargetKind,
)
from validators import FormatRegistry, CandidateState
from forensic_vault import (
    ForensicCaseManager,
    ForensicCase,
    EvidenceVault,
    VaultObjectType,
    EvidenceSourceType,
    utc_now_iso,
)
from tests.test_fs_fat import create_synthetic_fat32_image
from tests.test_fs_ext import create_synthetic_ext4_image


ROOT_PATH = Path(".")
NATIVE_BIN = ROOT_PATH / "native_bin"


# ─── Category A: Backend Discovery ────────────────────────────────────────────

def test_category_a_backend_discovery():
    """Verify that all expected mature forensic recovery binaries are discovered in native_bin/."""
    tsk_exe = find_backend_executable("tsk", ROOT_PATH)
    assert tsk_exe is not None
    assert tsk_exe.is_file()

    photorec_exe = find_backend_executable("photorec", ROOT_PATH)
    assert photorec_exe is not None
    assert photorec_exe.is_file()

    # Direct check on key TSK binaries
    for binary_name in ["fls.exe", "icat.exe", "fsstat.exe", "mmls.exe", "tsk_recover.exe"]:
        p = NATIVE_BIN / binary_name
        assert p.is_file(), f"Missing required TSK binary: {binary_name}"


# ─── Category B: Backend Version Capture ──────────────────────────────────────

def test_category_b_backend_version_capture():
    """Verify exact version reporting for TSK (4.15.0) and PhotoRec fidentify (7.2)."""
    # TSK version probe
    fls_exe = NATIVE_BIN / "fls.exe"
    res_tsk = subprocess.run([str(fls_exe), "-V"], capture_output=True, text=True, timeout=10)
    assert res_tsk.returncode == 0
    assert "The Sleuth Kit ver 4.15.0" in res_tsk.stdout

    # PhotoRec fidentify version probe
    fidentify_exe = NATIVE_BIN / "fidentify_win.exe"
    res_fid = subprocess.run([str(fidentify_exe), "--version"], capture_output=True, text=True, timeout=10)
    assert res_fid.returncode == 0
    assert "fidentify 7.2" in res_fid.stdout
    assert "Christophe GRENIER" in res_fid.stdout


# ─── Category C: Backend Invocation Safety ────────────────────────────────────

def test_category_c_backend_invocation_safety():
    """Verify command building uses argument arrays and resists shell injection attempts."""
    rec_exe = NATIVE_BIN / "tsk_recover.exe"
    malicious_target = "image.raw; rm -rf /; calc.exe"
    cmd = build_tsk_recover_command(rec_exe, malicious_target, "output_dir", all_files=True)

    assert isinstance(cmd, list)
    assert cmd[0] == str(rec_exe)
    assert "-e" in cmd
    assert cmd[-2] == malicious_target
    assert cmd[-1] == "output_dir"
    # Ensure command is passed as an isolated token, not a concatenated shell string
    assert len(cmd) == 4


# ─── Category D: Source Immutability ──────────────────────────────────────────

def test_category_d_source_immutability():
    """Verify that backend recovery operations preserve source bit-for-bit (ΔHash == 0)."""
    image_bytes = create_synthetic_fat32_image()
    initial_hash = hashlib.sha256(image_bytes).hexdigest().upper()
    initial_size = len(image_bytes)

    with tempfile.TemporaryDirectory() as td:
        img_path = Path(td) / "immutability_test.raw"
        img_path.write_bytes(image_bytes)
        out_dir = Path(td) / "output"

        orchestrator = MatureBackendOrchestrator(root=ROOT_PATH)
        exec_res = orchestrator.recover_with_tsk(img_path, out_dir, all_files=True)

        assert exec_res.source_immutable is True
        assert exec_res.source_sha256_before == initial_hash
        assert exec_res.source_sha256_after == initial_hash
        assert exec_res.source_size_before == initial_size
        assert exec_res.source_size_after == initial_size

        # Direct readback verification
        after_bytes = img_path.read_bytes()
        assert hashlib.sha256(after_bytes).hexdigest().upper() == initial_hash


# ─── Category E: Destination Isolation ────────────────────────────────────────

def test_category_e_destination_isolation():
    """Verify strict rejection of unsafe destination paths (overlap, identical, subpath)."""
    orchestrator = MatureBackendOrchestrator(root=ROOT_PATH)

    with tempfile.TemporaryDirectory() as td:
        src_file = Path(td) / "source.img"
        src_file.write_bytes(b"\x00" * 1024)

        # 1. Identical path
        with pytest.raises(RecoveryError, match="Destination cannot be identical"):
            orchestrator.validate_safety(src_file, src_file)

        # 2. Destination inside source directory (when source is dir)
        src_dir = Path(td) / "src_dir"
        src_dir.mkdir()
        dest_inside = src_dir / "nested_output"
        with pytest.raises(RecoveryError, match="cannot reside inside the source"):
            orchestrator.validate_safety(src_dir, dest_inside)


# ─── Category F & G: Known-Answer Recovery & SHA-256 Verification ──────────────

def test_category_f_g_known_answer_fat32_recovery():
    """Known-Answer Recovery: Run tsk_recover against FAT32 image with known files and verify SHA-256."""
    image_bytes = create_synthetic_fat32_image()

    with tempfile.TemporaryDirectory() as td:
        img_path = Path(td) / "fat32.img"
        img_path.write_bytes(image_bytes)
        out_dir = Path(td) / "recovered"

        orchestrator = MatureBackendOrchestrator(root=ROOT_PATH)
        exec_res = orchestrator.recover_with_tsk(img_path, out_dir, all_files=True)

        assert exec_res.success is True
        assert len(exec_res.artifacts) >= 3

        # Locate known recovered document
        doc_artifact = next((a for a in exec_res.artifacts if "Forensic" in a.filename), None)
        assert doc_artifact is not None
        assert doc_artifact.size_bytes == 610
        assert doc_artifact.execution_type == "REAL"
        assert "The Sleuth Kit" in doc_artifact.backend

        # Verify byte content of recovered artifact
        recovered_data = doc_artifact.artifact_path.read_bytes()
        assert hashlib.sha256(recovered_data).hexdigest().upper() == doc_artifact.sha256
        assert b"ACTIVE_CONFIDENTIAL_FORENSIC_DOCUMENT" in recovered_data


def test_category_f_g_known_answer_ext4_recovery():
    """Known-Answer Recovery: Run tsk_recover against EXT4 image with known orphan files."""
    ext_bytes = bytearray(create_synthetic_ext4_image())
    struct.pack_into("<I", ext_bytes, 1024 + 28, 2)  # s_log_frag_size = 2

    with tempfile.TemporaryDirectory() as td:
        img_path = Path(td) / "ext4.img"
        img_path.write_bytes(ext_bytes)
        out_dir = Path(td) / "recovered"

        orchestrator = MatureBackendOrchestrator(root=ROOT_PATH)
        exec_res = orchestrator.recover_with_tsk(img_path, out_dir, all_files=True)

        assert exec_res.success is True
        assert len(exec_res.artifacts) >= 3

        # Check orphan file recovery
        orphan_11 = next((a for a in exec_res.artifacts if "OrphanFile-11" in a.filename), None)
        assert orphan_11 is not None
        assert orphan_11.size_bytes == 1200
        recovered_data = orphan_11.artifact_path.read_bytes()
        assert hashlib.sha256(recovered_data).hexdigest().upper() == orphan_11.sha256
        assert b"EXT4_EXTENT_TREE_ACTIVE_FILE_CONTENT" in recovered_data


# ─── Category H: TSK Differential Validation ──────────────────────────────────

def test_category_h_tsk_differential_validation():
    """Verify that DifferentialValidator comparisons execute live without mocking."""
    from fs_base import DiskImageSource
    from fs_differential import DifferentialValidator, DifferentialValidationOutcome
    image_bytes = create_synthetic_fat32_image()

    with tempfile.TemporaryDirectory() as td:
        img_path = Path(td) / "fat32.img"
        img_path.write_bytes(image_bytes)

        source = DiskImageSource(img_path)
        rec = DifferentialValidator.cross_validate(source, root_path=ROOT_PATH)
        assert rec.outcome == DifferentialValidationOutcome.EXACT_MATCH
        source.close()


# ─── Category I: DREX Independent Format Validation ───────────────────────────

def test_category_i_drex_independent_validation():
    """Verify that artifacts recovered by mature backends undergo independent structural validation."""
    with tempfile.TemporaryDirectory() as td:
        td_path = Path(td)
        # Create genuine sample files
        jpg_data = (
            b"\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
            b"\xFF\xDB\x00C\x00" + b"\x00" * 64 +
            b"\xFF\xC0\x00\x0B\x08\x00\x01\x00\x01\x01\x01\x11\x00"
            b"\xFF\xDA\x00\x08\x01\x01\x00\x00?\x00\xBF\x00\xFF\xD9"
        )
        import zlib
        ihdr_data = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
        ihdr_chunk = struct.pack(">I", len(ihdr_data)) + b"IHDR" + ihdr_data + struct.pack(">I", zlib.crc32(b"IHDR" + ihdr_data))
        raw_scanlines = b"\x00\xff\x00\x00"
        idat_data = zlib.compress(raw_scanlines)
        idat_chunk = struct.pack(">I", len(idat_data)) + b"IDAT" + idat_data + struct.pack(">I", zlib.crc32(b"IDAT" + idat_data))
        iend_chunk = struct.pack(">I", 0) + b"IEND" + struct.pack(">I", zlib.crc32(b"IEND"))
        png_data = b"\x89PNG\r\n\x1a\n" + ihdr_chunk + idat_chunk + iend_chunk

        pdf_data = (
            b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\nxref\n0 2\n"
            b"0000000000 65535 f \n0000000009 00000 n \n"
            b"trailer\n<< /Size 2 /Root 1 0 R >>\nstartxref\n32\n%%EOF\n"
        )

        (td_path / "photo.jpg").write_bytes(jpg_data)
        (td_path / "chart.png").write_bytes(png_data)
        (td_path / "report.pdf").write_bytes(pdf_data)

        # 1. Independent validation via FormatRegistry
        val_jpg = FormatRegistry.validate_buffer("JPEG", jpg_data)
        assert val_jpg.is_valid is True
        assert val_jpg.state == CandidateState.RECOVERED_ARTIFACT

        val_png = FormatRegistry.validate_buffer("PNG", png_data)
        assert val_png.is_valid is True

        val_pdf = FormatRegistry.validate_buffer("PDF", pdf_data)
        assert val_pdf.is_valid is True

        # 2. PhotoRec fidentify validation
        orchestrator = MatureBackendOrchestrator(root=ROOT_PATH)
        fid_results = orchestrator.identify_with_fidentify(td_path)
        assert len(fid_results) >= 3
        formats_found = {r["format"] for r in fid_results}
        assert "jpg" in formats_found
        assert "png" in formats_found
        assert "pdf" in formats_found


# ─── Category J & K: ForensicVault Persistence & Audit Ledger ─────────────────

def test_category_j_k_vault_persistence_and_audit():
    """Verify that backend recovered artifacts are stored in EvidenceVault with cryptographically hash-linked audit ledger."""
    image_bytes = create_synthetic_fat32_image()

    with tempfile.TemporaryDirectory() as td:
        root_td = Path(td)
        img_path = root_td / "source.img"
        img_path.write_bytes(image_bytes)
        rec_dir = root_td / "recovered"
        case_dir = root_td / "cases"

        # Initialize Forensic Case & Vault
        case_mgr = ForensicCaseManager(base_data_dir=case_dir)
        case = case_mgr.create_case(case_number="CASE-QUAL-01", title="Phase 4 Backend Qualification", examiner="Examiner A", organization="DREX Lab")
        vault = EvidenceVault(case_mgr._case_path(case.case_id))

        orchestrator = MatureBackendOrchestrator(root=ROOT_PATH)
        exec_res = orchestrator.recover_with_tsk(
            img_path, rec_dir, all_files=True, case=case, vault=vault, case_mgr=case_mgr
        )

        assert exec_res.success is True
        assert len(exec_res.artifacts) >= 1

        # Check vault persistence
        vault_objs = vault.list_objects()
        assert len(vault_objs) == len(exec_res.artifacts)

        # Check audit trail integrity
        audits = case_mgr.get_audit_chain(case.case_id)
        assert len(audits) >= 1
        res = case_mgr.verify_case_audit_chain(case.case_id)
        assert res.status.value == "VALID"


# ─── Category L: Malformed Backend Output Handling ────────────────────────────

def test_category_l_malformed_backend_output_handling():
    """Verify that non-standard or malformed backend outputs are parsed safely without crashing."""
    from backend_adapters import parse_fls_output, parse_fidentify_output, parse_fsstat_output

    # Malformed fls output lines
    fls_malformed = "not a valid line\n?? missing colons\nr/r * 123:\n"
    cands = parse_fls_output(fls_malformed)
    assert isinstance(cands, list)

    # Malformed fidentify output
    fid_malformed = "no colon line\npath.txt: \nunknown: unknown\n"
    fid_res = parse_fidentify_output(fid_malformed)
    assert isinstance(fid_res, list)

    # Malformed fsstat output
    fsstat_malformed = "GARBAGE DATA\nNOT FSSTAT"
    fsstat_res = parse_fsstat_output(fsstat_malformed)
    assert "raw" in fsstat_res


# ─── Category M: Backend Failure Handling ─────────────────────────────────────

def test_category_m_backend_failure_handling():
    """Verify that backend execution on non-filesystem random noise fails cleanly."""
    with tempfile.TemporaryDirectory() as td:
        garbage_img = Path(td) / "garbage.raw"
        garbage_img.write_bytes(os.urandom(65536))
        out_dir = Path(td) / "recovered"

        orchestrator = MatureBackendOrchestrator(root=ROOT_PATH)
        exec_res = orchestrator.recover_with_tsk(garbage_img, out_dir)

        # tsk_recover should fail on random noise (cannot determine filesystem)
        assert exec_res.exit_code != 0
        assert len(exec_res.artifacts) == 0


# ─── Category N: Backend Unavailable Handling ─────────────────────────────────

def test_category_n_backend_unavailable_handling():
    """Verify that missing backend executables raise clear RecoveryError."""
    fake_root = Path("non_existent_directory_12345")
    orchestrator = MatureBackendOrchestrator(root=fake_root)

    with tempfile.TemporaryDirectory() as td:
        dummy_file = Path(td) / "dummy.raw"
        dummy_file.write_bytes(b"DATA")
        out_dir = Path(td) / "out"

        with pytest.raises(RecoveryError, match="executables not found"):
            orchestrator.recover_with_tsk(dummy_file, out_dir)


# ─── Category O: Timeout and Resource Bounds ──────────────────────────────────

def test_category_o_timeout_and_resource_bounds():
    """Verify that process execution respects timeout parameters."""
    rec_exe = NATIVE_BIN / "fls.exe"
    # Execute on non-existent file with short timeout
    cmd = [str(rec_exe), "-r", "non_existent_image.raw"]
    res = CentralProcessRunner.run(cmd, timeout=5)
    assert isinstance(res.exit_code, int)
    assert res.duration_seconds < 5.0


# ─── Category P: Unsafe Target Rejection ──────────────────────────────────────

def test_category_p_unsafe_target_rejection():
    """Verify that non-existent or empty target paths are rejected immediately."""
    orchestrator = MatureBackendOrchestrator(root=ROOT_PATH)

    with pytest.raises(RecoveryError, match="cannot be empty"):
        orchestrator.validate_safety("", Path("out"))

    with pytest.raises(RecoveryError, match="does not exist"):
        orchestrator.validate_safety("completely_fake_image_file_987654.dd", Path("out"))
