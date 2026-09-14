"""
DREX-V2 Phase 8 Forensic Acceptance Runner
===========================================
Runs real producer package verification and all 17 adversarial vectors with
strict target existence assertions.
"""

import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path
from typing import Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from certificate_engine import (
    CertificateMethodInfo,
    CertificateTargetInfo,
    CertificateVerificationInfo,
    ForensicCertificateEngine,
)
import drex_verify
from forensic_vault import (
    CasePackageManager,
    EvidenceSourceType,
    ForensicCaseManager,
    TimelineEventType,
    canonical_json_bytes,
)


def generate_real_producer_package(base_dir: Path) -> Tuple[Path, str]:
    vault_base = base_dir / "vault_base"
    mgr = ForensicCaseManager(vault_base)
    case = mgr.create_case("CASE-2026-REAL01", "Real Producer Audit Case", "Lead Examiner", "Forensics Lab")

    # 1. Register evidence
    ev_file = base_dir / "target_disk.img"
    ev_file.write_bytes(b"GENUINE FORENSIC EVIDENCE STREAM DATA" * 200)
    ev_source = mgr.register_evidence(case.case_id, EvidenceSourceType.FILE, str(ev_file), "Lead Examiner")

    # 2. Record operational events
    op_id = "OP-SAN-REAL01"
    mgr.record_sanitization_event(case.case_id, op_id, ev_source.evidence_id, "Lead Examiner", TimelineEventType.SANITIZATION_STARTED, "Sanitization started")
    mgr.record_sanitization_event(case.case_id, op_id, ev_source.evidence_id, "Lead Examiner", TimelineEventType.SANITIZATION_COMPLETED, "Sanitization completed")

    # 3. Create certificate bound to latest audit hash
    chain = mgr.get_audit_chain(case.case_id)
    latest_audit_hash = chain[-1].current_hash

    target_info = CertificateTargetInfo(target_name="target_disk.img", target_type="FILE")
    method_info = CertificateMethodInfo(method_id=8, canonical_name="CSPRNG Random Overwrite")
    verif_info = CertificateVerificationInfo(primary_verification_method="EXACT_BYTE_READBACK", post_wipe_sha256="abcdef1234567890" * 4)

    cert = ForensicCertificateEngine.create_certificate(
        case_id=case.case_id,
        case_name=case.title,
        examiner_name=case.examiner,
        organization=case.organization,
        target_info=target_info,
        method_info=method_info,
        verification_info=verif_info,
        prior_audit_hash=latest_audit_hash,
    )

    cdir = mgr._case_path(case.case_id)
    certs_dir = cdir / "certificates"
    certs_dir.mkdir(parents=True, exist_ok=True)
    ForensicCertificateEngine.export_json(cert, certs_dir / f"{cert.certificate_id}.json")
    mgr.record_certificate_event(case.case_id, cert.certificate_id, op_id, ev_source.evidence_id, "Lead Examiner", TimelineEventType.CERTIFICATE_CREATED, "Cert created")

    # Export package
    pkg_tar = base_dir / "real_package.tar.gz"
    CasePackageManager.export_package(cdir, pkg_tar, schema_version="2.0")

    # Extract to directory for inspection & mutation
    unpacked_dir = base_dir / "unpacked_pkg"
    unpacked_dir.mkdir(parents=True, exist_ok=True)
    with tarfile.open(pkg_tar, "r:gz") as t:
        t.extractall(unpacked_dir)

    return unpacked_dir, case.case_id


def run_verifier_cli(pkg_path: Path):
    verifier_py = Path(__file__).resolve().parent.parent / "drex_verify.py"
    cmd = [sys.executable, str(verifier_py), str(pkg_path), "--json"]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    try:
        report = json.loads(proc.stdout)
        verdict = report.get("final_verdict", "UNKNOWN")
    except Exception:
        verdict = "CLI_OUTPUT_PARSE_ERROR"
    return proc.returncode, verdict, proc.stdout, proc.stderr


def update_manifest_hashes(target_root: Path):
    mf = target_root / "manifest.json"
    mdata = json.loads(mf.read_text(encoding="utf-8"))
    for o in mdata.get("objects", []):
        fp = target_root / o["relative_path"]
        if fp.is_file():
            sha, sz = drex_verify.hash_file_streaming(fp)
            o["sha256"] = sha
            o["size_bytes"] = sz
    mb = drex_verify.canonical_json_bytes(mdata)
    mf.write_bytes(mb)
    (target_root / "manifest.sha256").write_text(f"{drex_verify.hash_bytes_sha256(mb)}  manifest.json\n")


def test_real_package_and_adversarial_matrix(tmp_path: Path):
    root = tmp_path
    unpacked, case_id = generate_real_producer_package(root)

    print("\n=== REAL PACKAGE MEMBER TREE ===")
    members = []
    for p in sorted(unpacked.rglob("*")):
        if p.is_file():
            rel = p.relative_to(unpacked).as_posix()
            members.append(rel)
            print(f"  {rel}")

    m_data = json.loads((unpacked / "manifest.json").read_text(encoding="utf-8"))
    print(f"\nmanifest_version: {m_data.get('schema_version')}")
    print(f"package_id: {m_data.get('package_id')}")
    print(f"case_id: {m_data.get('case_id')}")
    print(f"total declared objects: {len(m_data.get('objects', []))}")
    for obj in m_data.get("objects", []):
        print(f"  Declared object: {obj.get('relative_path')} ({obj.get('size_bytes')} bytes)")

    # Assert 7 properties from Section 3
    declared_paths = {obj["relative_path"] for obj in m_data.get("objects", [])}
    # 1. Every declared object exists
    for d_path in declared_paths:
        assert (unpacked / d_path).is_file(), f"Declared object {d_path} does not exist"
    # 2. Every non-structural package file is declared
    structural_files = {"manifest.json", "manifest.sha256", "README.txt", "readme.txt"}
    for member in members:
        if member not in structural_files:
            assert member in declared_paths, f"Non-structural file {member} not declared in manifest"
    # 3. manifest.json does not declare itself
    assert "manifest.json" not in declared_paths
    # 4. manifest.sha256 does not declare itself
    assert "manifest.sha256" not in declared_paths
    # 5. verification reports not recursively included
    for d_path in declared_paths:
        assert "verification_report" not in d_path
    # 6. No undeclared object exists
    for member in members:
        assert member in structural_files or member in declared_paths
    # 7. Verifier returns PASS for untouched package
    rc, verd, out, err = run_verifier_cli(unpacked)
    print(f"\nUntouched Package Verification: exit_code={rc}, verdict={verd}")
    assert rc == 0 and verd == "PASS", f"Untouched package failed verification: rc={rc}, verd={verd}, err={err}"

    print("\n=== RUNNING 17 ADVERSARIAL VECTORS AGAINST REAL PACKAGE ===")
    matrix = {}

    # A. One-byte evidence modification
    dir_a = root / "vec_A"
    shutil.copytree(unpacked, dir_a)
    target_a = dir_a / "case.json"
    assert target_a.is_file(), "Target case.json missing before mutation"
    b_data = bytearray(target_a.read_bytes())
    b_data[0] ^= 0xFF
    target_a.write_bytes(bytes(b_data))
    rc, verd, _, _ = run_verifier_cli(dir_a)
    matrix["A. One-byte evidence modification"] = (rc, verd, "TAMPERED", 1)

    # B. Evidence deletion
    dir_b = root / "vec_B"
    shutil.copytree(unpacked, dir_b)
    target_b = dir_b / "evidence.json"
    assert target_b.is_file(), "Target evidence.json missing before deletion"
    target_b.unlink()
    rc, verd, _, _ = run_verifier_cli(dir_b)
    matrix["B. Evidence deletion"] = (rc, verd, "INCOMPLETE", 2)

    # C. Manifest size modification
    dir_c = root / "vec_C"
    shutil.copytree(unpacked, dir_c)
    m_file = dir_c / "manifest.json"
    assert m_file.is_file(), "manifest.json missing"
    mdata = json.loads(m_file.read_text(encoding="utf-8"))
    assert len(mdata["objects"]) > 0, "No objects in manifest"
    mdata["objects"][0]["size_bytes"] += 9999
    m_bytes = drex_verify.canonical_json_bytes(mdata)
    m_file.write_bytes(m_bytes)
    (dir_c / "manifest.sha256").write_text(f"{drex_verify.hash_bytes_sha256(m_bytes)}  manifest.json\n")
    rc, verd, _, _ = run_verifier_cli(dir_c)
    matrix["C. Manifest size modification"] = (rc, verd, "TAMPERED", 1)

    # D. Manifest object hash modification
    dir_d = root / "vec_D"
    shutil.copytree(unpacked, dir_d)
    m_file = dir_d / "manifest.json"
    assert m_file.is_file(), "manifest.json missing"
    mdata = json.loads(m_file.read_text(encoding="utf-8"))
    assert len(mdata["objects"]) > 0, "No objects in manifest"
    mdata["objects"][0]["sha256"] = "0" * 64
    m_bytes = drex_verify.canonical_json_bytes(mdata)
    m_file.write_bytes(m_bytes)
    (dir_d / "manifest.sha256").write_text(f"{drex_verify.hash_bytes_sha256(m_bytes)}  manifest.json\n")
    rc, verd, _, _ = run_verifier_cli(dir_d)
    matrix["D. Manifest object hash modification"] = (rc, verd, "TAMPERED", 1)

    # E. manifest.sha256 modification
    dir_e = root / "vec_E"
    shutil.copytree(unpacked, dir_e)
    assert (dir_e / "manifest.sha256").is_file(), "manifest.sha256 missing before mutation"
    (dir_e / "manifest.sha256").write_text(f"{'f'*64}  manifest.json\n")
    rc, verd, _, _ = run_verifier_cli(dir_e)
    matrix["E. manifest.sha256 modification"] = (rc, verd, "TAMPERED", 1)

    # F. Audit payload modification
    dir_f = root / "vec_F"
    shutil.copytree(unpacked, dir_f)
    a_file = dir_f / "audit" / "audit_chain.json"
    assert a_file.is_file(), "Target audit file missing before mutation"
    events = json.loads(a_file.read_text(encoding="utf-8"))
    assert len(events) > 0, "Audit ledger empty"
    events[0]["canonical_payload"]["tampered_key"] = "tampered_val"
    a_file.write_text(json.dumps(events), encoding="utf-8")
    update_manifest_hashes(dir_f)
    rc, verd, _, _ = run_verifier_cli(dir_f)
    matrix["F. Audit payload modification"] = (rc, verd, "TAMPERED", 1)

    # G. Audit previous_hash modification
    dir_g = root / "vec_G"
    shutil.copytree(unpacked, dir_g)
    a_file = dir_g / "audit" / "audit_chain.json"
    assert a_file.is_file(), "Target audit file missing before mutation"
    events = json.loads(a_file.read_text(encoding="utf-8"))
    assert len(events) > 0, "Audit ledger empty"
    events[0]["previous_hash"] = "f" * 64
    a_file.write_text(json.dumps(events), encoding="utf-8")
    update_manifest_hashes(dir_g)
    rc, verd, _, _ = run_verifier_cli(dir_g)
    matrix["G. Audit previous_hash modification"] = (rc, verd, "TAMPERED", 1)

    # H. Audit event deletion
    dir_h = root / "vec_H"
    shutil.copytree(unpacked, dir_h)
    a_file = dir_h / "audit" / "audit_chain.json"
    assert a_file.is_file(), "Target audit file missing before mutation"
    events = json.loads(a_file.read_text(encoding="utf-8"))
    assert len(events) >= 2, "Not enough audit events to delete one"
    events.pop(1)
    a_file.write_text(json.dumps(events), encoding="utf-8")
    update_manifest_hashes(dir_h)
    rc, verd, _, _ = run_verifier_cli(dir_h)
    matrix["H. Audit event deletion"] = (rc, verd, "TAMPERED", 1)

    # I. Audit event reorder
    dir_i = root / "vec_I"
    shutil.copytree(unpacked, dir_i)
    a_file = dir_i / "audit" / "audit_chain.json"
    assert a_file.is_file(), "Target audit file missing before mutation"
    events = json.loads(a_file.read_text(encoding="utf-8"))
    assert len(events) >= 2, "Not enough audit events to reorder"
    events[0], events[1] = events[1], events[0]
    a_file.write_text(json.dumps(events), encoding="utf-8")
    update_manifest_hashes(dir_i)
    rc, verd, _, _ = run_verifier_cli(dir_i)
    matrix["I. Audit event reorder"] = (rc, verd, "TAMPERED", 1)

    # J. Custody modification
    dir_j = root / "vec_J"
    shutil.copytree(unpacked, dir_j)
    c_file = dir_j / "custody.json"
    assert c_file.is_file(), "Target custody file missing before mutation"
    cust = json.loads(c_file.read_text(encoding="utf-8"))
    assert len(cust) > 0, "Custody records empty"
    cust[0]["custodian"] = "Attacker"
    c_file.write_text(json.dumps(cust), encoding="utf-8")
    update_manifest_hashes(dir_j)
    rc, verd, _, _ = run_verifier_cli(dir_j)
    matrix["J. Custody modification"] = (rc, verd, "TAMPERED", 1)

    # K. Certificate modification
    dir_k = root / "vec_K"
    shutil.copytree(unpacked, dir_k)
    cert_files = list((dir_k / "certificates").glob("*.json"))
    assert len(cert_files) > 0, "No certificate file found in real package before mutation"
    c_data = json.loads(cert_files[0].read_text(encoding="utf-8"))
    c_data["method"]["method_id"] = 99
    cert_files[0].write_text(json.dumps(c_data), encoding="utf-8")
    update_manifest_hashes(dir_k)
    rc, verd, _, _ = run_verifier_cli(dir_k)
    matrix["K. Certificate modification"] = (rc, verd, "TAMPERED", 1)

    # L. Cross-link modification
    dir_l = root / "vec_L"
    shutil.copytree(unpacked, dir_l)
    mf = dir_l / "manifest.json"
    assert mf.is_file(), "manifest.json missing before mutation"
    mdata = json.loads(mf.read_text(encoding="utf-8"))
    mdata["case_id"] = "CASE-WRONG-8888"
    mb = drex_verify.canonical_json_bytes(mdata)
    mf.write_bytes(mb)
    (dir_l / "manifest.sha256").write_text(f"{drex_verify.hash_bytes_sha256(mb)}  manifest.json\n")
    rc, verd, _, _ = run_verifier_cli(dir_l)
    matrix["L. Cross-link modification"] = (rc, verd, "TAMPERED", 1)

    # M. Undeclared file insertion
    dir_m = root / "vec_M"
    shutil.copytree(unpacked, dir_m)
    (dir_m / "untracked_extra.bin").write_bytes(b"UNTRACKED PAYLOAD")
    rc, verd, _, _ = run_verifier_cli(dir_m)
    matrix["M. Undeclared file insertion"] = (rc, verd, "TAMPERED", 1)

    # N. Missing structural file (manifest.json missing)
    dir_n = root / "vec_N"
    shutil.copytree(unpacked, dir_n)
    assert (dir_n / "manifest.json").is_file(), "manifest.json missing before deletion"
    (dir_n / "manifest.json").unlink()
    rc, verd, _, _ = run_verifier_cli(dir_n)
    matrix["N. Missing structural file (manifest.json)"] = (rc, verd, "INVALID", 3)

    # O. Future schema (3.0)
    dir_o = root / "vec_O"
    shutil.copytree(unpacked, dir_o)
    mf = dir_o / "manifest.json"
    assert mf.is_file(), "manifest.json missing before mutation"
    mdata = json.loads(mf.read_text(encoding="utf-8"))
    mdata["schema_version"] = "3.0"
    mb = drex_verify.canonical_json_bytes(mdata)
    mf.write_bytes(mb)
    (dir_o / "manifest.sha256").write_text(f"{drex_verify.hash_bytes_sha256(mb)}  manifest.json\n")
    rc, verd, _, _ = run_verifier_cli(dir_o)
    matrix["O. Future schema (3.0)"] = (rc, verd, "INDETERMINATE", 4)

    # P. Malformed schema (broken json)
    dir_p = root / "vec_P"
    shutil.copytree(unpacked, dir_p)
    assert (dir_p / "manifest.json").is_file(), "manifest.json missing before corruption"
    (dir_p / "manifest.json").write_text('{"schema_version": ', encoding="utf-8")
    (dir_p / "manifest.sha256").write_text(f"{drex_verify.hash_bytes_sha256(b'{\"schema_version\": ')}  manifest.json\n")
    rc, verd, _, _ = run_verifier_cli(dir_p)
    matrix["P. Malformed schema"] = (rc, verd, "INVALID", 3)

    # Q. Unsafe archive path
    tar_q = root / "evil.tar"
    with tarfile.open(tar_q, "w") as t:
        ti = tarfile.TarInfo(name="../../evil_escape.txt")
        data = b"malicious"
        ti.size = len(data)
        t.addfile(ti, io.BytesIO(data))
    rc, verd, _, _ = run_verifier_cli(tar_q)
    matrix["Q. Unsafe archive path"] = (rc, verd, "INVALID", 3)

    for vec, (rc, verd, exp_v, exp_rc) in matrix.items():
        status = "MATCH" if (verd == exp_v and rc == exp_rc) else "MISMATCH"
        print(f"{vec}: ExitCode={rc} (Exp: {exp_rc}), Verdict={verd} (Exp: {exp_v}) -> {status}")
        assert verd == exp_v and rc == exp_rc, f"{vec} failed: got rc={rc}, verd={verd}, expected rc={exp_rc}, verd={exp_v}"

    print("\nALL 17 ADVERSARIAL VECTORS AGAINST REAL PRODUCER PACKAGE PASSED!")


if __name__ == "__main__":
    with tempfile.TemporaryDirectory() as td:
        test_real_package_and_adversarial_matrix(Path(td))
