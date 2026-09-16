"""
DREX-V2 — Phase 22 Final Acceptance: Real Telemetry Demonstration
Executes real sanitization on disposable test target and logs every runtime telemetry frame:
- processed_bytes=0, percent_complete=null
- first positive write triggering 0.01% floor
- 100% writing -> VERIFYING -> SEALING -> VERIFIED
"""
import os
import sys
import time
import json
import uuid
import tempfile
from pathlib import Path

# Add project root
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from drex_server import app, case_manager, job_registry
from fastapi.testclient import TestClient

def run_real_telemetry_demo():
    client = TestClient(app)

    # 1. Switch persona to ADMIN
    res_auth = client.post("/api/auth/switch-persona", json={"target_role": "ADMIN"})
    assert res_auth.status_code == 200
    token = res_auth.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    tmp_dir = Path(tempfile.mkdtemp(prefix="drex_telemetry_demo_"))
    try:
        # Create disposable target (4 MB)
        target_file = tmp_dir / "disposable_target_4mb.bin"
        target_size = 4 * 1024 * 1024  # 4,194,304 bytes
        target_file.write_bytes(b"\xAA" * target_size)

        # Create test case
        case_res = client.post("/api/cases", json={
            "case_number": f"CASE-TEL-{uuid.uuid4().hex[:6].upper()}",
            "title": "Real Telemetry Demonstration",
            "examiner": "Forensic Telemetry Lead",
            "organization": "NTRO Forensic Workstation",
        }, headers=headers)
        case_id = case_res.json()["case_id"]

        # Compute exact safety confirmation phrase
        clean_target = str(target_file).replace("\\", "_").replace("/", "_").replace(".", "_").strip("_").upper()
        phrase = f"ERASE-{clean_target}-PERMANENT"

        # Dispatch async sanitization
        exec_res = client.post("/api/sanitization/execute", json={
            "case_id": case_id,
            "target_path": str(target_file),
            "method_id": 8,  # CSPRNG Multi-Pass Overwrite
            "safety_phrase_entered": phrase,
            "async_execution": True,
        }, headers=headers)

        assert exec_res.status_code == 200, f"Execution failed: {exec_res.text}"
        job_data = exec_res.json()
        job_id = job_data["job_id"]

        telemetry_log = []
        start_time = time.time()
        timeout = 30.0

        # Poll telemetry at high resolution
        last_frame = None
        while time.time() - start_time < timeout:
            status_res = client.get(f"/api/jobs/{job_id}?case_id={case_id}", headers=headers)
            if status_res.status_code == 200:
                rec = status_res.json()
                current_frame = {
                    "timestamp_offset_ms": round((time.time() - start_time) * 1000, 1),
                    "status": rec.get("status"),
                    "phase": rec.get("phase"),
                    "processed_bytes": rec.get("processed_bytes"),
                    "total_bytes": rec.get("total_bytes"),
                    "percent_complete": rec.get("percent_complete"),
                    "verification_state": rec.get("verification_state"),
                }

                # Deduplicate consecutive identical frames
                frame_key = (
                    current_frame["phase"],
                    current_frame["processed_bytes"],
                    current_frame["percent_complete"],
                    current_frame["verification_state"],
                    current_frame["status"]
                )
                if frame_key != last_frame:
                    telemetry_log.append(current_frame)
                    last_frame = frame_key

                if rec.get("status") in ("COMPLETED", "FAILED", "CANCELLED"):
                    break

            time.sleep(0.005)

        print("\n" + "="*80)
        print("REAL TELEMETRY DEMONSTRATION RUNTIME CAPTURE")
        print("="*80)
        for idx, f in enumerate(telemetry_log):
            pct_str = f"{f['percent_complete']}%" if f['percent_complete'] is not None else "null"
            print(f"[{f['timestamp_offset_ms']:>6} ms] Frame {idx:>2} | Status: {f['status']:<10} | Phase: {str(f['phase']):<12} | "
                  f"Bytes: {f['processed_bytes']:>8} / {f['total_bytes']} | Progress: {pct_str:<7} | Verification: {f['verification_state']}")

        return telemetry_log

    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)

if __name__ == "__main__":
    import shutil
    run_real_telemetry_demo()
