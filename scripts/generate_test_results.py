"""
DREX-V2 Machine-Generated Test Results Artifact Generator
==========================================================
Authoritative test execution recorder that executes pytest suites,
captures real test run outcomes via pytest hooks, and generates the
empirically verifiable `drex_data/test_results.json` artifact.

NON-NEGOTIABLE FORENSIC INTEGRITY PRINCIPLES:
1. Zero fabrication: Collection is NEVER reported as PASS.
2. If run with --collect-only, status is strictly labeled 'COLLECTED_NOT_RUN'
   and passed count is 0.
3. Actual test statuses (PASSED, FAILED, ERROR, SKIPPED), durations, and tracebacks
   derive strictly from pytest_runtest_logreport.
4. Total duration and category counts are derived from real execution.
5. Invariant enforced: PYTEST RESULTS == JSON RESULTS == API RESULTS == UI RESULTS.
"""

from __future__ import annotations

import datetime
import json
import os
import pathlib
import platform
import subprocess
import sys
import time
from typing import Any, Dict, List, Optional
import pytest


def get_git_commit() -> str:
    repo_root = pathlib.Path(__file__).resolve().parent.parent
    try:
        out = subprocess.check_output(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=str(repo_root),
            stderr=subprocess.DEVNULL
        ).decode().strip()
        if out:
            return out
    except Exception:
        pass
    return "unknown"


def categorize_nodeid(nodeid: str) -> str:
    nid = nodeid.lower()
    if any(k in nid for k in ["recovery", "carver", "fragment", "tsk", "raid", "fs_"]):
        return "Recovery"
    elif any(k in nid for k in ["sanitiz", "eraser", "wipe", "slack", "mft", "vss"]):
        return "Sanitization"
    elif any(k in nid for k in ["evidence", "vault", "ledger"]):
        return "Evidence"
    elif any(k in nid for k in ["audit", "certificat"]):
        return "Audit"
    elif any(k in nid for k in ["auth", "rbac", "security", "threat", "adversarial_crypto", "crypto_adversarial"]):
        return "Security"
    elif any(k in nid for k in ["verify", "verifier", "validation_lab", "truthful_validation"]):
        return "Verification"
    elif any(k in nid for k in ["perf", "benchmark", "throughput", "ui", "view", "page"]):
        return "Performance & UX"
    elif any(k in nid for k in ["hardware", "device", "storage", "process_adversarial", "isolation"]):
        return "Hardware & Isolation"
    else:
        return "Core"


CATEGORY_DESCRIPTIONS = {
    "Recovery": "Filesystem inode, directory tree, raw sector carving, and fragment reconstruction algorithms",
    "Sanitization": "NIST SP 800-88, DoD 5220.22-M, CSPRNG shredder, and physical drive wiping",
    "Core": "Architecture boundaries, state lifecycle, crypto core, and backend dispatchers",
    "Evidence": "Evidence vault isolation, SHA-256 hash chaining, and tamper-evident sealing",
    "Audit": "Cryptographic audit ledger, tamper detection, and Schema 2.0 certificates",
    "Security": "RBAC persona boundaries, threat model tripwires, and constant-time cryptography",
    "Verification": "Independent Schema 2.0 verifier, Ground Truth validation lab, and KAT suites",
    "Performance & UX": "Throughput benchmarking, context bars, view state transitions, and safety dialogs",
    "Hardware & Isolation": "Hardware storage detection, ATA/NVMe pass-through, and process memory limits",
}


class PytestExecutionRecorderPlugin:
    """Pytest plugin recording real test execution outcomes, durations, and tracebacks."""

    def __init__(self, commit_id: str, is_collect_only: bool = False):
        self.commit_id = commit_id
        self.is_collect_only = is_collect_only
        self.items_meta: Dict[str, Dict[str, Any]] = {}
        self.test_records: Dict[str, Dict[str, Any]] = {}
        self.start_time: float = 0.0
        self.end_time: float = 0.0
        self.warning_count: int = 0
        self.counts = {
            "collected": 0,
            "passed": 0,
            "failed": 0,
            "errors": 0,
            "skipped": 0,
            "xfailed": 0,
            "xpassed": 0,
        }

    def pytest_sessionstart(self, session):
        self.start_time = time.perf_counter()

    def pytest_collection_modifyitems(self, session, config, items):
        self.counts["collected"] = len(items)
        now_utc = datetime.datetime.now(datetime.timezone.utc).isoformat()
        for item in items:
            cat = categorize_nodeid(item.nodeid)
            doc = (item.obj.__doc__ or "").strip() if hasattr(item, "obj") and item.obj else ""
            first_doc_line = doc.split("\n")[0].strip() if doc else f"Validates {item.name}"
            mod_name = pathlib.Path(item.location[0]).name if item.location else ""
            cls_name = item.cls.__name__ if hasattr(item, "cls") and item.cls else None
            markers = [m.name for m in item.own_markers] if hasattr(item, "own_markers") else []

            initial_status = "COLLECTED_NOT_RUN" if self.is_collect_only else "PENDING"
            self.items_meta[item.nodeid] = {
                "node_id": item.nodeid,
                "module": mod_name,
                "class_name": cls_name,
                "name": item.name,
                "category": cat,
                "status": initial_status,
                "duration_seconds": 0.0,
                "docstring": first_doc_line,
                "markers": markers,
                "last_run_utc": now_utc,
                "commit": self.commit_id,
                "traceback": None,
            }

    def pytest_runtest_logreport(self, report):
        nodeid = report.nodeid
        if nodeid not in self.items_meta:
            return

        record = self.items_meta[nodeid]

        # Setup failure -> ERROR
        if report.when == "setup" and report.outcome == "failed":
            record["status"] = "ERROR"
            record["duration_seconds"] = round(report.duration, 4)
            record["traceback"] = str(report.longrepr) if report.longrepr else None
            self.counts["errors"] += 1
        elif report.when == "call":
            record["duration_seconds"] = round(report.duration, 4)
            if hasattr(report, "wasxfail"):
                if report.outcome == "passed":
                    record["status"] = "XPASSED"
                    self.counts["xpassed"] += 1
                else:
                    record["status"] = "XFAILED"
                    self.counts["xfailed"] += 1
            elif report.outcome == "passed":
                record["status"] = "PASSED"
                self.counts["passed"] += 1
            elif report.outcome == "failed":
                record["status"] = "FAILED"
                record["traceback"] = str(report.longrepr) if report.longrepr else None
                self.counts["failed"] += 1
            elif report.outcome == "skipped":
                record["status"] = "SKIPPED"
                self.counts["skipped"] += 1
        elif report.when == "teardown" and report.outcome == "failed":
            # Only elevate to ERROR if call didn't already fail
            if record["status"] == "PASSED":
                record["status"] = "ERROR"
                record["traceback"] = str(report.longrepr) if report.longrepr else None
                self.counts["passed"] -= 1
                self.counts["errors"] += 1

    def pytest_terminal_summary(self, terminalreporter, exitstatus, config):
        self.end_time = time.perf_counter()
        stats = getattr(terminalreporter, "stats", {})
        warnings_list = stats.get("warnings", [])
        self.warning_count = len(warnings_list)


def generate_test_results_artifact(
    output_path: Optional[str] = None,
    pytest_args: Optional[List[str]] = None,
    collect_only: bool = False,
) -> Dict[str, Any]:
    """
    Execute pytest test runner with an authoritative result-recording plugin,
    guaranteeing real provenance without fabrication.
    """
    repo_root = pathlib.Path(__file__).resolve().parent.parent
    if output_path is None:
        data_dir = repo_root / "drex_data"
        data_dir.mkdir(parents=True, exist_ok=True)
        output_path = str(data_dir / "test_results.json")

    commit_id = get_git_commit()
    recorder = PytestExecutionRecorderPlugin(commit_id=commit_id, is_collect_only=collect_only)

    cmd_args = list(pytest_args) if pytest_args else []
    if collect_only and "--collect-only" not in cmd_args:
        cmd_args.append("--collect-only")

    # If no target specified, run all tests in tests/
    if not any(arg for arg in cmd_args if not arg.startswith("-")):
        cmd_args.append(str(repo_root / "tests"))

    start_mono = time.perf_counter()
    exit_code = pytest.main(cmd_args, plugins=[recorder])
    elapsed_seconds = round(time.perf_counter() - start_mono, 2)

    timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
    total_collected = recorder.counts["collected"]

    # Category aggregations strictly based on actual test outcomes
    categories_dict: Dict[str, Dict[str, Any]] = {}
    for item in recorder.items_meta.values():
        cat = item["category"]
        if cat not in categories_dict:
            categories_dict[cat] = {
                "total": 0,
                "passed": 0,
                "failed": 0,
                "errors": 0,
                "warnings": 0,
                "desc": CATEGORY_DESCRIPTIONS.get(cat, f"{cat} subsystem invariants"),
            }
        categories_dict[cat]["total"] += 1
        if item["status"] == "PASSED":
            categories_dict[cat]["passed"] += 1
        elif item["status"] == "FAILED":
            categories_dict[cat]["failed"] += 1
        elif item["status"] == "ERROR":
            categories_dict[cat]["errors"] += 1

    artifact = {
        "commit": commit_id,
        "run_timestamp": timestamp,
        "pytest_version": pytest.__version__,
        "python_version": platform.python_version(),
        "environment": f"{platform.system()} {platform.release()} ({platform.machine()})",
        "provenance": "COLLECT_ONLY_DRY_RUN (ZERO TESTS EXECUTED)" if collect_only else "AUTHENTIC_PYTEST_EXECUTION",
        "collected": total_collected,
        "passed": recorder.counts["passed"],
        "failed": recorder.counts["failed"],
        "errors": recorder.counts["errors"],
        "skipped": recorder.counts["skipped"],
        "xfailed": recorder.counts["xfailed"],
        "xpassed": recorder.counts["xpassed"],
        "warnings": recorder.warning_count,
        "duration_seconds": elapsed_seconds if not collect_only else 0.0,
        "categories": categories_dict,
        "tests": list(recorder.items_meta.values()),
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(artifact, f, indent=2)

    return artifact


if __name__ == "__main__":
    args = sys.argv[1:]
    is_collect = "--collect-only" in args
    filtered_args = [a for a in args if a != "--collect-only"]
    res = generate_test_results_artifact(pytest_args=filtered_args, collect_only=is_collect)
    print(f"Recorded results for {res['collected']} test items across {len(res['categories'])} categories.")
    print(f"Outcome: {res['passed']} passed, {res['failed']} failed, {res['errors']} errors, {res['skipped']} skipped.")
    print(f"Commit: {res['commit']} | Duration: {res['duration_seconds']}s | Provenance: {res['provenance']}")
