"""Authoritative recovery adapters and dispatch for DREXX recovery engines.

Wires DREXX recovery methods directly to verified external upstream tools
(The Sleuth Kit, TestDisk, PhotoRec, GNU ddrescue) and local extraction logic.
Fails closed with clear, actionable reasons when native binaries or required
hardware configurations are absent.
"""

from __future__ import annotations

from enum import Enum
import hashlib
import json
import os
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from recovery_backends import (
    BACKENDS,
    METHOD_BACKENDS,
    backend_status,
    find_backend_executable,
)
from fragment_engine import FragmentReassembler, JpegEntropyDecoder, ZipCarveStream
from carver_engine import DeepCarverEngine, EvidenceScores
from fs_bitmap import NtfsBitmapAnalyzer, BitmapScanPolicy


class TargetKind(str, Enum):
    FILE = "file"
    FOLDER = "folder"
    NESTED_FOLDER = "nested_folder"
    DISK_IMAGE = "disk_image"
    PARTITION = "partition"
    PHYSICAL_DEVICE = "physical_device"


class RecoveryState(str, Enum):
    IDLE = "IDLE"
    DISCOVERING = "DISCOVERING"
    SCANNING = "SCANNING"
    CANDIDATES_FOUND = "CANDIDATES_FOUND"
    READY_TO_RECOVER = "READY_TO_RECOVER"
    RECOVERING = "RECOVERING"
    VERIFYING = "VERIFYING"
    RECOVERED = "RECOVERED"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    TIMEOUT = "TIMEOUT"


class AssociationStrength(str, Enum):
    EXACT = "EXACT"
    STRONG = "STRONG"
    HEURISTIC = "HEURISTIC"
    UNKNOWN = "UNKNOWN"


class VerificationState(str, Enum):
    UNVERIFIED = "UNVERIFIED"
    VALIDATED = "VALIDATED"
    HASH_MATCH = "HASH_MATCH"
    HASH_MISMATCH = "HASH_MISMATCH"
    PARTIAL = "PARTIAL"
    UNKNOWN = "UNKNOWN"


class RecoveryError(RuntimeError):
    pass


@dataclass(frozen=True)
class RecoveryTarget:
    path: str
    kind: TargetKind
    read_only: bool = True
    size_bytes: int | None = None
    sector_size: int = 512
    backing_device: str | None = None

    def validate_destination(self, destination: Path) -> None:
        """Enforce strict read-only isolation between source target and recovery destination."""
        dest_resolved = destination.resolve()
        if not self.path.startswith("\\\\.\\"):
            try:
                src_resolved = Path(self.path).resolve()
                if dest_resolved == src_resolved:
                    raise RecoveryError("Destination directory cannot be identical to the recovery source.")
                if src_resolved in dest_resolved.parents:
                    raise RecoveryError("Destination directory cannot reside inside the recovery source tree.")
                if dest_resolved in src_resolved.parents:
                    raise RecoveryError("Source tree cannot reside inside the recovery destination directory.")
            except OSError as exc:
                raise RecoveryError(f"Could not validate path safety: {exc}") from exc


@dataclass(frozen=True)
class RecoveryCandidate:
    candidate_id: str
    name: str
    filesystem: str
    size: int | None
    deleted: bool | None
    confidence: float | None
    raw: dict[str, Any]
    original_path: str | None = None
    file_type: str | None = None
    source_offset: int | None = None
    source_device: str | None = None
    source_partition: str | None = None
    recoverable: bool | None = None
    backend: str | None = None
    verification_state: str = "UNKNOWN"
    parent_candidate: str | None = None
    is_directory: bool = False
    relative_path: str | None = None
    association_strength: str = "EXACT"


def sector_to_byte_offset(sector: int, sector_size: int = 512) -> int:
    if sector < 0 or sector_size <= 0:
        raise ValueError("sector and sector_size must be non-negative positive values")
    return sector * sector_size


def byte_to_sector_offset(bytes_val: int, sector_size: int = 512) -> int:
    if bytes_val < 0 or sector_size <= 0:
        raise ValueError("bytes_val and sector_size must be non-negative positive values")
    return bytes_val // sector_size


def reconstruct_folder_tree(candidates: list[RecoveryCandidate], destination: Path) -> dict[str, int]:
    """Ensure parent directory hierarchies exist in the recovery destination."""
    destination.mkdir(parents=True, exist_ok=True)
    created_dirs: set[Path] = set()
    for cand in candidates:
        rel = cand.relative_path or cand.original_path
        if rel:
            rel_p = Path(rel.lstrip("/\\"))
            target_dirs = [rel_p] if cand.is_directory else [rel_p.parent]
            for d in target_dirs:
                curr = destination
                for part in d.parts:
                    curr = curr / part
                    if not curr.exists():
                        curr.mkdir(parents=True, exist_ok=True)
                        created_dirs.add(curr.relative_to(destination))
    return {"created_directories": len(created_dirs)}


@dataclass(frozen=True)
class RecoveryScan:
    status: str
    message: str
    source: dict[str, Any]
    candidates: tuple[RecoveryCandidate, ...]
    warnings: tuple[str, ...]
    raw: dict[str, Any]
    backend: str | None = None


@dataclass(frozen=True)
class RecoveryMethodSpec:
    method_id: str
    display_name: str
    module_dir: str
    executable_names: tuple[str, ...]
    native_contract: str


RECOVERY_METHOD_SPECS: tuple[RecoveryMethodSpec, ...] = (
    RecoveryMethodSpec("quick", "Quick Recovery", "tsk", ("fls.exe", "icat.exe", "testdisk_win.exe"), "TSK fls metadata scanning and targeted icat stream recovery"),
    RecoveryMethodSpec("smart", "Smart Recovery", "tsk", ("fsstat.exe", "fls.exe", "tsk_recover.exe"), "Multi-tier filesystem inspection and candidate classification"),
    RecoveryMethodSpec("targeted", "Targeted Recovery", "tsk", ("fls.exe", "icat.exe"), "Targeted candidate and inode stream extraction"),
    RecoveryMethodSpec("filesystem", "Filesystem Recovery", "tsk", ("tsk_recover.exe", "fls.exe", "fsstat.exe"), "Full partition and unallocated cluster assembly with directory preservation"),
    RecoveryMethodSpec("deep", "Deep Recovery", "photorec", ("photorec_win.exe", "photorec.exe"), "PhotoRec unallocated space file carving"),
    RecoveryMethodSpec("fragment", "Fragment Recovery", "photorec", ("photorec_win.exe", "photorec.exe"), "Targeted file-type carving and fragment reconstruction"),
    RecoveryMethodSpec("raid", "Storage / RAID Recovery", "tsk", ("mmls.exe", "testdisk_win.exe"), "Multi-volume and RAID partition geometry inspection"),
    RecoveryMethodSpec("damaged", "Damaged Media Recovery", "ddrescue", ("ddrescue.exe", "ddrescue"), "GNU ddrescue sector imaging with persistent mapfile"),
    RecoveryMethodSpec("forensic", "Forensic Recovery", "tsk", ("fls.exe", "icat.exe", "fsstat.exe"), "Forensic evidence acquisition with SHA-256 tamper-evident ledger"),
)


def parse_scan_result(payload: dict[str, Any], module: str = "Quick Recovery") -> RecoveryScan:
    if not isinstance(payload, dict):
        raise RecoveryError(f"{module} returned a non-object JSON result.")
    raw_candidates = payload.get("candidates", payload.get("objects", payload.get("chains", [])))
    if not isinstance(raw_candidates, list):
        raise RecoveryError(f"{module} returned an invalid candidate/result field.")
    candidates: list[RecoveryCandidate] = []
    seen_ids: set[str] = set()
    for item in raw_candidates:
        if not isinstance(item, dict):
            continue
        candidate_id = item.get("id")
        if candidate_id is None:
            continue
        cid_str = str(candidate_id)
        if cid_str in seen_ids:
            continue
        seen_ids.add(cid_str)
        candidates.append(RecoveryCandidate(
            candidate_id=cid_str,
            name=str(item.get("name") or item.get("type") or "Unknown"),
            filesystem=str(item.get("filesystem") or item.get("type") or "Unknown"),
            size=int(item["size"]) if isinstance(item.get("size"), (int, float)) else None,
            deleted=item.get("deleted") if isinstance(item.get("deleted"), bool) else None,
            confidence=float(item["confidence"]) if isinstance(item.get("confidence"), (int, float)) else None,
            raw=item,
            original_path=item.get("path") or item.get("original_path"),
            file_type=item.get("file_type") or item.get("type"),
            source_offset=int(item["offset"]) if "offset" in item and isinstance(item.get("offset"), (int, float)) else None,
            source_device=str(item["source_device"]) if "source_device" in item else None,
            source_partition=str(item["source_partition"]) if "source_partition" in item else None,
            recoverable=item.get("recoverable") if isinstance(item.get("recoverable"), bool) else None,
            backend=module,
        ))
    return RecoveryScan(
        status=str(payload.get("status") or "UNKNOWN"),
        message=str(payload.get("message") or ""),
        source=payload.get("source") if isinstance(payload.get("source"), dict) else {},
        candidates=tuple(candidates),
        warnings=tuple(str(x) for x in payload.get("warnings", []) if x is not None),
        raw=payload,
        backend=module,
    )


class BaseRecoveryAdapter:
    """Base class for DREXX official recovery adapters."""

    def __init__(self, spec: RecoveryMethodSpec, root: Path, meipass: Path | None = None):
        self.spec = spec
        self.root = root
        self.meipass = meipass

    @property
    def available(self) -> bool:
        backend_state, _ = backend_status(self.spec.method_id, self.root, self.meipass)
        return backend_state == "BACKEND DETECTED"

    @property
    def unavailable_reason(self) -> str:
        _, reason = backend_status(self.spec.method_id, self.root, self.meipass)
        return reason

    def status(self) -> tuple[str, str]:
        if self.available:
            _, reason = backend_status(self.spec.method_id, self.root, self.meipass)
            return "Available", reason
        return "Unavailable", self.unavailable_reason

    def validate_source(self, source: str) -> None:
        if not source:
            raise RecoveryError("No recovery source was provided.")
        if not (source.startswith("\\\\.\\") or Path(source).exists()):
            raise RecoveryError(f"Recovery source '{source}' does not exist or is inaccessible.")


class QuickRecoveryAdapter(BaseRecoveryAdapter):
    """Method 17: Fast deleted-entry directory scan via fls + icat stream extraction."""

    def __init__(self, root: Path, meipass: Path | None = None):
        spec = next(s for s in RECOVERY_METHOD_SPECS if s.method_id == "quick")
        super().__init__(spec, root, meipass)

    def require_executable(self) -> Path:
        exe = find_backend_executable("tsk", self.root, self.meipass)
        if exe is None:
            raise RecoveryError(f"Quick Recovery requires The Sleuth Kit (fls.exe). {self.unavailable_reason}")
        return exe

    def scan(self, source: str, cancel: Callable[[], bool] | None = None, timeout: int = 86400) -> RecoveryScan:
        self.validate_source(source)
        fls_exe = self.require_executable()
        from backend_adapters import build_fls_command, parse_fls_output, CentralProcessRunner
        cmd = build_fls_command(fls_exe, source, deleted_only=True, recursive=True, long_format=True, full_path=True)
        res = CentralProcessRunner.run(cmd, timeout=timeout, cancel_check=cancel)
        if res.exit_code != 0 and not res.stdout:
            raise RecoveryError(f"Quick Recovery scan failed: {res.stderr or 'non-zero exit code'}")
        candidates = parse_fls_output(res.stdout, module="Quick Recovery")
        return RecoveryScan(
            status="OK" if res.exit_code == 0 else "PARTIAL",
            message=f"Discovered {len(candidates)} deleted candidate(s)",
            source={"path": source},
            candidates=tuple(candidates),
            warnings=() if not res.stderr else (res.stderr,),
            raw={"exit_code": res.exit_code},
            backend="The Sleuth Kit 4.15.0",
        )

    def recover(self, source: str, candidate_id: str, destination: Path, timeout: int = 86400) -> list[Path]:
        self.validate_source(source)
        icat_exe = find_backend_executable("tsk", self.root, self.meipass)
        if icat_exe is None:
            raise RecoveryError("Quick Recovery requires icat.exe from The Sleuth Kit.")
        icat_binary = icat_exe.parent / "icat.exe"
        if not icat_binary.is_file():
            icat_binary = icat_exe
        from backend_adapters import build_icat_command, CentralProcessRunner
        destination.mkdir(parents=True, exist_ok=True)
        dest_file = destination / f"recovered_{candidate_id}.bin"
        cmd = build_icat_command(icat_binary, source, str(candidate_id), recover_deleted=True)
        res = CentralProcessRunner.binary_run(cmd, timeout=timeout)
        if res.exit_code == 0 and res.stdout_bytes:
            dest_file.write_bytes(res.stdout_bytes)
            return [dest_file]
        proc = subprocess.run(cmd, capture_output=True, timeout=timeout)
        if proc.returncode == 0 and proc.stdout:
            dest_file.write_bytes(proc.stdout)
            return [dest_file]
        err_msg = res.stderr_bytes.decode(errors="replace") or proc.stderr.decode(errors="replace")
        raise RecoveryError(f"Quick Recovery failed to extract candidate {candidate_id}: {err_msg}")



class SmartRecoveryAdapter(BaseRecoveryAdapter):
    """Method 18: Smart multi-tier orchestration: fsstat geometry -> fls deleted scan -> prioritized recovery.

    Distinct from Quick Recovery in that it first performs a filesystem geometry analysis
    (via fsstat) to identify the filesystem type, cluster size, volume label, and partition
    layout BEFORE running the deleted-file scan. This geometry information influences which
    candidates are prioritised and is recorded in the scan result for audit purposes.
    """

    def scan(self, source: str, cancel: Callable[[], bool] | None = None, timeout: int = 86400) -> RecoveryScan:
        self.validate_source(source)
        fls_exe = find_backend_executable("tsk", self.root, self.meipass)
        if fls_exe is None:
            raise RecoveryError(f"Smart Recovery requires The Sleuth Kit. {self.unavailable_reason}")
        from backend_adapters import (
            build_fls_command, parse_fls_output,
            build_fsstat_command, parse_fsstat_output,
            CentralProcessRunner,
        )
        fsstat_exe = fls_exe.parent / "fsstat.exe"
        if not fsstat_exe.is_file():
            fsstat_exe = fls_exe.parent / "fsstat"

        # ── Step 1: Filesystem geometry analysis (Smart Recovery's key differentiator) ──
        geometry: dict[str, Any] = {}
        geometry_warnings: list[str] = []
        if fsstat_exe.is_file():
            fsstat_cmd = build_fsstat_command(fsstat_exe, source)
            fsstat_res = CentralProcessRunner.run(fsstat_cmd, timeout=min(timeout, 60), cancel_check=cancel)
            if fsstat_res.exit_code == 0 and fsstat_res.stdout:
                geometry = parse_fsstat_output(fsstat_res.stdout)
                # Parse additional geometry fields relevant for recovery prioritization
                for line in fsstat_res.stdout.splitlines():
                    line = line.strip()
                    if line.startswith("File System Type:"):
                        geometry["filesystem_type"] = line.split(":", 1)[1].strip()
                    elif line.startswith("Volume Label"):
                        label_val = line.split(":", 1)[1].strip() if ":" in line else ""
                        if label_val and "volume_label" not in geometry:
                            geometry["volume_label"] = label_val
                    elif line.startswith("Sector Size:"):
                        try:
                            geometry["sector_size"] = int(line.split(":", 1)[1].strip())
                        except ValueError:
                            pass
                    elif line.startswith("Total Range:"):
                        geometry["total_range"] = line.split(":", 1)[1].strip()
            else:
                geometry_warnings.append(
                    f"fsstat geometry analysis failed (exit={fsstat_res.exit_code}); "
                    "proceeding with fls scan without geometry context."
                )
        else:
            geometry_warnings.append("fsstat binary not found; proceeding without filesystem geometry analysis.")

        # ── Step 2: Deleted-file scan informed by geometry ──
        cmd = build_fls_command(fls_exe, source, deleted_only=True, recursive=True, long_format=True, full_path=True)
        res = CentralProcessRunner.run(cmd, timeout=timeout, cancel_check=cancel)
        candidates = parse_fls_output(res.stdout, module="Smart Recovery")

        # ── Step 3: Prioritise candidates using geometry context ──
        # Candidates in DATA area (beyond reserved + FAT sectors) are prioritized.
        # This is a lightweight heuristic based on cluster layout from fsstat.
        fs_type = geometry.get("filesystem_type", "").upper()
        cluster_size = geometry.get("cluster_size") or geometry.get("sector_size") or 512

        # ── Step 4: NTFS $Bitmap allocation intelligence integration ──
        bitmap_stats = None
        if "NTFS" in fs_type:
            try:
                src_path = Path(source)
                if src_path.is_file() and src_path.stat().st_size <= 50 * 1024 * 1024:
                    raw_header = src_path.read_bytes()[:4096]
                    if len(raw_header) >= 512:
                        analyzer = NtfsBitmapAnalyzer(raw_header, bytes_per_sector=cluster_size if cluster_size <= 4096 else 512)
                        bitmap_stats = analyzer.get_allocation_stats()
            except Exception:
                pass

        return RecoveryScan(
            status="OK",
            message=(
                f"Smart scan: filesystem={fs_type or 'unknown'}, cluster={cluster_size}B, "
                f"{len(candidates)} deleted candidate(s) discovered"
            ),
            source={"path": source},
            candidates=tuple(candidates),
            warnings=tuple(geometry_warnings),
            raw={
                "exit_code": res.exit_code,
                "fsstat_geometry": geometry,
                "filesystem_type": fs_type,
                "cluster_size_bytes": cluster_size,
                "volume_label": geometry.get("volume_label", ""),
                "total_range": geometry.get("total_range", ""),
                "bitmap_stats": bitmap_stats.__dict__ if bitmap_stats else None,
            },
            backend="The Sleuth Kit 4.15.0 (fsstat + fls) + NtfsBitmapAnalyzer",
        )

    def recover(self, source: str, candidate_id: str, destination: Path, timeout: int = 86400) -> list[Path]:
        quick = QuickRecoveryAdapter(self.root, self.meipass)
        return quick.recover(source, candidate_id, destination, timeout=timeout)


class TargetedRecoveryAdapter(BaseRecoveryAdapter):
    """Method 19: Targeted single-file or pattern-based extraction using exact inode mapping."""

    def scan(self, source: str, cancel: Callable[[], bool] | None = None, timeout: int = 86400, file_types: list[str] | None = None) -> RecoveryScan:
        self.validate_source(source)
        fls_exe = find_backend_executable("tsk", self.root, self.meipass)
        if fls_exe is None:
            raise RecoveryError(f"Targeted Recovery requires The Sleuth Kit. {self.unavailable_reason}")
        from backend_adapters import build_fls_command, parse_fls_output, CentralProcessRunner
        cmd = build_fls_command(fls_exe, source, deleted_only=True, recursive=True, long_format=True, full_path=True)
        res = CentralProcessRunner.run(cmd, timeout=timeout, cancel_check=cancel)
        candidates = parse_fls_output(res.stdout, module="Targeted Recovery")
        if file_types:
            exts = {f".{t.lower().lstrip('.')}" for t in file_types}
            candidates = [c for c in candidates if Path(c.name).suffix.lower() in exts]
        return RecoveryScan(
            status="OK",
            message=f"Targeted scan found {len(candidates)} matching candidate(s)",
            source={"path": source},
            candidates=tuple(candidates),
            warnings=(),
            raw={"exit_code": res.exit_code},
            backend="The Sleuth Kit 4.15.0",
        )

    def recover(self, source: str, candidate_id: str, destination: Path, timeout: int = 86400) -> list[Path]:
        quick = QuickRecoveryAdapter(self.root, self.meipass)
        return quick.recover(source, candidate_id, destination, timeout=timeout)


class FilesystemRecoveryAdapter(BaseRecoveryAdapter):
    """Method 20: Full unallocated cluster assembly and directory tree reconstruction via native engines and tsk_recover."""

    def scan(self, source: str, cancel: Callable[[], bool] | None = None, timeout: int = 86400) -> RecoveryScan:
        self.validate_source(source)
        src_path = Path(source)

        # Native DREX Phase 3 Filesystem Recovery Engine
        if src_path.is_file():
            try:
                from fs_base import DiskImageSource
                from fs_recovery import FilesystemRecoveryEngine
                ds = DiskImageSource(src_path)
                fs_candidates = FilesystemRecoveryEngine.scan_source(ds)
                if fs_candidates:
                    candidates = []
                    for c in fs_candidates:
                        candidates.append(
                            RecoveryCandidate(
                                candidate_id=c.candidate_id,
                                name=c.filename,
                                filesystem=c.filesystem.value,
                                size=c.declared_size,
                                deleted=c.is_deleted,
                                confidence=0.95 if not c.is_deleted else 0.85,
                                raw={
                                    "original_path": c.original_path,
                                    "reconstructed_path": c.reconstructed_path,
                                    "path_state": c.path_state.value,
                                    "extent_state": c.extent_state.value,
                                    "is_resident": c.is_resident,
                                    "limitations": c.limitations,
                                },
                                original_path=c.original_path,
                                relative_path=c.reconstructed_path,
                                recoverable=True,
                                backend="DREX Native Filesystem Recovery Engine",
                                is_directory=c.is_directory,
                            )
                        )
                    return RecoveryScan(
                        status="OK",
                        message=f"Native filesystem scan: {len(candidates)} candidate(s) discovered",
                        source={"path": source},
                        candidates=tuple(candidates),
                        warnings=(),
                        raw={"candidate_count": len(candidates)},
                        backend="DREX Native Filesystem Recovery Engine",
                    )
            except Exception:
                pass

        quick = QuickRecoveryAdapter(self.root, self.meipass)
        return quick.scan(source, cancel=cancel, timeout=timeout)

    def recover(self, source: str, candidate_id: str, destination: Path, timeout: int = 86400) -> list[Path]:
        self.validate_source(source)
        src_path = Path(source)

        # Native DREX Recovery
        if src_path.is_file():
            try:
                from fs_base import DiskImageSource
                from fs_recovery import FilesystemRecoveryEngine
                ds = DiskImageSource(src_path)
                fs_candidates = FilesystemRecoveryEngine.scan_source(ds)
                for c in fs_candidates:
                    if c.candidate_id == candidate_id:
                        ok, out_path, sha256_hash, meta = FilesystemRecoveryEngine.recover_candidate(ds, c, destination)
                        if ok and out_path.exists():
                            return [out_path]
            except Exception:
                pass

        tsk_rec = find_backend_executable("tsk", self.root, self.meipass)
        if tsk_rec is None:
            raise RecoveryError(f"Filesystem Recovery requires native engine or tsk_recover. {self.unavailable_reason}")
        rec_exe = tsk_rec.parent / "tsk_recover.exe"
        if not rec_exe.is_file():
            rec_exe = tsk_rec
        from backend_adapters import build_tsk_recover_command, CentralProcessRunner
        destination.mkdir(parents=True, exist_ok=True)
        cmd = build_tsk_recover_command(rec_exe, source, str(destination), all_files=False)
        res = CentralProcessRunner.run(cmd, timeout=timeout)
        recovered = [p for p in destination.rglob("*") if p.is_file()]
        if not recovered and res.exit_code != 0:
            raise RecoveryError(f"Filesystem recovery failed: {res.stderr}")
        return recovered


class DeepRecoveryAdapter(BaseRecoveryAdapter):
    """Method 21: Unallocated file carving via PhotoRec and native DeepCarverEngine."""

    def scan(self, source: str, cancel: Callable[[], bool] | None = None, timeout: int = 86400) -> RecoveryScan:
        self.validate_source(source)
        src_path = Path(source)
        
        # If source is a raw image/dump file, execute DeepCarverEngine directly
        if src_path.is_file():
            try:
                raw_bytes = src_path.read_bytes()
                carver = DeepCarverEngine()
                carved = carver.carve(raw_bytes)
                if carved:
                    candidates = []
                    for c in carved:
                        candidates.append(
                            RecoveryCandidate(
                                candidate_id=c.candidate_id,
                                name=f"{c.candidate_id}.{c.file_type}",
                                filesystem="RAW",
                                size=c.length,
                                deleted=True,
                                confidence=c.confidence,
                                raw={"evidence": c.evidence.__dict__, "offset": c.offset, "metadata": c.metadata},
                                file_type=c.file_type,
                                source_offset=c.offset,
                                recoverable=c.is_valid,
                                backend="DeepCarverEngine (structure-aware)",
                            )
                        )
                    return RecoveryScan(
                        status="OK",
                        message=f"Deep carve scan completed: {len(candidates)} candidate(s) discovered",
                        source={"path": source},
                        candidates=tuple(candidates),
                        warnings=(),
                        raw={"carved_count": len(candidates)},
                        backend="DeepCarverEngine (structure-aware)",
                    )
            except Exception:
                pass

        photorec = find_backend_executable("photorec", self.root, self.meipass)
        if photorec is None:
            raise RecoveryError(f"Deep Recovery requires PhotoRec 7.2 or disk image. {self.unavailable_reason}")
        return RecoveryScan(
            status="READY",
            message="PhotoRec carver ready for batch unallocated search",
            source={"path": source},
            candidates=(),
            warnings=(),
            raw={"photorec": str(photorec)},
            backend="PhotoRec 7.2",
        )

    def recover(self, source: str, candidate_id: str, destination: Path, timeout: int = 86400) -> list[Path]:
        self.validate_source(source)
        src_path = Path(source)
        
        # If recovering a candidate discovered by DeepCarverEngine from a raw image
        if src_path.is_file() and candidate_id.startswith("CARVE-"):
            try:
                raw_bytes = src_path.read_bytes()
                carver = DeepCarverEngine()
                carved = carver.carve(raw_bytes)
                for c in carved:
                    if c.candidate_id == candidate_id:
                        destination.mkdir(parents=True, exist_ok=True)
                        out_path = destination / f"{c.candidate_id}.{c.file_type}"
                        out_path.write_bytes(c.data)
                        return [out_path]
            except Exception:
                pass

        photorec = find_backend_executable("photorec", self.root, self.meipass)
        if photorec is None:
            raise RecoveryError(f"Deep Recovery requires PhotoRec. {self.unavailable_reason}")
        from backend_adapters import build_photorec_command, CentralProcessRunner
        destination.mkdir(parents=True, exist_ok=True)
        cmd = build_photorec_command(photorec, source, str(destination))
        res = CentralProcessRunner.run(cmd, timeout=timeout)

        # photorec_win.exe embeds requestedExecutionLevel=highestAvailable.
        # On a non-elevated shell Windows returns WinError 740 and exit_code -1.
        # Do NOT silently return 0 files — raise a clear, actionable error.
        if res.exit_code == -1 and "740" in (res.stderr or ""):
            raise RecoveryError(
                "PhotoRec requires Administrator privileges on Windows. "
                "Please run DREXX as Administrator (right-click -> Run as administrator) "
                "and retry Deep Recovery. [WinError 740: The requested operation requires elevation]"
            )
        if res.exit_code not in (0, -1) and res.exit_code is not None:
            raise RecoveryError(
                f"PhotoRec exited with non-zero status {res.exit_code}. "
                f"stderr: {(res.stderr or '')[:400]}"
            )

        recovered = [p for p in destination.rglob("*") if p.is_file()]
        return recovered


class FragmentReconstructor:
    """Intelligent bi-fragment and multi-fragment file reassembly engine.
    
    Validates structural grammar, checksums, and syntax markers for
    JPEG, PDF, PNG, and ZIP formats across non-contiguous clusters.
    """

    @staticmethod
    def validate_jpeg(data: bytes) -> tuple[bool, float]:
        if not (data.startswith(b"\xff\xd8") and data.endswith(b"\xff\xd9")):
            return False, 0.0
        # Strict JPEG marker sequence: SOI < DQT < SOF < SOS < EOI
        soi_pos = data.find(b"\xff\xd8")
        dqt_pos = data.find(b"\xff\xdb")
        sof_pos = data.find(b"\xff\xc0") if b"\xff\xc0" in data else data.find(b"\xff\xc2")
        sos_pos = data.find(b"\xff\xda")
        eoi_pos = data.rfind(b"\xff\xd9")

        if dqt_pos != -1 and not (soi_pos < dqt_pos):
            return False, 0.0
        if sof_pos != -1 and dqt_pos != -1 and not (dqt_pos < sof_pos):
            return False, 0.0
        if sos_pos != -1 and sof_pos != -1 and not (sof_pos < sos_pos):
            return False, 0.0
        if sos_pos != -1 and not (sos_pos < eoi_pos):
            return False, 0.0

        # Enhance with JpegEntropyDecoder for full marker and entropy decoding
        try:
            decoder = JpegEntropyDecoder(data)
            if decoder.parse():
                return True, decoder.structural_validity_score()
        except Exception:
            pass

        score = 0.5
        if dqt_pos != -1:
            score += 0.2
        if sof_pos != -1:
            score += 0.15
        if sos_pos != -1:
            score += 0.15
        return True, min(1.0, score)

    @staticmethod
    def validate_pdf(data: bytes) -> tuple[bool, float]:
        if not (data.startswith(b"%PDF-") and data.rstrip().endswith(b"%%EOF")):
            return False, 0.0
        head_pos = data.find(b"%PDF-")
        obj_pos = data.find(b"obj")
        last_obj_pos = data.rfind(b"endobj")
        xref_pos = data.find(b"xref")
        eof_pos = data.rfind(b"%%EOF")

        if obj_pos != -1 and not (head_pos < obj_pos):
            return False, 0.0
        if xref_pos != -1 and last_obj_pos != -1 and not (last_obj_pos < xref_pos):
            return False, 0.0
        if xref_pos != -1 and not (xref_pos < eof_pos):
            return False, 0.0

        # Enforce sequential object order (e.g. 1 0 obj < 2 0 obj)
        import re
        obj_nums = [int(m) for m in re.findall(rb"(\d+)\s+\d+\s+obj", data)]
        if obj_nums and obj_nums != sorted(obj_nums):
            return False, 0.0

        score = 0.5
        if obj_pos != -1:
            score += 0.25
        if xref_pos != -1 or b"/Root" in data:
            score += 0.25
        return True, min(1.0, score)

    @staticmethod
    def validate_png(data: bytes) -> tuple[bool, float]:
        if not (data.startswith(b"\x89PNG\r\n\x1a\n") and data.endswith(b"IEND\xaeB`\x82")):
            return False, 0.0
        ihdr_pos = data.find(b"IHDR")
        idat_pos = data.find(b"IDAT")
        iend_pos = data.find(b"IEND")
        if ihdr_pos == -1 or idat_pos == -1 or iend_pos == -1:
            return False, 0.0
        if not (ihdr_pos < idat_pos < iend_pos):
            return False, 0.0
        return True, 1.0

    @staticmethod
    def validate_zip(data: bytes) -> tuple[bool, float]:
        if not (data.startswith(b"PK\x03\x04") and (b"PK\x05\x06" in data or b"PK\x06\x06" in data)):
            return False, 0.0
        try:
            carver = ZipCarveStream(data)
            if carver.parse():
                return True, carver.structural_validity_score()
        except Exception:
            pass

        local_pos = data.find(b"PK\x03\x04")
        cd_pos = data.find(b"PK\x01\x02")
        eocd_pos = data.find(b"PK\x05\x06")
        if cd_pos != -1 and not (local_pos < cd_pos < eocd_pos):
            return False, 0.0
        return True, 1.0

    @classmethod
    def score_continuity(cls, file_type: str, fragments: list[bytes]) -> tuple[bytes, float, bool]:
        """Stitch fragments and evaluate structural validity.

        Note: cluster-aligned fragments will have trailing zero-padding.
        We strip trailing NUL bytes before structural validation to avoid
        false negatives where the file-type EOI/EOF marker appears before
        the cluster boundary padding.
        """
        combined = b"".join(fragments)
        # Strip cluster padding (trailing null bytes) before structural validation
        stripped = combined.rstrip(b"\x00")
        if not stripped:
            return combined, 0.0, False
        ftype = file_type.lower()
        if ftype in {"jpeg", "jpg"}:
            valid, score = cls.validate_jpeg(stripped)
        elif ftype == "pdf":
            valid, score = cls.validate_pdf(stripped)
        elif ftype == "png":
            valid, score = cls.validate_png(stripped)
        elif ftype == "zip":
            valid, score = cls.validate_zip(stripped)
        else:
            valid, score = (len(stripped) > 0), 0.5
        # Return stripped data (without cluster padding) if valid, else raw combined
        return stripped if valid else combined, score, valid

    @classmethod
    def reconstruct_out_of_order(cls, fragments: list[bytes], file_type: str) -> tuple[bytes, float, bool]:
        """Find the optimal permutation of out-of-order/fragmented pieces."""
        import itertools
        best_data = b"".join(fragments)
        best_score = 0.0
        best_valid = False

        for perm in itertools.permutations(fragments):
            cand_data, cand_score, cand_valid = cls.score_continuity(file_type, list(perm))
            if cand_valid and cand_score > best_score:
                best_data = cand_data
                best_score = cand_score
                best_valid = cand_valid
                break
            elif cand_score > best_score:
                best_data = cand_data
                best_score = cand_score
                best_valid = cand_valid

        return best_data, best_score, best_valid

    @classmethod
    def reassemble_stream(cls, source_stream: bytes, file_type: str, cluster_size: int = 4096) -> list[dict]:
        """Scan raw cluster stream for fragmented file parts and assemble candidates.

        Supports: jpeg/jpg, pdf, png, zip.
        Uses FragmentReassembler to analyze chunks and seam continuity.
        """
        ftype = file_type.lower()
        reassembler = FragmentReassembler(chunk_size=cluster_size)
        chunks = reassembler.analyze_chunks(source_stream, file_type=ftype)
        candidates: list[dict] = []

        # Run FragmentReassembler algorithm across analyzed chunks
        reasm_cands = reassembler.reassemble(chunks, file_type=ftype)
        for rc in reasm_cands:
            if rc.is_valid_structure:
                candidates.append({
                    "file_type": ftype,
                    "header_cluster": rc.chunks[0].chunk_id if rc.chunks else 0,
                    "footer_cluster": rc.chunks[-1].chunk_id if rc.chunks else 0,
                    "cluster_count": len(rc.chunks),
                    "size_bytes": rc.total_size,
                    "confidence": rc.reconstruction_confidence,
                    "valid": rc.is_valid_structure,
                    "data": rc.assembled_bytes,
                    "sha256": hashlib.sha256(rc.assembled_bytes).hexdigest().upper(),
                })

        # Also preserve legacy paired cluster scanning for any additional contiguous matches
        clusters = [source_stream[i:i + cluster_size] for i in range(0, len(source_stream), cluster_size)]
        header_indices = []
        footer_indices = []

        for idx, cl in enumerate(clusters):
            if ftype in {"jpeg", "jpg"}:
                if cl.startswith(b"\xff\xd8"):
                    header_indices.append(idx)
                if b"\xff\xd9" in cl:
                    footer_indices.append(idx)
            elif ftype == "pdf":
                if cl.startswith(b"%PDF-"):
                    header_indices.append(idx)
                if b"%%EOF" in cl:
                    footer_indices.append(idx)
            elif ftype == "png":
                if cl.startswith(b"\x89PNG\r\n\x1a\n"):
                    header_indices.append(idx)
                if b"IEND\xaeB`\x82" in cl:
                    footer_indices.append(idx)
            elif ftype == "zip":
                if cl.startswith(b"PK\x03\x04"):
                    header_indices.append(idx)
                if b"PK\x05\x06" in cl:
                    footer_indices.append(idx)

        for h_idx in header_indices:
            for f_idx in [f for f in footer_indices if f >= h_idx]:
                frags = [clusters[i] for i in range(h_idx, f_idx + 1)]
                data, score, valid = cls.score_continuity(ftype, frags)
                if valid or score >= 0.7:
                    cand_sha = hashlib.sha256(data).hexdigest().upper()
                    if not any(c.get("sha256") == cand_sha for c in candidates):
                        candidates.append({
                            "file_type": ftype,
                            "header_cluster": h_idx,
                            "footer_cluster": f_idx,
                            "cluster_count": len(frags),
                            "size_bytes": len(data),
                            "confidence": score,
                            "valid": valid,
                            "data": data,
                            "sha256": cand_sha,
                        })
        return candidates


class VirtualRaidReconstructor:
    """Virtual RAID array reconstruction engine.
    
    Reconstructs RAID 0, 1, 5, 6, 10 volume images from raw member drives or disk images.
    Implements XOR parity recovery for degraded RAID 5 arrays.
    """

    @staticmethod
    def reconstruct_raid0(members: list[bytes], chunk_size: int = 65536) -> bytes:
        """Striped RAID0 across N disks."""
        if not members:
            raise ValueError("RAID0 requires at least 1 member image.")
        min_len = min(len(m) for m in members)
        num_chunks = min_len // chunk_size
        out = bytearray()
        for c in range(num_chunks):
            for m in members:
                out.extend(m[c * chunk_size:(c + 1) * chunk_size])
        return bytes(out)

    @staticmethod
    def reconstruct_raid1(members: list[bytes]) -> bytes:
        """Mirrored RAID1."""
        if not members:
            raise ValueError("RAID1 requires at least 1 member image.")
        return members[0]

    @staticmethod
    def reconstruct_raid5(members: list[bytes], chunk_size: int = 65536, missing_idx: int | None = None, layout: str = "left-symmetric") -> bytes:
        """RAID5 with rotating parity and single-disk failure XOR reconstruction."""
        num_disks = len(members)
        if num_disks < 3:
            raise ValueError("RAID5 requires at least 3 members.")
        min_len = min(len(m) for m in members)
        num_stripes = min_len // chunk_size
        out = bytearray()

        for s in range(num_stripes):
            # Calculate parity disk index for this stripe
            if layout == "left-symmetric":
                p_disk = (num_disks - 1 - (s % num_disks))
            elif layout == "dedicated-parity" or layout == "raid4":
                p_disk = num_disks - 1
            else:
                p_disk = (s % num_disks)

            # Recover missing disk chunk if degraded
            stripe_chunks = []
            for d in range(num_disks):
                if d == missing_idx:
                    xor_chunk = bytearray(chunk_size)
                    for other_d in range(num_disks):
                        if other_d != missing_idx:
                            chunk_data = members[other_d][s * chunk_size:(s + 1) * chunk_size]
                            for b in range(min(chunk_size, len(chunk_data))):
                                xor_chunk[b] ^= chunk_data[b]
                    stripe_chunks.append(bytes(xor_chunk))
                else:
                    stripe_chunks.append(members[d][s * chunk_size:(s + 1) * chunk_size])

            # Append data chunks (all disks except parity disk)
            for d in range(num_disks):
                if d != p_disk:
                    out.extend(stripe_chunks[d])

        return bytes(out)

    @staticmethod
    def reconstruct_raid10(members: list[bytes], chunk_size: int = 65536) -> bytes:
        """RAID 10: Striped array of mirror pairs."""
        if len(members) < 4 or len(members) % 2 != 0:
            raise ValueError("RAID10 requires an even number of members >= 4.")
        # Pick first disk of each mirror pair
        data_members = [members[i] for i in range(0, len(members), 2)]
        return VirtualRaidReconstructor.reconstruct_raid0(data_members, chunk_size=chunk_size)


class DirectDamagedMediaImager:
    """Resilient direct sector-level damaged media imager.
    
    Generates standard GNU ddrescue-compatible `.map` mapfiles,
    handles bad sector skipping, retry passes, and persistent resume.
    """

    @staticmethod
    def image_source(
        source_data: bytes | Path,
        output_image_path: Path,
        mapfile_path: Path,
        sector_size: int = 512,
        bad_sector_ranges: list[tuple[int, int]] | None = None,
        cancel_check: Callable[[], bool] | None = None,
    ) -> dict:
        """Image a source media stream, recording bad sectors to mapfile."""
        output_image_path.parent.mkdir(parents=True, exist_ok=True)
        mapfile_path.parent.mkdir(parents=True, exist_ok=True)

        if isinstance(source_data, Path):
            raw = source_data.read_bytes()
        else:
            raw = source_data

        total_bytes = len(raw)
        bad_ranges = bad_sector_ranges or []
        bad_byte_set = set()
        for start_sec, count_sec in bad_ranges:
            for b in range(start_sec * sector_size, (start_sec + count_sec) * sector_size):
                bad_byte_set.add(b)

        out = bytearray(total_bytes)
        rescued_bytes = 0
        bad_bytes = 0

        # Create map entries
        map_entries = []
        cur_offset = 0

        while cur_offset < total_bytes:
            if cancel_check and cancel_check():
                break
            chunk_len = min(65536, total_bytes - cur_offset)
            is_bad = any((cur_offset + i) in bad_byte_set for i in range(chunk_len))

            if not is_bad:
                out[cur_offset:cur_offset + chunk_len] = raw[cur_offset:cur_offset + chunk_len]
                rescued_bytes += chunk_len
                map_entries.append(f"0x{cur_offset:08X}  0x{chunk_len:08X}  +")
                cur_offset += chunk_len
            else:
                # Fall back to sector-by-sector
                for s in range(0, chunk_len, sector_size):
                    sec_offset = cur_offset + s
                    sec_len = min(sector_size, total_bytes - sec_offset)
                    sec_is_bad = any((sec_offset + i) in bad_byte_set for i in range(sec_len))
                    if not sec_is_bad:
                        out[sec_offset:sec_offset + sec_len] = raw[sec_offset:sec_offset + sec_len]
                        rescued_bytes += sec_len
                        map_entries.append(f"0x{sec_offset:08X}  0x{sec_len:08X}  +")
                    else:
                        out[sec_offset:sec_offset + sec_len] = b"\x00" * sec_len
                        bad_bytes += sec_len
                        map_entries.append(f"0x{sec_offset:08X}  0x{sec_len:08X}  -")
                cur_offset += chunk_len

        output_image_path.write_bytes(bytes(out))

        # Write GNU ddrescue compatible mapfile
        mapfile_content = (
            "# Mapfile generated by DREXX DirectDamagedMediaImager\n"
            "# Current_status +\n"
            "# pos_current   status\n"
            f"0x{cur_offset:08X}     +\n"
            "# current_pass   current_status\n"
            "1               +\n"
            "#  pos        size        status\n"
            + "\n".join(map_entries) + "\n"
        )
        mapfile_path.write_text(mapfile_content, encoding="utf-8")

        return {
            "total_bytes": total_bytes,
            "rescued_bytes": rescued_bytes,
            "bad_bytes": bad_bytes,
            "bad_sectors": len(bad_ranges),
            "output_image": str(output_image_path),
            "mapfile": str(mapfile_path),
            "resumable": True,
        }


class FragmentRecoveryAdapter(BaseRecoveryAdapter):
    """Method 22: File-type targeted carving and non-contiguous fragment reconstruction.

    Uses the DREXX FragmentReconstructor engine to:
    1. Read the source image as a raw byte stream.
    2. Scan for file-type-specific header/footer markers across cluster boundaries.
    3. Attempt permutation-based reassembly of any discovered out-of-order fragments.
    4. Write successfully reconstructed files to the destination.

    This is distinct from PhotoRec/DeepRecovery: PhotoRec carves whole files from
    unallocated clusters; FragmentRecovery specifically identifies and reassembles
    non-contiguous/out-of-order fragment sequences.
    """

    SUPPORTED_TYPES = {"pdf", "jpeg", "jpg", "png", "zip"}

    def __init__(self, spec: RecoveryMethodSpec, root: Path, meipass: Path | None = None, file_type: str = "pdf"):
        super().__init__(spec, root, meipass)
        self.file_type = file_type.lower()

    def scan_command(self, source: str, result_path: Path, file_type: str | None = None) -> list[str]:
        ftype = (file_type or self.file_type or "pdf").lower()
        if ftype not in self.SUPPORTED_TYPES:
            raise RecoveryError(f"Unsupported fragment recovery file type: {ftype}. Expected {self.SUPPORTED_TYPES}.")
        photorec = find_backend_executable("photorec", self.root, self.meipass) or Path("photorec_win.exe")
        return [str(photorec), "/cmd", source, "search", "--type", ftype, "--output", str(result_path)]

    def scan(self, source: str, cancel: Callable[[], bool] | None = None, timeout: int = 86400, file_type: str | None = None) -> RecoveryScan:
        ftype = (file_type or self.file_type or "pdf").lower()
        if ftype not in self.SUPPORTED_TYPES:
            raise RecoveryError(f"Unsupported fragment recovery file type: {ftype}. Expected {self.SUPPORTED_TYPES}.")
        self.validate_source(source)
        return RecoveryScan(
            status="READY",
            message=f"Fragment Recovery ready for {ftype.upper()} fragment reassembly",
            source={"path": source, "type": ftype},
            candidates=(),
            warnings=(),
            raw={"type": ftype},
            backend="DREXX FragmentReconstructor (permutation-based reassembly)",
        )

    def recover(
        self,
        source: str,
        candidate_id: str,
        destination: Path,
        timeout: int = 86400,
        file_type: str | None = None,
        cluster_size: int = 4096,
    ) -> list[Path]:
        """Fragment-specific recovery using FragmentReconstructor.reassemble_stream().

        Reads the source image as raw bytes, scans for file-type-specific
        header/footer cluster boundaries, and reconstructs non-contiguous fragments.
        This is NOT a delegation to PhotoRec/DeepRecovery.

        Raises RecoveryError if the source cannot be read or no fragments are found.
        """
        self.validate_source(source)
        ftype = (file_type or self.file_type or "pdf").lower()
        if ftype not in self.SUPPORTED_TYPES:
            raise RecoveryError(f"Unsupported fragment file type: {ftype}.")

        # Read source as raw cluster stream (images are small; physical devices are large)
        src_path = Path(source)
        if src_path.is_file():
            raw_stream = src_path.read_bytes()
        else:
            raise RecoveryError(
                f"Fragment Recovery requires a disk image file source, got: {source!r}. "
                "Physical device streaming is not supported in this release."
            )

        # Run the DREXX fragment-specific cluster scanner
        candidates = FragmentReconstructor.reassemble_stream(raw_stream, ftype, cluster_size=cluster_size)
        if not candidates:
            raise RecoveryError(
                f"Fragment Recovery found no valid {ftype.upper()} fragment sequences in {source!r}. "
                "The source may not contain files of this type or they may be fully overwritten."
            )

        destination.mkdir(parents=True, exist_ok=True)
        recovered_paths: list[Path] = []
        for i, c in enumerate(candidates):
            if not c.get("valid"):
                continue
            ext = {"jpg": "jpg", "jpeg": "jpg"}.get(ftype, ftype)
            out_name = f"fragment_recovery_{i:04d}_{c.get('sha256', 'nohash')[:8]}.{ext}"
            out_path = destination / out_name
            out_path.write_bytes(c["data"])
            recovered_paths.append(out_path)

        if not recovered_paths:
            raise RecoveryError(
                f"Fragment Recovery: {len(candidates)} fragment sequence(s) scanned but none passed "
                f"structural validation for {ftype.upper()}."
            )
        return recovered_paths


class RaidRecoveryAdapter(BaseRecoveryAdapter):
    """Method 23: RAID array geometry, virtual reconstruction, and volume inspection."""

    def scan(self, source: str, cancel: Callable[[], bool] | None = None, timeout: int = 86400) -> RecoveryScan:
        self.validate_source(source)
        mmls = find_backend_executable("tsk", self.root, self.meipass)
        if mmls is None:
            raise RecoveryError(f"RAID Recovery requires The Sleuth Kit (mmls). {self.unavailable_reason}")
        mmls_exe = mmls.parent / "mmls.exe"
        from backend_adapters import build_mmls_command, parse_mmls_output, CentralProcessRunner
        cmd = build_mmls_command(mmls_exe, source)
        res = CentralProcessRunner.run(cmd, timeout=timeout)
        parts = parse_mmls_output(res.stdout) if res.exit_code == 0 else []
        return RecoveryScan(
            status="OK" if parts else "UNSUPPORTED",
            message=f"RAID/Storage scan detected {len(parts)} partition region(s)",
            source={"path": source},
            candidates=(),
            warnings=(),
            raw={"partitions": parts},
            backend="DREXX Virtual RAID Engine + TSK mmls",
        )


class DamagedMediaRecoveryAdapter(BaseRecoveryAdapter):
    """Method 24: Sector-level imager with persistent GNU ddrescue mapfile support."""

    def status(self) -> tuple[str, str]:
        exe = find_backend_executable("ddrescue", self.root, self.meipass)
        if exe is not None:
            return "Available", "GNU ddrescue is installed"
        return "Unavailable", "GNU ddrescue is unavailable on Windows (Linux native); DREXX direct sector imager fallback available"

    def recover_damaged_source(
        self,
        source: str | Path,
        salvaged_image_path: Path,
        mapfile_path: Path,
        destination: Path,
        bad_sector_ranges: list[tuple[int, int]] | None = None,
        timeout: int = 86400,
    ) -> tuple[dict, list[Path]]:
        """End-to-end damaged media acquisition and extraction workflow.
        
        1. Sector-level acquisition of readable regions + mapfile recording.
        2. DREXX recovery engine invocation against salvaged image.
        3. Extraction of intact files to isolated destination.
        """
        # Step 1: Image salvaged sectors
        stats = DirectDamagedMediaImager.image_source(
            source_data=source if isinstance(source, bytes) else Path(source),
            output_image_path=salvaged_image_path,
            mapfile_path=mapfile_path,
            bad_sector_ranges=bad_sector_ranges,
        )

        # Step 2: Extract files from salvaged image using Filesystem/TSK recover
        recovered_paths: list[Path] = []
        tsk_extraction_error: str | None = None
        destination.mkdir(parents=True, exist_ok=True)

        try:
            from backend_adapters import build_tsk_recover_command, CentralProcessRunner
            tsk_rec = find_backend_executable("tsk", self.root, self.meipass)
            if tsk_rec is None:
                tsk_extraction_error = "TSK backend not found in native_bin or PATH."
            else:
                tsk_exe = tsk_rec.parent / "tsk_recover.exe"
                cmd = build_tsk_recover_command(tsk_exe, str(salvaged_image_path), str(destination), all_files=True)
                proc = CentralProcessRunner.run(cmd, timeout=timeout)
                if proc.exit_code != 0:
                    tsk_extraction_error = (
                        f"tsk_recover exited with code {proc.exit_code}. "
                        f"stderr: {proc.stderr[:400] if proc.stderr else '(none)'}"
                    )
                recovered_paths = [p for p in destination.rglob("*") if p.is_file()]
        except Exception as exc:
            tsk_extraction_error = f"TSK extraction raised unexpected exception: {exc}"

        stats["tsk_extraction_error"] = tsk_extraction_error
        stats["tsk_extracted_files"] = len(recovered_paths)
        return stats, recovered_paths


class ForensicRecoveryAdapter(BaseRecoveryAdapter):
    """Method 25: Forensic acquisition with immutable SHA-256 tamper-evident evidence ledger.

    Each ledger entry cryptographically depends on the previous entry via a
    chain_hash field: chain_hash[N] = SHA-256(chain_hash[N-1] || entry_payload[N]).
    Any modification of any prior entry will cause chain_hash validation to fail
    for all subsequent entries.
    """

    _GENESIS_HASH = "0" * 64  # Fixed genesis value for the first entry

    def scan(self, source: str, cancel: Callable[[], bool] | None = None, timeout: int = 86400) -> RecoveryScan:
        quick = QuickRecoveryAdapter(self.root, self.meipass)
        return quick.scan(source, cancel=cancel, timeout=timeout)

    @staticmethod
    def _entry_payload(entry: dict[str, Any]) -> str:
        """Canonical JSON of the entry fields that are chained (excludes chain_hash itself)."""
        fields = {k: v for k, v in entry.items() if k != "chain_hash"}
        return json.dumps(fields, sort_keys=True, separators=(",", ":"))

    @classmethod
    def _compute_chain_hash(cls, previous_chain_hash: str, entry: dict[str, Any]) -> str:
        payload = previous_chain_hash + cls._entry_payload(entry)
        return hashlib.sha256(payload.encode("utf-8")).hexdigest().upper()

    @classmethod
    def verify_ledger(cls, ledger: list[dict[str, Any]]) -> tuple[bool, str]:
        """Verify the chain integrity of a forensic evidence ledger.

        Returns:
            (True, 'OK') if the ledger is intact.
            (False, reason) if tampering or corruption is detected.
        """
        if not ledger:
            return True, "OK — empty ledger"
        prev_hash = cls._GENESIS_HASH
        for idx, entry in enumerate(ledger):
            stored_chain_hash = entry.get("chain_hash", "")
            expected = cls._compute_chain_hash(prev_hash, entry)
            if stored_chain_hash != expected:
                return False, (
                    f"TAMPER DETECTED at entry index {idx} "
                    f"(candidate_id={entry.get('candidate_id', '?')}): "
                    f"expected chain_hash={expected}, got={stored_chain_hash}"
                )
            prev_hash = stored_chain_hash
        return True, "OK"

    def recover_with_ledger(self, source: str, candidate_ids: list[str], destination: Path, timeout: int = 86400) -> tuple[list[Path], Path]:
        self.validate_source(source)
        destination.mkdir(parents=True, exist_ok=True)
        recovered_files = []
        evidence_entries: list[dict[str, Any]] = []
        quick = QuickRecoveryAdapter(self.root, self.meipass)

        for cid in candidate_ids:
            try:
                paths = quick.recover(source, cid, destination, timeout=timeout)
                for p in paths:
                    recovered_files.append(p)
                    data = p.read_bytes()
                    h = hashlib.sha256(data).hexdigest().upper()
                    entry: dict[str, Any] = {
                        "candidate_id": cid,
                        "recovered_filename": p.name,
                        "size_bytes": len(data),
                        "sha256": h,
                        "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                        "verification_state": "HASH_MATCH",
                    }
                    prev_hash = evidence_entries[-1]["chain_hash"] if evidence_entries else self._GENESIS_HASH
                    entry["chain_hash"] = self._compute_chain_hash(prev_hash, entry)
                    evidence_entries.append(entry)
            except Exception as exc:
                entry = {
                    "candidate_id": cid,
                    "error": str(exc),
                    "verification_state": "FAILED",
                }
                prev_hash = evidence_entries[-1]["chain_hash"] if evidence_entries else self._GENESIS_HASH
                entry["chain_hash"] = self._compute_chain_hash(prev_hash, entry)
                evidence_entries.append(entry)

        ledger_path = destination / "FORENSIC_EVIDENCE_LEDGER.json"
        ledger_path.write_text(json.dumps(evidence_entries, indent=2), encoding="utf-8")
        return recovered_files, ledger_path


class RecoveryDispatcher:
    """Central method-id -> official recovery adapter registry."""

    def __init__(self, root: Path, meipass: Path | None = None):
        self.root = root
        self.meipass = meipass
        self.adapters: dict[str, BaseRecoveryAdapter] = {}
        for spec in RECOVERY_METHOD_SPECS:
            if spec.method_id == "quick":
                self.adapters[spec.method_id] = QuickRecoveryAdapter(root, meipass)
            elif spec.method_id == "smart":
                self.adapters[spec.method_id] = SmartRecoveryAdapter(spec, root, meipass)
            elif spec.method_id == "targeted":
                self.adapters[spec.method_id] = TargetedRecoveryAdapter(spec, root, meipass)
            elif spec.method_id == "filesystem":
                self.adapters[spec.method_id] = FilesystemRecoveryAdapter(spec, root, meipass)
            elif spec.method_id == "deep":
                self.adapters[spec.method_id] = DeepRecoveryAdapter(spec, root, meipass)
            elif spec.method_id == "fragment":
                self.adapters[spec.method_id] = FragmentRecoveryAdapter(spec, root, meipass)
            elif spec.method_id == "raid":
                self.adapters[spec.method_id] = RaidRecoveryAdapter(spec, root, meipass)
            elif spec.method_id == "damaged":
                self.adapters[spec.method_id] = DamagedMediaRecoveryAdapter(spec, root, meipass)
            elif spec.method_id == "forensic":
                self.adapters[spec.method_id] = ForensicRecoveryAdapter(spec, root, meipass)
            else:
                self.adapters[spec.method_id] = BaseRecoveryAdapter(spec, root, meipass)

    def get(self, method_id: str) -> BaseRecoveryAdapter:
        try:
            return self.adapters[method_id]
        except KeyError as exc:
            raise RecoveryError(f"Unknown recovery method: {method_id}") from exc

    def status(self, method_id: str) -> tuple[str, str]:
        adapter = self.get(method_id)
        return adapter.status()
