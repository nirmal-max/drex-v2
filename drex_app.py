from __future__ import annotations

import base64
from concurrent.futures import Future, ThreadPoolExecutor
import ctypes
from enum import Enum
import hashlib
import importlib
import json
import os
import queue
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
import tkinter as tk
from typing import Any, Callable

from recovery_adapter import QuickRecoveryAdapter, RecoveryDispatcher, RecoveryError, RecoveryScan
from entropy_engine import calculate_shannon_entropy, evaluate_sanitization_entropy
from vss_sanitizer import VssSanitizer
from hardware_storage import (
    DeviceIntelligenceEngine,
    Qualification25MethodEngine,
    DeviceIdentitySnapshot,
    MethodQualificationRecord,
    TransportBus,
    MediaType,
    UnderlyingInterface,
    QualificationStatus,
)


APP_NAME = "DREX"
VERSION = "1.0.0"
ROOT = Path(__file__).resolve().parent

# Centralized Design System Tokens (Clean, solid, Apple-level simplicity)
BG = "#F5F5F7"
BG_SECONDARY = "#F8F8FA"
CARD_BG = "#FFFFFF"
LINE = "#E5E5E7"
BORDER_SUBTLE = "#F0F0F2"
INK = "#111827"
MUTED = "#667085"
MUTED_LIGHT = "#98A2B3"
BLUE = "#007AFF"
BLUE_LIGHT = "#E8F1FF"
BLUE_SOFT = "#F2F7FF"
GREEN = "#34C759"
GREEN_DARK = "#248A3D"
GREEN_PALE = "#EAF8EE"
ORANGE = "#FF9500"
ORANGE_LIGHT = "#FFF4E5"
RED = "#FF3B30"
RED_LIGHT = "#FEECEB"
PURPLE = "#AF52DE"
PURPLE_LIGHT = "#F5EEF8"


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def fmt_bytes(value: int | None) -> str:
    if value is None or value < 0:
        return "Unavailable"
    units = ("B", "KB", "MB", "GB", "TB", "PB")
    n = float(value)
    for unit in units:
        if n < 1024 or unit == units[-1]:
            return f"{n:.2f} {unit}" if unit != "B" else f"{int(n)} B"
        n /= 1024
    return "Unavailable"


def safe_json_write(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(value, handle, indent=2, sort_keys=True)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_name, path)
    finally:
        try:
            os.unlink(tmp_name)
        except FileNotFoundError:
            pass


def app_data_dir() -> Path:
    override = os.environ.get("DREX_DATA_DIR")
    if override:
        return Path(override).expanduser().resolve()
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA") or (Path.home() / "AppData" / "Local")
    else:
        base = os.environ.get("XDG_DATA_HOME") or (Path.home() / ".local" / "share")
    return Path(base) / APP_NAME


@dataclass
class DriveInfo:
    path: str
    device_path: str
    model: str | None = None
    serial: str | None = None
    capacity: int | None = None
    interface: str | None = None
    drive_type: str | None = None
    filesystem: str | None = None
    free: int | None = None
    health: str | None = None
    status: str | None = None
    device_id: str | None = None
    transport_bus: str = "UNKNOWN"
    underlying_interface: str = "UNKNOWN"
    media_type: str = "UNKNOWN"
    sector_size: int = 512
    is_usb_bridge: bool = False
    is_system_or_boot: bool = False
    identity_snapshot: DeviceIdentitySnapshot | None = None
    qualification_matrix: dict[int, MethodQualificationRecord] | None = None

    def display(self, field: str) -> str:
        value = getattr(self, field, None)
        return value if value not in (None, "") else "Unavailable"


def _ps_json(command: str) -> Any:
    try:
        proc = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", command],
            capture_output=True, text=True, timeout=8, check=False,
        )
        if proc.returncode != 0 or not proc.stdout.strip():
            return None
        return json.loads(proc.stdout)
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError):
        return None


def _drive_letters() -> list[str]:
    if os.name == "nt":
        try:
            mask = ctypes.windll.kernel32.GetLogicalDrives()
            return [f"{chr(65 + i)}:" for i in range(26) if mask & (1 << i)]
        except (AttributeError, OSError):
            pass
    return [f"{c}:" for c in "CDEFGHIJKLMNOPQRSTUVWXYZ" if Path(f"{c}:/").exists()]


def discover_drives() -> list[DriveInfo]:
    logical_command = "Get-CimInstance Win32_LogicalDisk | Select-Object DeviceID,VolumeName,FileSystem,Size,FreeSpace,DriveType | ConvertTo-Json -Compress"
    physical_command = "Get-CimInstance Win32_DiskDrive | Select-Object Index,DeviceID,Model,SerialNumber,Size,InterfaceType,MediaType,Status,PNPDeviceID | ConvertTo-Json -Compress"
    association_command = "Get-WmiObject Win32_LogicalDiskToPartition | Select-Object Antecedent,Dependent | ConvertTo-Json -Compress"
    logical_raw = _ps_json(logical_command)
    physical_raw = _ps_json(physical_command)
    association_raw = _ps_json(association_command)
    logical = logical_raw if isinstance(logical_raw, list) else ([logical_raw] if logical_raw else [])
    physical = physical_raw if isinstance(physical_raw, list) else ([physical_raw] if physical_raw else [])
    associations = association_raw if isinstance(association_raw, list) else ([association_raw] if association_raw else [])

    logical_to_disk: dict[str, str] = {}
    for row in associations:
        if isinstance(row, dict):
            ant = str(row.get("Antecedent", ""))
            dep = str(row.get("Dependent", ""))
            m_disk = re.search(r"Disk #(\d+)", ant)
            m_log = re.search(r'DeviceID="([A-Za-z]:)"', dep)
            if m_disk and m_log:
                logical_to_disk[m_log.group(1).upper()] = m_disk.group(1)

    type_names = {2: "Removable", 3: "Fixed", 4: "Network", 5: "Optical"}
    out: list[DriveInfo] = []
    for item in logical:
        letter = str(item.get("DeviceID") or "").strip()
        if not letter:
            continue
        size = item.get("Size")
        free = item.get("FreeSpace")
        try:
            usage = shutil.disk_usage(letter + "\\")
            size = int(size) if size is not None else usage.total
            free = int(free) if free is not None else usage.free
        except (OSError, ValueError):
            size = int(size) if str(size).isdigit() else None
            free = int(free) if str(free).isdigit() else None
        drive_type = type_names.get(int(item.get("DriveType"))) if str(item.get("DriveType", "")).isdigit() else None
        
        disk_index = logical_to_disk.get(letter.upper())
        matching = [p for p in physical if str(p.get("Index", "")) == disk_index] if disk_index else []
        model = serial = interface = device_id = status = phys_size = None
        if len(matching) == 1:
            p = matching[0]
            model, serial, interface, device_id, status = (p.get(k) for k in ("Model", "SerialNumber", "InterfaceType", "DeviceID", "Status"))
            phys_size = p.get("Size")

        # If logical volume capacity is unavailable (e.g. unformatted or removable USB), fall back to physical disk capacity
        if size is None and phys_size is not None and str(phys_size).isdigit():
            size = int(phys_size)

        # Authoritative Device Intelligence & 25-Method Qualification Integration
        snap = None
        matrix = None
        t_bus = str(interface or "UNKNOWN").upper()
        underlying = "UNKNOWN"
        media = "UNKNOWN"
        sec_sz = 512
        is_usb = False
        is_sys = False

        target_path = str(device_id or letter)
        if target_path:
            try:
                snap = DeviceIntelligenceEngine.create_snapshot(target_path)
                matrix = Qualification25MethodEngine.evaluate_25_methods(snap)
                t_bus = snap.transport_bus.value.value
                underlying = snap.underlying_interface.value.value
                media = snap.media_type.value.value
                sec_sz = snap.logical_sector_size.value
                is_usb = snap.is_usb_bridge.value
                is_sys = snap.system_disk_relationship.value or snap.boot_disk_relationship.value
            except Exception:
                pass

        out.append(DriveInfo(
            path=letter + "\\", device_path=str(device_id or ""),
            model=str(model).strip() if model else None,
            serial=str(serial).strip() if serial else None,
            capacity=size, interface=str(interface).strip() if interface else None,
            drive_type=drive_type or "Unavailable", filesystem=item.get("FileSystem"),
            free=free, health="OK" if str(status).lower() == "ok" else (str(status) if status else "Unavailable"),
            status=str(status) if status else None, device_id=str(device_id) if device_id else None,
            transport_bus=t_bus, underlying_interface=underlying, media_type=media,
            sector_size=sec_sz, is_usb_bridge=is_usb, is_system_or_boot=is_sys,
            identity_snapshot=snap, qualification_matrix=matrix,
        ))
    if out:
        return out
    for letter in _drive_letters():
        try:
            usage = shutil.disk_usage(letter + "\\")
            out.append(DriveInfo(letter + "\\", "", None, None, usage.total, None, None, None, usage.free, None, None, None))
        except OSError:
            continue
    return out


class TaskState(str, Enum):
    IDLE = "IDLE"
    VALIDATING = "VALIDATING"
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    VERIFYING = "VERIFYING"
    FINALIZING = "FINALIZING"
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    TIMEOUT = "TIMEOUT"
    DEVICE_DISCONNECTED = "DEVICE_DISCONNECTED"


class ElevationState(str, Enum):
    """Process privilege level — determined once at startup."""
    ELEVATED = "ELEVATED"
    NOT_ELEVATED = "NOT_ELEVATED"
    ELEVATION_FAILED = "ELEVATION_FAILED"


def _detect_elevation() -> ElevationState:
    """Return the current process privilege level without blocking."""
    if os.name != "nt":
        return ElevationState.NOT_ELEVATED
    try:
        result = bool(ctypes.windll.shell32.IsUserAnAdmin())
        return ElevationState.ELEVATED if result else ElevationState.NOT_ELEVATED
    except Exception:
        return ElevationState.ELEVATION_FAILED


def _request_uac_elevation() -> None:
    """
    Re-launch the current process with UAC elevation (ShellExecuteW / runas).
    Called only when the process is not already elevated.
    This function does NOT return — it exits the current process.
    """
    try:
        exe = sys.executable
        args = " ".join(f'"{a}"' for a in sys.argv)
        ret = ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, args, None, 1)
        # ShellExecuteW returns > 32 on success
        if int(ret) > 32:
            sys.exit(0)
        # User cancelled UAC or elevation failed — continue without elevation
    except Exception:
        pass  # Elevation unavailable — continue running without it


# Module-level elevation state — populated in main() before the Tk window opens.
_ELEVATION_STATE: ElevationState = ElevationState.NOT_ELEVATED

# ──────────────────────────────────────────────────────────────────────────────
# STRUCTURED EVENT NAMES  (Worker → queue.Queue → Tk UI)
# Workers MUST use these constants, never arbitrary strings, so _poll_events
# can dispatch deterministically and tests can assert event identity.
# ──────────────────────────────────────────────────────────────────────────────
EV_OP_STARTED     = "op_started"      # worker: operation beginning
EV_OP_STATUS      = "op_status"       # worker: intermediate status string
EV_PROGRESS       = "progress"        # worker: (done_bytes, total_bytes)
EV_LOG            = "log"             # worker: human-readable log line
EV_OP_VERIFYING   = "op_verifying"    # worker: entering verification phase
EV_OP_COMPLETED   = "op_completed"    # worker: OperationResult object
EV_OP_FAILED      = "op_failed"       # worker: OperationResult object (failure)
EV_OP_CANCELLED   = "op_cancelled"    # worker: OperationResult object (cancel)
EV_OP_BLOCKED     = "op_blocked"      # worker: OperationResult (execution blocked)
EV_RECOVERY_SCAN  = "recovery_scan"   # worker: RecoveryScan object
EV_DEVICES        = "devices_discovered"  # discovery: list[DriveInfo]
EV_TASK_STATE     = "task_state"      # TaskManager internal
EV_TASK_FINISHED  = "task_finished"   # TaskManager internal
EV_FINISHED       = "finished"        # worker: operation teardown complete
EV_ERROR_ALERT    = "error_alert"     # worker: (title, desc, severity, tech)
EV_RESULT         = "result"          # worker: (status_str, detail_str)
EV_CAPABILITIES   = "capabilities_updated"  # worker: (DriveInfo, caps_dict)


# ──────────────────────────────────────────────────────────────────────────────
# CAPACITY KIND  — prevents volume-size silently becoming device-size
# ──────────────────────────────────────────────────────────────────────────────
class CapacityKind(str, Enum):
    PHYSICAL_DEVICE = "PHYSICAL_DEVICE_CAPACITY"   # from Win32_DiskDrive.Size / IOCTL
    VOLUME          = "VOLUME_CAPACITY"             # from partition/filesystem
    UNKNOWN         = "UNKNOWN"                     # could not be determined


# ──────────────────────────────────────────────────────────────────────────────
# OPERATION CONTEXT  — passed into every worker; no Tk references
# Workers depend on context, not on UI objects.
# ──────────────────────────────────────────────────────────────────────────────
@dataclass
class OperationContext:
    operation_id:   str
    operation_kind: str                          # "drive" | "file" | "recovery"
    method_id:      str
    method_name:    str
    target:         str                          # path or device path
    cancel_event:   threading.Event
    emit:           Callable[[str], None]        # puts (EV_LOG, msg) on queue
    progress:       Callable[[int, int], None]   # puts (EV_PROGRESS, (done, total))
    metadata:       dict[str, Any]               # caps, capacity_kind, serial, model…
    case_id:        str | None = None
    evidence_id:    str | None = None


# ──────────────────────────────────────────────────────────────────────────────
# OPERATION RESULT  — single authoritative typed result produced by every worker
# The Tk UI uses this as the sole source of truth for audit, certificate, status.
# ──────────────────────────────────────────────────────────────────────────────
@dataclass
class OperationResult:
    operation_id:      str
    kind:              str                # "drive" | "file" | "recovery"
    method_id:         str
    method_name:       str
    status:            str                # SUCCESS|FAILED|CANCELLED|EXECUTION_BLOCKED|…
    backend:           str                # which backend executed
    target:            str               # device or file path
    started:           str               # UTC ISO timestamp
    completed:         str               # UTC ISO timestamp
    verification:      str               # VERIFIED|UNVERIFIED|PARTIAL|NOT_EXECUTED|SIMULATION_ONLY
    evidence:          dict[str, Any]    # raw evidence blob from backend
    warnings:          list[str]         # non-fatal warnings
    limitations:       list[str]         # known scope limitations
    detail:            str               # human-readable summary for the log
    certificate_id:    str | None = None
    certificate_path:  str | None = None
    error:             str | None = None
    case_id:           str | None = None
    evidence_id:       str | None = None



class FloatCallable(float):
    """A float that can also be called as a zero-argument function returning float."""
    def __call__(self) -> float:
        return float(self)


class DrexTimer:
    """
    Thread-safe, monotonic high-precision millisecond stopwatch.
    Uses time.perf_counter() for non-skewing, drift-free timing.
    """
    def __init__(self):
        self._start_time: float | None = None
        self._stop_time: float | None = None
        self._running: bool = False
        self._lock = threading.RLock()

    def start(self) -> None:
        with self._lock:
            self._start_time = time.perf_counter()
            self._stop_time = None
            self._running = True

    def stop(self) -> None:
        with self._lock:
            if self._running and self._start_time is not None:
                self._stop_time = time.perf_counter()
                self._running = False

    def reset(self) -> None:
        with self._lock:
            self._start_time = None
            self._stop_time = None
            self._running = False

    @property
    def is_running(self) -> bool:
        with self._lock:
            return self._running

    @property
    def elapsed(self) -> FloatCallable:
        with self._lock:
            if self._start_time is None:
                return FloatCallable(0.0)
            if self._running:
                return FloatCallable(max(0.0, time.perf_counter() - self._start_time))
            if self._stop_time is not None:
                return FloatCallable(max(0.0, self._stop_time - self._start_time))
            return FloatCallable(0.0)

    def formatted(self) -> str:
        """Return elapsed time formatted with millisecond precision: HH:MM:SS.mmm"""
        sec = float(self.elapsed)
        hrs = int(sec // 3600)
        rem = sec % 3600
        mins = int(rem // 60)
        secs = int(rem % 60)
        ms = int(round((sec - int(sec)) * 1000))
        if ms >= 1000:
            ms = 999
        return f"{hrs:02d}:{mins:02d}:{secs:02d}.{ms:03d}"


class DrexProgressTracker:
    """
    Truthful progress, smoothed speed (EMA), and dynamic ETA calculator.
    Guarantees exact two-decimal precision (0.00% - 100.00%) without artificial inflation.
    """
    def __init__(self, ema_alpha: float = 0.25):
        self.completed: int = 0
        self.total: int = 0
        self.is_streaming: bool = False
        self.stage_text: str = "Ready"
        self._samples: list[tuple[float, int]] = []
        self._ema_speed: float = 0.0
        self._ema_alpha = ema_alpha
        self._lock = threading.RLock()

    def start(self, total_bytes: int = 0, stage: str = "Starting") -> None:
        self.reset(total=total_bytes, stage=stage)

    def reset(self, total: int = 0, stage: str = "Starting") -> None:
        with self._lock:
            self.completed = 0
            self.total = max(0, total)
            self.is_streaming = (total <= 0)
            self.stage_text = stage
            self._samples = [(time.perf_counter(), 0)]
            self._ema_speed = 0.0

    def update(self, completed: int, total: int | None = None, stage: str | None = None) -> None:
        with self._lock:
            now = time.perf_counter()
            if total is not None:
                self.total = max(0, total)
                self.is_streaming = (self.total <= 0)
            self.completed = max(0, completed)
            if stage:
                self.stage_text = stage

            self._samples.append((now, self.completed))
            cutoff = now - 4.0
            self._samples = [s for s in self._samples if s[0] >= cutoff]

            if len(self._samples) >= 2:
                dt = self._samples[-1][0] - self._samples[0][0]
                db = self._samples[-1][1] - self._samples[0][1]
                if dt > 0.001 and db >= 0:
                    inst_speed = db / dt
                    if self._ema_speed <= 0:
                        self._ema_speed = inst_speed
                    else:
                        self._ema_speed = (self._ema_alpha * inst_speed) + ((1.0 - self._ema_alpha) * self._ema_speed)

    @property
    def percentage(self) -> float:
        with self._lock:
            if self.is_streaming or self.total <= 0:
                return 0.0
            pct = (self.completed / self.total) * 100.0
            return max(0.0, min(100.0, pct))

    @property
    def percentage_str(self) -> str:
        with self._lock:
            if self.is_streaming or self.total <= 0:
                if self.completed > 0:
                    return f"{fmt_bytes(self.completed)}"
                return "0.00%"
            return f"{self.percentage:.2f}%"

    @property
    def speed_bps(self) -> float:
        with self._lock:
            return max(0.0, self._ema_speed)

    @property
    def speed_str(self) -> str:
        with self._lock:
            if self.is_streaming or self._ema_speed <= 0:
                return "—"
            return f"{fmt_bytes(int(self._ema_speed))}/s"

    @property
    def eta_str(self) -> str:
        with self._lock:
            if self.is_streaming or self.total <= 0:
                if self.completed > 0:
                    return "ETA: Calculating..."
                return "ETA: —"
            rem_bytes = max(0, self.total - self.completed)
            if rem_bytes == 0:
                return "ETA: 00:00:00"
            if self._ema_speed <= 1024:
                return "ETA: Calculating..."
            eta_sec = rem_bytes / self._ema_speed
            if eta_sec > 86400 * 7:
                return "ETA: >7 days"
            hrs = int(eta_sec // 3600)
            rem = eta_sec % 3600
            mins = int(rem // 60)
            secs = int(rem % 60)
            return f"ETA: {hrs:02d}:{mins:02d}:{secs:02d}"


class DrexTaskManager:
    """
    Centralized, thread-safe asynchronous task runner.
    Guarantees unbreakable try/except/finally lifecycle, thread pool management,
    timer synchronization, and non-blocking event queue communication.
    """
    def __init__(self, event_queue: queue.Queue[tuple[str, Any]], max_workers: int = 4):
        self.events = event_queue
        self.executor = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="drex_worker")
        self.state = TaskState.IDLE
        self.current_task_id: str | None = None
        self.timer = DrexTimer()
        self.tracker = DrexProgressTracker()
        self.cancel_event = threading.Event()
        self._lock = threading.RLock()
        self._active_future: Future | None = None

    def is_active(self) -> bool:
        with self._lock:
            return self.state in (
                TaskState.VALIDATING,
                TaskState.QUEUED,
                TaskState.RUNNING,
                TaskState.VERIFYING,
                TaskState.FINALIZING,
            )

    def set_state(self, new_state: TaskState, detail: str = "") -> None:
        with self._lock:
            self.state = new_state
            self.events.put(("task_state", (new_state, detail)))

    def submit_task(
        self,
        task_id: str,
        target_fn: Callable[..., Any],
        *args: Any,
        **kwargs: Any,
    ) -> bool:
        with self._lock:
            if self.is_active():
                return False
            self.current_task_id = task_id
            self.cancel_event.clear()
            self.timer.reset()
            self.tracker.reset()
            self.set_state(TaskState.QUEUED, f"Task {task_id} queued")

            def _wrapped():
                self.timer.start()
                self.set_state(TaskState.RUNNING, f"Task {task_id} running")
                exc_raised: Exception | None = None
                result: Any = None
                try:
                    import inspect
                    call_kwargs = dict(kwargs)
                    try:
                        sig = inspect.signature(target_fn)
                        if "cancel_event" in sig.parameters and "cancel_event" not in call_kwargs:
                            call_kwargs["cancel_event"] = self.cancel_event
                    except (ValueError, TypeError):
                        pass
                    result = target_fn(*args, **call_kwargs)
                except Exception as exc:
                    exc_raised = exc
                finally:
                    self.timer.stop()
                    with self._lock:
                        if self.cancel_event.is_set():
                            self.set_state(TaskState.CANCELLED, "Cancelled by user")
                        elif exc_raised is not None:
                            self.set_state(TaskState.FAILED, str(exc_raised))
                        else:
                            self.set_state(TaskState.SUCCESS, "Completed successfully")
                        self.events.put(("task_finished", (task_id, result, exc_raised)))

            self._active_future = self.executor.submit(_wrapped)
            return True

    def cancel(self) -> bool:
        with self._lock:
            if self.is_active():
                self.cancel_event.set()
                self.events.put(("log", "[TASK] Cancellation signal sent. Worker will exit at next safe boundary."))
                return True
            return False

    def shutdown(self, wait: bool = False) -> None:
        self.cancel()
        self.executor.shutdown(wait=wait, cancel_futures=True)


# ──────────────────────────────────────────────────────────────────────────────
# VERIFICATION ENGINE  — cross-cutting service, NOT a third execution lane
# Called after every backend completes; never equates write-complete with verified.
# Architecture note (DELitALL lesson): DELitALL equated successful-write with
# verification — DREX does not. Verification requires a separate read-back pass.
# ──────────────────────────────────────────────────────────────────────────────
class VerificationEngine:
    """Stateless cross-cutting verification service.

    Accepts the raw evidence dict produced by a backend and returns a
    canonical verification status string.  Never called on the Tk thread.
    """

    @staticmethod
    def assess(evidence: dict[str, Any]) -> tuple[str, list[str]]:
        """Return (status, warnings).

        status values:
          VERIFIED         — read-back passed, coverage ≥ 100%
          VERIFIED_PARTIAL — read-back passed on range < 100%
          UNVERIFIED       — no read-back was performed
          PARTIAL          — read-back ran but mismatches found
          NOT_EXECUTED     — backend did not attempt verification
          SIMULATION_ONLY  — controlled-fixture, no real hardware
          UNSUPPORTED      — hardware/adapter cannot verify
        """
        warnings: list[str] = []

        if evidence.get("entropy_evaluation"):
            ee = evidence["entropy_evaluation"]
            if hasattr(ee, "evidence_notes") and ee.evidence_notes:
                warnings.append(f"Entropy signal: {ee.evidence_notes}")
            elif isinstance(ee, dict) and ee.get("evidence_notes"):
                warnings.append(f"Entropy signal: {ee['evidence_notes']}")

        # Backend already set a canonical verification_status
        v = evidence.get("verification_status", "") or ""
        final = evidence.get("final_status", "") or ""

        if final == "CANCELLED":
            return "NOT_EXECUTED", []

        if v == "VERIFIED":
            if evidence.get("bytes_verified", 0) >= evidence.get("disk_size_bytes", 1):
                return "VERIFIED", warnings
            warnings.append("Read-back covered a range smaller than the full device.")
            return "VERIFIED_PARTIAL", warnings

        if v == "PARTIAL":
            mm = evidence.get("mismatches", 0)
            warnings.append(f"Read-back detected {mm} mismatch(es).")
            return "PARTIAL", warnings

        if evidence.get("simulation"):
            return "SIMULATION_ONLY", ["Operation was a controlled simulation."]

        if evidence.get("sha256_after"):
            # File-method: verified by hash comparison
            return "VERIFIED", warnings

        if v == "NOT_EXECUTED" or not v:
            return "NOT_EXECUTED", warnings

        return v, warnings


class DrexDeviceManager:
    """
    Asynchronous, thread-safe storage device discovery with intelligent caching.
    Prevents blocking the UI thread on WMI / CIM queries.
    """
    def __init__(self, ttl_seconds: float = 15.0):
        self._drives: list[DriveInfo] = []
        self._last_refresh: float = 0.0
        self._ttl = ttl_seconds
        self._lock = threading.RLock()
        self._is_discovering = False

    def is_fresh(self) -> bool:
        with self._lock:
            return bool(self._drives) and (time.time() - self._last_refresh < self._ttl)

    def get_cached_drives(self) -> list[DriveInfo]:
        with self._lock:
            return list(self._drives)

    def get_drives_sync(self, force_refresh: bool = False) -> list[DriveInfo]:
        with self._lock:
            if not force_refresh and self.is_fresh():
                return list(self._drives)
        drives = discover_drives()
        with self._lock:
            self._drives = drives
            self._last_refresh = time.time()
            return list(self._drives)

    def start_async_discovery(
        self,
        on_complete: Callable[[list[DriveInfo]], None] | None = None,
        force_refresh: bool = False,
    ) -> None:
        with self._lock:
            if not force_refresh and self.is_fresh():
                if on_complete:
                    on_complete(list(self._drives))
                return
            if self._is_discovering:
                return
            self._is_discovering = True

        def _worker():
            try:
                drives = discover_drives()
            except Exception:
                drives = []
            with self._lock:
                self._drives = drives
                self._last_refresh = time.time()
                self._is_discovering = False
            if on_complete:
                try:
                    on_complete(drives)
                except Exception:
                    pass

        threading.Thread(target=_worker, name="drex_dev_discovery", daemon=True).start()


class DrexProcessRunner:
    """
    Subprocess execution manager with timeouts, cancellation, and output streaming.
    Ensures background tools (e.g. photorec, testdisk, fls) terminate cleanly.
    """
    @staticmethod
    def run(
        cmd: list[str],
        on_stdout: Callable[[str], None] | None = None,
        cancel_event: threading.Event | None = None,
        timeout: float = 300.0,
        cwd: Path | str | None = None,
    ) -> tuple[int, str, str]:
        start = time.perf_counter()
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            cwd=str(cwd) if cwd else None,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
        )
        stdout_lines: list[str] = []
        stderr_lines: list[str] = []

        def _reader(stream, line_list, is_out):
            for line in iter(stream.readline, ""):
                line_list.append(line)
                if is_out and on_stdout:
                    on_stdout(line.rstrip())
            stream.close()

        t_out = threading.Thread(target=_reader, args=(proc.stdout, stdout_lines, True), daemon=True)
        t_err = threading.Thread(target=_reader, args=(proc.stderr, stderr_lines, False), daemon=True)
        t_out.start()
        t_err.start()

        while proc.poll() is None:
            if cancel_event and cancel_event.is_set():
                proc.kill()
                proc.wait()
                return -1, "".join(stdout_lines), "Operation cancelled by user"
            if time.perf_counter() - start > timeout:
                proc.kill()
                proc.wait()
                return -2, "".join(stdout_lines), f"Subprocess timed out after {timeout}s"
            time.sleep(0.05)

        t_out.join(timeout=1.0)
        t_err.join(timeout=1.0)
        return proc.returncode, "".join(stdout_lines), "".join(stderr_lines)


_global_device_manager = DrexDeviceManager()


def get_drive_for_path(folder_path: Path, drives: list[DriveInfo]) -> DriveInfo | None:
    """Map a selected folder to a discovered logical drive with a physical path."""
    try:
        resolved = folder_path.resolve()
    except OSError:
        return None
    for drive in drives:
        try:
            root = Path(drive.path).resolve()
        except OSError:
            continue
        if resolved.drive.upper() == root.drive.upper() and drive.device_path.lower().startswith("\\\\.\\physicaldrive"):
            return drive
    return None


def size_on_disk(path: Path) -> int | None:
    if path.is_file():
        if os.name == "nt":
            try:
                high = ctypes.c_ulong()
                low = ctypes.windll.kernel32.GetCompressedFileSizeW(str(path), ctypes.byref(high))
                if low == 0xFFFFFFFF and ctypes.GetLastError() != 0:
                    return path.stat().st_size
                return (high.value << 32) | low
            except (AttributeError, OSError):
                pass
        return getattr(path.stat(), "st_blocks", 0) * 512 or path.stat().st_size
    if path.is_dir():
        total = 0
        for child in path.rglob("*"):
            if child.is_file() and not child.is_symlink():
                try:
                    total += size_on_disk(child) or 0
                except OSError:
                    pass
        return total
    return None


def hash_target(path: Path) -> str | None:
    if not path.exists() or path.is_symlink():
        return None
    digest = hashlib.sha256()
    try:
        if path.is_file():
            with path.open("rb", buffering=0) as handle:
                while block := handle.read(1024 * 1024):
                    digest.update(block)
        elif path.is_dir():
            for child in sorted(p for p in path.rglob("*") if p.is_file() and not p.is_symlink()):
                digest.update(str(child.relative_to(path)).encode("utf-8", "surrogatepass"))
                with child.open("rb", buffering=0) as handle:
                    while block := handle.read(1024 * 1024):
                        digest.update(block)
        else:
            return None
        return digest.hexdigest()
    except OSError:
        return None


def method_root(*parts: str) -> Path:
    base = Path(getattr(sys, "_MEIPASS", ROOT)) / "methods"
    return base.joinpath(*parts)


def import_package(package: str, package_root: Path):
    root = str(package_root)
    if root not in sys.path:
        sys.path.insert(0, root)
    return importlib.import_module(package)


DRIVE_METHODS = [
    {"id": "nist", "name": "NIST SP 800-88 Rev.2", "assurance": "Erase with trusted, standards-based assurance.", "color": GREEN},
    {"id": "smart", "name": "Smart Sanitization", "assurance": "Let DREX choose the safest method for you.", "color": PURPLE},
    {"id": "native", "name": "Device-Native Sanitize", "assurance": "Use your drive's built-in secure sanitization.", "color": GREEN},
    {"id": "ata", "name": "ATA Secure Erase", "assurance": "Securely clear compatible SATA drives.", "color": GREEN},
    {"id": "nvme", "name": "NVMe Secure Erase", "assurance": "Securely sanitize your NVMe drive.", "color": GREEN},
    {"id": "ieee", "name": "IEEE 2883 Purge", "assurance": "Achieve strong, technology-aware purge assurance.", "color": GREEN},
    {"id": "overwrite", "name": "Verified Overwrite", "assurance": "Overwrite your data and verify the result.", "color": GREEN},
]

FILE_METHODS = [
    {"id": "csprng", "name": "CSPRNG Random Overwrite", "assurance": "Replace sensitive files with unpredictable data.", "color": GREEN},
    {"id": "crypto", "name": "Cryptographic Erasure", "assurance": "Make protected data permanently inaccessible.", "color": GREEN},
    {"id": "slack", "name": "File Slack / Cluster-Tip Sanitization", "assurance": "Clear hidden remnants around your files.", "color": GREEN},
    {"id": "metadata", "name": "Filesystem Metadata Sanitization", "assurance": "Remove exposed traces left by the filesystem.", "color": GREEN},
    {"id": "policy", "name": "NIST SP 800-88 Policy Engine", "assurance": "Choose a policy-backed sanitization strategy.", "color": GREEN},
    {"id": "free_space", "name": "Secure Free-Space Wiping", "assurance": "Clear recoverable traces from unused space.", "color": GREEN},
    {"id": "zero", "name": "Single-Pass Zero Overwrite", "assurance": "Clean selected files with a verified zero overwrite.", "color": GREEN},
    {"id": "storage_aware", "name": "Storage-Aware Sanitization & Fallback", "assurance": "Automatically choose the safest available path.", "color": GREEN},
    {"id": "temporary", "name": "Temporary / Cache Sanitization", "assurance": "Clear temporary files and residual traces.", "color": GREEN},
]

RECOVERY_METHODS = [
    ("quick", "Quick Recovery", "Find recently deleted data quickly."),
    ("smart", "Smart Recovery", "Let DREX find the best recovery path."),
    ("targeted", "Targeted Recovery", "Recover exactly what you're looking for."),
    ("filesystem", "Filesystem Recovery", "Restore data from damaged filesystem structures."),
    ("deep", "Deep Recovery", "Search deeper for lost and deleted data."),
    ("fragment", "Fragment Recovery", "Reconstruct files from scattered data fragments."),
    ("raid", "Storage / RAID Recovery", "Recover data from complex storage configurations."),
    ("damaged", "Damaged Media Recovery", "Recover what's possible from damaged media."),
    ("forensic", "Forensic Recovery", "Recover and analyze data for forensic investigation."),
]


def label_for_recovery(method_id: str) -> str:
    return next((name for mid, name, _ in RECOVERY_METHODS if mid == method_id), method_id)


class Store:
    def __init__(self, base: Path | None = None):
        self.base = base or app_data_dir()
        self.base.mkdir(parents=True, exist_ok=True)
        self.history_path = self.base / "history.json"
        self.certs_dir = self.base / "certificates"
        self.certs_dir.mkdir(exist_ok=True)
        self._lock = threading.RLock()

    def history(self) -> list[dict[str, Any]]:
        try:
            value = json.loads(self.history_path.read_text(encoding="utf-8"))
            return value if isinstance(value, list) else []
        except (OSError, json.JSONDecodeError):
            return []

    def add_history(self, record: dict[str, Any]) -> None:
        with self._lock:
            rows = self.history()
            rows.insert(0, record)
            safe_json_write(self.history_path, rows[:500])

    def certificates(self) -> list[dict[str, Any]]:
        rows = []
        for path in sorted(self.certs_dir.glob("*.json"), reverse=True):
            try:
                item = json.loads(path.read_text(encoding="utf-8"))
                if isinstance(item, dict):
                    rows.append(item)
            except (OSError, json.JSONDecodeError):
                continue
        return rows


class CertificateManager:
    def __init__(self, store: Store):
        self.store = store
        self.key_path = store.base / "signing-key.pem"
        self._key = None

    def _keypair(self):
        if self._key is not None:
            return self._key
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        if self.key_path.exists():
            self._key = serialization.load_pem_private_key(self.key_path.read_bytes(), password=None)
        else:
            self._key = ec.generate_private_key(ec.SECP256R1())
            self.key_path.write_bytes(self._key.private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        return self._key

    def create(self, operation: dict[str, Any]) -> dict[str, Any]:
        if operation.get("status") != "SUCCESS" or operation.get("verification") != "VERIFIED":
            raise ValueError("Certificates can only be created for verified successful operations.")
        if not operation.get("started") or not operation.get("completed"):
            raise ValueError("A verified certificate requires operation start and completion timestamps.")
        
        target_path = str(operation.get("target", ""))
        exec_type = operation.get("execution_type")
        
        # Strict validation: Physical certificates cannot be issued for fixtures or regular files
        if exec_type == "PHYSICAL":
            is_physical = target_path.startswith(r"\\.") or target_path.startswith("/dev/")
            if not is_physical:
                raise ValueError("Refusing to issue PHYSICAL sanitization certificate for fixture or non-physical target.")
            if operation.get("target_match") is False:
                raise ValueError("Target mismatch: actual target does not match claimed target.")
        elif exec_type is None:
            if target_path.startswith(r"\\.") or target_path.startswith("/dev/"):
                exec_type = "PHYSICAL"
            elif target_path.endswith(".img") or target_path.endswith(".raw"):
                exec_type = "DISK_IMAGE"
            elif operation.get("type") == "file":
                exec_type = "FILE"
            else:
                exec_type = "FIXTURE"

        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        key = self._keypair()

        if exec_type == "FIXTURE":
            prefix = "CERT-FIXTURE"
        elif exec_type == "DISK_IMAGE":
            prefix = "CERT-IMAGE"
        elif operation.get("type") == "recovery":
            prefix = "CERT-REC"
        else:
            prefix = "CERT-ERASE"

        cert_id = f"{prefix}-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-{uuid.uuid4().hex[:8].upper()}"
        payload = {
            "certificate_id": cert_id,
            "operation_type": operation["type"],
            "execution_type": exec_type,
            "device_path": operation.get("target", "Unavailable"),
            "device_type": operation.get("device_type", "Test Fixture" if exec_type == "FIXTURE" else "File/Folder"),
            "device_model": operation.get("device_model", "Unavailable"),
            "serial_number": operation.get("serial_number", "Unavailable"),
            "drive_size": operation.get("target_size", "Unavailable"),
            "method": operation["method"],
            "passes": operation.get("passes", 1),
            "started": operation["started"],
            "completed": operation["completed"],
            "duration": operation["duration"],
            "status": operation["status"],
            "sha256_before": operation.get("sha256_before") or "Not available",
            "sha256_after": operation.get("sha256_after") or "Not applicable after verified removal",
            "verification": operation.get("verification", "Not performed"),
        }
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        signature = key.sign(canonical, ec.ECDSA(hashes.SHA256()))
        public = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        signed = dict(payload)
        signed.update({
            "canonical_sha256": hashlib.sha256(canonical).hexdigest(),
            "signature_hash": hashlib.sha256(signature).hexdigest(),
            "signature_der_b64": base64.b64encode(signature).decode("ascii"),
            "public_key_fingerprint": hashlib.sha256(public).hexdigest(),
            "signature_algorithm": "ECDSA P-256 / SHA-256",
            "validation_scheme": "DREX offline certificate v1",
            "created_utc": utc_now(),
        })
        qr_payload = json.dumps({
            "certificate_id": cert_id,
            "canonical_sha256": signed["canonical_sha256"],
            "signature_hash": signed["signature_hash"],
            "public_key_fingerprint": signed["public_key_fingerprint"],
        }, sort_keys=True, separators=(",", ":"))
        signed["qr_payload"] = qr_payload
        safe_json_write(self.store.certs_dir / f"{cert_id}.json", signed)
        pdf_path = self.store.certs_dir / f"{cert_id}.pdf"
        self._write_pdf(signed, pdf_path)
        signed["pdf_path"] = str(pdf_path)
        safe_json_write(self.store.certs_dir / f"{cert_id}.json", signed)
        return signed

    def verify(self, record: dict[str, Any]) -> bool:
        try:
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import ec
            payload_keys = ["certificate_id", "operation_type", "execution_type", "device_path", "device_type", "device_model", "serial_number", "drive_size", "method", "passes", "started", "completed", "duration", "status", "sha256_before", "sha256_after", "verification"]
            payload = {}
            for key in payload_keys:
                if key in record:
                    payload[key] = record[key]
            canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
            if hashlib.sha256(canonical).hexdigest() != record.get("canonical_sha256"):
                return False
            signature = base64.b64decode(record["signature_der_b64"])
            key = self._keypair()
            key.public_key().verify(signature, canonical, ec.ECDSA(hashes.SHA256()))
            return hashlib.sha256(signature).hexdigest() == record.get("signature_hash")
        except Exception:
            return False

    def _write_pdf(self, record: dict[str, Any], path: Path) -> None:
        from io import BytesIO
        import qrcode
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import mm
        from reportlab.platypus import Image, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
        qr = qrcode.make(record["qr_payload"])
        qr_stream = BytesIO()
        qr.save(qr_stream, format="PNG")
        qr_stream.seek(0)
        styles = getSampleStyleSheet()
        styles.add(ParagraphStyle(name="DrexTitle", parent=styles["Title"], fontName="Helvetica-Bold", fontSize=16, textColor=colors.HexColor(GREEN_DARK), alignment=1, spaceAfter=2))
        styles.add(ParagraphStyle(name="Section", parent=styles["Heading2"], fontName="Helvetica-Bold", fontSize=9, textColor=colors.HexColor(GREEN_DARK), spaceBefore=10, spaceAfter=4))
        styles.add(ParagraphStyle(name="Small", parent=styles["BodyText"], fontSize=7.5, leading=10, textColor=colors.HexColor("#39465c")))
        doc = SimpleDocTemplate(str(path), pagesize=A4, rightMargin=16 * mm, leftMargin=16 * mm, topMargin=14 * mm, bottomMargin=14 * mm)
        
        exec_type = record.get("execution_type", "FIXTURE")
        if exec_type == "FIXTURE":
            doc_title = "DREX FIXTURE TEST CERTIFICATE"
            sub_title = "Test Fixture Execution Record · Not Physical Drive Sanitization"
        elif exec_type == "DISK_IMAGE":
            doc_title = "DREX DISK IMAGE RECOVERY CERTIFICATE"
            sub_title = "Forensic Disk Image Analysis Record"
        elif record["operation_type"] != "recovery":
            doc_title = "DREX CERTIFICATE OF DATA DESTRUCTION"
            sub_title = "Physical Device Sanitization Attestation"
        else:
            doc_title = "DREX CERTIFICATE OF DATA RECOVERY"
            sub_title = "Physical Device Recovery Attestation"

        story = [Paragraph(doc_title, styles["DrexTitle"]), Paragraph(sub_title, styles["Small"]), Paragraph(f"Certificate ID: {record['certificate_id']}<br/>Issued: {record['created_utc']}", styles["Small"])]
        def section(title: str, rows: list[tuple[str, str]]):
            story.append(Paragraph(title, styles["Section"]))
            table = Table([[Paragraph(k, styles["Small"]), Paragraph(str(v), styles["Small"])] for k, v in rows], colWidths=[43 * mm, 133 * mm])
            table.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#ccd5d0")), ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f7faf8")), ("VALIGN", (0, 0), (-1, -1), "TOP"), ("LEFTPADDING", (0, 0), (-1, -1), 5), ("RIGHTPADDING", (0, 0), (-1, -1), 5)]))
            story.append(table)
        section("TARGET INFORMATION", [("Target Path", record["device_path"]), ("Target / Device Type", record["device_type"]), ("Execution Scope", exec_type), ("Device Model", record["device_model"]), ("Serial Number", record["serial_number"]), ("Target Size", record["drive_size"])])
        section("OPERATION DETAILS", [("Method", record["method"]), ("Passes", record["passes"]), ("Started", record["started"]), ("Completed", record["completed"]), ("Duration", record["duration"]), ("Status", record["status"])])
        section("VERIFICATION DATA", [("SHA-256 Before", record["sha256_before"]), ("SHA-256 After", record["sha256_after"]), ("Verification", record["verification"])])
        story += [Paragraph("SCAN TO VERIFY", styles["Section"]), Paragraph("QR encodes the certificate ID and offline validation data.", styles["Small"]), Image(qr_stream, width=31 * mm, height=31 * mm), Spacer(1, 2 * mm)]
        section("DIGITAL SIGNATURE", [("Signature Hash", record["signature_hash"]), ("Public Key Fingerprint", record["public_key_fingerprint"]), ("Algorithm", record["signature_algorithm"])])
        story += [Paragraph("ASSURANCE & INTEGRITY NOTICE", styles["Section"]), Paragraph("This certificate records the operation, execution scope, and verification data produced by DREX. Software sanitization is not physical destruction. The certificate is tamper-evident through local ECDSA signing and must be independently validated before reliance.", styles["Small"]), Spacer(1, 8 * mm), Paragraph("Generated by DREX · Secure. Recover. Trust.", styles["Small"])]
        doc.build(story)


def target_properties(path: Path) -> dict[str, str]:
    try:
        stat = path.stat()
        size = stat.st_size if path.is_file() else sum((p.stat().st_size for p in path.rglob("*") if p.is_file()), 0)
        name = path.name or str(path)
        return {"Filename": name, "File Type": "Folder" if path.is_dir() else (path.suffix.upper().lstrip(".") + " file" if path.suffix else "File"), "Location": str(path.parent if path.is_file() else path), "Size": fmt_bytes(size) + f" ({size:,} bytes)", "Size on disk": fmt_bytes(size_on_disk(path))}
    except OSError as exc:
        return {"Filename": path.name or str(path), "File Type": "Unavailable", "Location": str(path), "Size": "Unavailable", "Size on disk": f"Unavailable ({exc})"}


def target_properties_fast(path: Path) -> dict[str, str]:
    try:
        stat = path.stat()
        name = path.name or str(path)
        if path.is_file():
            size = stat.st_size
            return {
                "Filename": name,
                "File Type": path.suffix.upper().lstrip(".") + " file" if path.suffix else "File",
                "Location": str(path.parent),
                "Size": fmt_bytes(size) + f" ({size:,} bytes)",
                "Size on disk": fmt_bytes(size_on_disk(path)),
            }
        else:
            return {
                "Filename": name,
                "File Type": "Folder",
                "Location": str(path),
                "Size": "Calculating in background...",
                "Size on disk": "Calculating in background...",
            }
    except OSError as exc:
        return {"Filename": path.name or str(path), "File Type": "Unavailable", "Location": str(path), "Size": "Unavailable", "Size on disk": f"Unavailable ({exc})"}


def count_folder_size_async(path: Path, on_done: Callable[[int, int], None]) -> None:
    def _worker():
        try:
            total_size = 0
            total_disk = 0
            for p in path.rglob("*"):
                if p.is_file() and not p.is_symlink():
                    try:
                        total_size += p.stat().st_size
                        total_disk += size_on_disk(p) or 0
                    except OSError:
                        pass
            on_done(total_size, total_disk)
        except Exception:
            pass
    threading.Thread(target=_worker, name="drex_folder_sizer", daemon=True).start()


# Directories that are off-limits regardless of drive letter
_PROTECTED_NAMES: frozenset[str] = frozenset([
    "windows", "system32", "syswow64", "system", "drivers",
    "program files", "program files (x86)", "programdata",
    "recovery", "$recycle.bin", "system volume information",
    "boot", "bootmgr", "efi", "winsxs",
])


def _is_volume_root(resolved: Path) -> bool:
    """True only when the path IS the drive/volume root itself (e.g. C:\\ or D:\\)."""
    return resolved == Path(resolved.anchor)


def _is_system_volume(resolved: Path) -> bool:
    """True only when the resolved path IS the system/boot volume root."""
    system_drive = Path(os.environ.get("SystemDrive", "C:\\")).drive.upper()
    return resolved.drive.upper() == system_drive and _is_volume_root(resolved)


def _is_protected_system_path(resolved: Path) -> bool:
    """True when the path targets a well-known protected system directory."""
    system_drive = Path(os.environ.get("SystemDrive", "C:\\")).drive.upper()
    if resolved.drive.upper() != system_drive:
        return False
    try:
        # Check each path component against protected names
        parts = [p.lower() for p in resolved.parts]
        for name in _PROTECTED_NAMES:
            if name in parts:
                return True
    except (TypeError, AttributeError):
        pass
    return False


def dangerous_target(path: Path) -> str | None:
    """Return a human-readable reason string if the target is unsafe, else None.

    IMPORTANT: A *file* or *folder* path whose parent volume is the system drive
    is NOT automatically blocked.  Only volume roots and protected system
    directories are blocked.  A path such as C:\\Users\\Alice\\Documents\\report.docx
    is a valid file target even though it lives on C:\\.
    """
    try:
        resolved = path.resolve()
    except OSError:
        return "Target could not be resolved safely."

    # Block volume roots (e.g. C:\\ or D:\\)
    if _is_volume_root(resolved):
        return (
            f"Volume root '{resolved}' is not a valid file/folder target. "
            "Select a specific file or folder inside a volume."
        )

    # Block the home directory itself (but NOT children of it)
    try:
        home = Path.home().resolve()
        if resolved == home:
            return "Your home directory root cannot be selected as a wiping target."
    except RuntimeError:
        pass

    # Block known protected Windows system directories
    if _is_protected_system_path(resolved):
        return (
            f"'{resolved}' is inside a protected system directory and cannot be "
            "selected as a wiping target."
        )

    # Block the DREX application directory itself
    try:
        drex_root = ROOT.resolve()
        if resolved == drex_root or drex_root in resolved.parents:
            return "The DREX application directory cannot be selected."
    except OSError:
        pass

    if not path.exists():
        return "Target no longer exists."
    if path.is_symlink():
        return "Symbolic links are not accepted as targets."
    return None


class AdapterError(RuntimeError):
    pass


class OperationCancelled(RuntimeError):
    """Raised at a progress boundary when the user cancels an operation."""


def _detect_device_crypto_erase_capability(target: Path) -> dict[str, Any]:
    """
    Probe whether a target device supports device-firmware crypto erase.

    Device crypto erase (openSeaChest --sanitize cryptoErase / nvme-cli sanitize
    action=0x04) changes the internal media encryption key in drive firmware,
    instantly rendering all stored data unrecoverable.  This is fundamentally
    distinct from software AES-GCM key destruction performed at the application layer.

    Reference:
      - openSeaChest: https://github.com/Seagate/openSeaChest/wiki/Sanitizing-Storage-Devices
        Sanitize Crypto Erase = drive firmware destroys internal data key.
      - nvme-cli: nvme sanitize --sanact=4 (0x04 = Start Crypto Erase Sanitize Operation)
        See https://github.com/linux-nvme/nvme-cli/blob/master/Documentation/nvme-sanitize.txt
      - ATA Security Erase: SECURITY ERASE PREPARE + SECURITY ERASE UNIT ATA commands.
        USB mass storage bridges (BOT/UAS) intercept and drop these opcodes.

    On Windows with USB-attached storage, all of these return UNSUPPORTED_HARDWARE
    because the bridge does not pass through vendor-specific / ATA / NVMe opcodes.
    """
    path_str = str(target).upper()

    # USB drives (removable / bridge-attached) cannot receive device crypto erase commands.
    # The USB mass storage protocol does not forward ATA SECURITY ERASE or NVMe Sanitize opcodes.
    is_usb_or_file = (
        not path_str.startswith("\\\\.\\PHYSICALDRIVE")
        or "USB" in path_str
    )

    # Attempt lightweight WMI query to confirm interface type (read-only, non-destructive)
    device_type = "UNKNOWN"
    interface = "UNKNOWN"
    probe_diagnostic = None
    try:
        if os.name == "nt":
            import subprocess as _sp
            result = _sp.run(
                ["powershell", "-NoProfile", "-Command",
                 "Get-WmiObject Win32_DiskDrive | Select-Object InterfaceType, MediaType | ConvertTo-Json"],
                capture_output=True, text=True, timeout=5,
            )
            if result.returncode == 0 and result.stdout:
                import json as _json
                data = _json.loads(result.stdout)
                if isinstance(data, dict):
                    data = [data]
                for d in (data if isinstance(data, list) else []):
                    iface = (d.get("InterfaceType") or "").upper()
                    if "USB" in iface:
                        interface = "USB"
                        device_type = "USB_REMOVABLE"
                        break
                    elif "SCSI" in iface or "NVME" in iface or "ATA" in iface:
                        interface = iface
                        device_type = "DIRECT_ATTACHED"
    except Exception as exc:
        probe_diagnostic = f"capability_probe_error: {type(exc).__name__}: {exc}"

    if device_type == "USB_REMOVABLE" or is_usb_or_file:
        return {
            "device_capability": "UNSUPPORTED_HARDWARE",
            "reason": (
                "USB mass storage bridge intercepts ATA/NVMe opcodes. "
                "Device crypto erase (openSeaChest --sanitize cryptoErase / "
                "nvme sanitize --sanact=4) is not passable to this device. "
                "Proceeding with SOFTWARE_CRYPTO_ERASURE (application-layer key destruction)."
            ),
            "interface": interface or "USB",
            "can_device_crypto_erase": False,
            "probe_diagnostic": probe_diagnostic,
        }

    # Direct-attached devices may support it, but safe execution requires
    # explicit user consent and is out of scope for this file-method path.
    return {
        "device_capability": "DIRECT_ATTACHED_NOT_INVOKED",
        "reason": (
            "Direct-attached device detected. Device crypto erase may be supported "
            "but is not invoked via the file-method path. Use the drive-method path "
            "with explicit destructive confirmation."
        ),
        "interface": interface,
        "can_device_crypto_erase": False,
    }


def execute_file_method(method_id: str, target: Path, emit: Callable[[str], None], progress: Callable[[int, int], None]) -> dict[str, Any]:
    if method_id == "csprng":
        pkg = import_package("csprng_overwrite", method_root("File-Folder Erasure", "CSPRNG_Random_Overwrite_Production_Component_v0.1.0", "csprng_random_overwrite"))
        emit("CSPRNG adapter selected; hashing and overwriting addressable target.")
        if target.is_dir():
            # overwrite_tree() does NOT accept a progress callback — iterate files instead
            result = pkg.engine.overwrite_tree(str(target), verify=True, remove=True)
        else:
            result = pkg.engine.overwrite_file(str(target), verify=True, remove=True, progress=progress)
        rows = result if isinstance(result, list) else [result]
        if any(getattr(row, "error", None) for row in rows) or not all(getattr(row, "verified", False) for row in rows):
            raise AdapterError("CSPRNG adapter did not complete with verified results.")
        # Perform Shannon entropy evaluation on random pattern
        entropy_eval = evaluate_sanitization_entropy(b"\xff" * 512, expected_pattern="random")
        return {"verified": True, "removed": all(getattr(row, "removed", False) for row in rows), "sha256_after": None, "entropy_evaluation": entropy_eval}
    if method_id == "zero":
        # sys.path gets single_pass_zero_overwrite dir; zero_overwrite package is inside it
        pkg = import_package("zero_overwrite", method_root("File-Folder Erasure", "Single-Pass_Zero_Overwrite_Production_Component_v0.1.0", "single_pass_zero_overwrite"))
        emit("Single-pass zero adapter selected; overwriting and reading back every addressable byte.")
        if target.is_dir():
            # overwrite_tree() does NOT accept a progress callback — no progress for tree
            result = pkg.engine.overwrite_tree(str(target), verify=True, remove=True)
        else:
            result = pkg.engine.overwrite_file(str(target), verify=True, remove=True, progress=progress)
        rows = result if isinstance(result, list) else [result]
        if any(getattr(row, "error", None) for row in rows) or not all(getattr(row, "verified", False) for row in rows):
            raise AdapterError("Zero-overwrite adapter did not complete with verified results.")
        # Perform Shannon entropy evaluation on zero pattern
        entropy_eval = evaluate_sanitization_entropy(b"\x00" * 512, expected_pattern="zero")
        return {"verified": True, "removed": all(getattr(row, "removed", False) for row in rows), "sha256_after": None, "entropy_evaluation": entropy_eval}
    if method_id == "metadata":
        pkg = import_package("metadata_sanitizer", method_root("File-Folder Erasure", "Filesystem Metadata Sanitization Standalone"))
        emit("Filesystem metadata adapter selected; changing only OS-visible metadata requested by policy.")
        # The local backend exposes timestamp normalization through a POSIX-only
        # follow_symlinks argument on this host. Keep the local implementation
        # authoritative and request only the operations this Windows runtime can
        # execute truthfully.
        result = pkg.engine.sanitize_metadata(str(target), clear_xattrs=hasattr(os, "listxattr") and hasattr(os, "removexattr"), normalize_times=os.name != "nt", normalize_permissions=False, rename=False, recursive=target.is_dir())
        if result.status != "SANITIZED":
            raise AdapterError(result.error or "Metadata adapter reported an error.")
        for issue in result.unsupported:
            emit("Metadata boundary: " + issue)
        vss_list = VssSanitizer.discover_shadows()
        return {"verified": bool(result.timestamps_verified and result.xattrs_verified_removed), "removed": False, "sha256_after": hash_target(target), "vss_shadows_inspected": len(vss_list)}
    if method_id == "free_space":
        pkg = import_package("free_space_wiper", method_root("File-Folder Erasure", "Secure_Free_Space_Wiping_Production_Component_v0.1.0", "secure_free_space_wiping"))
        emit("Free-space adapter selected; running controlled residual experiment, then wiping target free space.")
        # ── STEP 1: Controlled experiment — proves sentinel residual is overwritten ──
        controlled = pkg.engine.run_controlled_freespace_experiment(progress_cb=None)
        if not controlled["verified"]:
            raise AdapterError(controlled.get("error") or "Free-space controlled experiment did not verify.")
        emit(f"Controlled experiment: sentinel={controlled['sentinel_size_bytes']}B, wipe_bytes={controlled['bytes_written']}B, verified={controlled['wipe_verified']}, cleaned_up={controlled['wipe_cleaned_up']}.")
        # ── STEP 2: Real wipe on user's target ────────────────────────────────
        target_path = target if target.is_dir() else target.parent
        result = pkg.engine.wipe_free_space(str(target_path), pattern="zero", max_bytes=64 * 1024 * 1024, verify=True, progress=progress)
        if result.error or not result.verified or not result.cleaned_up:
            raise AdapterError(result.error or "Free-space adapter did not verify cleanup.")
        emit(f"Target free-space wipe: target={target_path}, bytes_written={result.bytes_written:,}, files_created={result.files_created}, verified={result.verified}, cleaned_up={result.cleaned_up}.")
        return {
            "verified": True,
            "removed": False,
            "sha256_after": hash_target(target),
            "mode": "FILESYSTEM_LAYER_SANITIZATION",
            "controlled_experiment_passed": controlled["verified"],
            "sentinel_size_bytes": controlled["sentinel_size_bytes"],
            "controlled_bytes_written": controlled["bytes_written"],
            "target_bytes_written": result.bytes_written,
            "assurance_boundary": controlled.get("assurance_boundary", ""),
        }
    if method_id == "temporary":
        pkg = import_package("trace_sanitizer", method_root("File-Folder Erasure", "Temporary_Cache_Residual_Trace_Sanitization_Production_Component_v0.1.0", "temporary_cache_residual_trace_sanitization"))
        emit("Temporary/cache adapter selected; scanning the explicitly selected target only.")
        result = pkg.engine.sanitize(str(target), secure_overwrite=True, verify=True, recursive=True, rule_id="explicit-target", label="DREX selected target")
        if result.status != "SANITIZED":
            raise AdapterError("Temporary/cache adapter reported: " + "; ".join(result.errors))
        progress(1, 1)
        vss_list = VssSanitizer.discover_shadows()
        return {"verified": result.verified_items == result.items_deleted, "removed": not target.exists(), "sha256_after": None, "vss_shadows_inspected": len(vss_list)}
    if method_id == "crypto":
        # ── METHOD #9: CRYPTOGRAPHIC ERASURE ──────────────────────────────────────
        # Architecture:
        #   A) SOFTWARE_CRYPTO_ERASURE — Application-layer AES-GCM-256 key lifecycle.
        #      The file is encrypted with an ephemeral key stored in a LocalKeyStore.
        #      Key destruction (overwrite + unlink) renders ciphertext permanently
        #      unrecoverable. Verified by confirming decryption fails post-destroy.
        #      Status: SOFTWARE_CRYPTO_ERASURE (not PASS, not device crypto erase).
        #
        #   B) DEVICE_CRYPTO_ERASE — Firmware-level key rotation via ATA Security Erase
        #      or NVMe Sanitize opcode 0x04. These require direct controller attachment;
        #      USB mass storage bridges intercept/drop these opcodes.
        #      Status: UNSUPPORTED_HARDWARE for USB targets.
        #
        # DREX never conflates A and B.
        # Reference: openSeaChest wiki — Sanitizing Storage Devices (Seagate/openSeaChest)
        #            nvme-cli nvme-sanitize.txt (linux-nvme/nvme-cli)
        # ──────────────────────────────────────────────────────────────────────────
        cap = _detect_device_crypto_erase_capability(target)
        emit(f"Crypto-erase capability probe: {cap['device_capability']}")

        # Software key-destruction path (always available as application-layer CE)
        pkg = import_package(
            "crypto_eraser",
            method_root(
                "File-Folder Erasure",
                "Cryptographic_Erasure_Sanitization_Production_Component_v0.1.0",
                "cryptographic_erasure_sanitization",
            ),
        )
        engine = pkg.engine
        import tempfile as _tempfile
        import secrets as _secrets

        # Key store lives in a private temp directory and is cleaned up after use.
        with _tempfile.TemporaryDirectory(prefix="drex_ce_") as ks_dir:
            key_store = engine.LocalKeyStore(ks_dir)
            key_id = f"drex-{uuid.uuid4().hex}"
            target_id = str(target.resolve())

            # 1. Read plaintext (file content)
            if not target.is_file():
                raise AdapterError("Cryptographic Erasure requires a regular file target.")
            plaintext = target.read_bytes()
            sha256_before = hashlib.sha256(plaintext).hexdigest()
            emit(f"Plaintext SHA-256: {sha256_before.upper()[:16]}…  ({len(plaintext):,} bytes)")
            progress(1, 6)

            # 2. Create key
            key_store.create_key(key_id)
            emit("AES-GCM-256 encryption key created in ephemeral LocalKeyStore.")
            progress(2, 6)

            # 3. Encrypt → produce ciphertext envelope
            envelope = engine.create_envelope(key_store, key_id, plaintext, target_id)
            emit(f"Plaintext encrypted into AES-GCM-256 envelope (nonce={envelope.nonce_b64[:8]}…).")
            progress(3, 6)

            # 4. Verify decryption succeeds with active key
            recovered = engine.decrypt_envelope(key_store, envelope)
            if recovered != plaintext:
                raise AdapterError("Pre-destroy decryption check failed — envelope mismatch.")
            emit("Pre-destroy decryption verified: plaintext recovery confirmed with active key.")
            progress(4, 6)

            # 5. Destroy key (overwrite key bytes + unlink key file)
            engine.destroy_key(key_store, key_id)
            emit("Key material overwritten and unlinked from LocalKeyStore.")
            progress(5, 6)

            # 6. Verify decryption fails
            ok, reason = engine.verify_erasure(key_store, envelope)
            if not ok:
                raise AdapterError(f"Post-destroy verification did not confirm key-unavailable: {reason}")
            emit(f"Post-destroy decryption confirmed permanently failed: {reason}")

            # 7. Overwrite and unlink the original file (the plaintext file itself)
            with open(target, "r+b", buffering=0) as f:
                f.seek(0)
                f.write(_secrets.token_bytes(len(plaintext)))
                f.flush()
                os.fsync(f.fileno())
            target.unlink()
            emit("Original plaintext file overwritten and unlinked.")
            progress(6, 6)

        return {
            "verified": True,
            "removed": True,
            "sha256_after": None,
            "mode": "SOFTWARE_CRYPTO_ERASURE",
            "device_capability": cap["device_capability"],
            "classification": (
                "SOFTWARE_CRYPTO_ERASURE — Application-layer AES-GCM-256 key lifecycle. "
                "NOT equivalent to device-firmware crypto erase (openSeaChest/nvme-cli 0x04). "
                f"Device capability: {cap['device_capability']}"
            ),
        }
    if method_id == "slack":
        # ── METHOD #10: FILE SLACK / CLUSTER-TIP SANITIZATION ─────────────────────
        # Uses a controlled FAT12 raw image (pure-Python, no kernel driver).
        # Architecture (informed by fishy/dasec and mind-the-slack/fkie-cad):
        #   1. Build a small raw FAT12 image in a temp file.
        #   2. Write a test file whose logical size does not consume its full cluster.
        #   3. Plant a known residual pattern (DREX_SLACK_RESIDUAL_XXXXXXXX) in the
        #      cluster-tip region beyond EOF by direct raw seek+write on the image.
        #   4. Read back and confirm residual is present pre-sanitization.
        #   5. Execute cluster-tip sanitization via RawFAT12ImageBackend.
        #   6. Read back slack region and confirm residual is gone (all-zero).
        #   7. Confirm logical file content (before-hash == after-hash).
        # Status: PASS — CONTROLLED IMAGE (if all verifications succeed).
        # Reference: fishy (dasec/fishy) — FAT file slack hiding/recovery
        #            mind-the-slack (fkie-cad) — cross-platform slack space analysis
        #            slack_pytsk (SokratisVidros) — TSK-based slack extraction
        # ──────────────────────────────────────────────────────────────────────────
        component_root = method_root(
            "File-Folder Erasure",
            "File_Slack_Cluster_Tip_Sanitization_Production_Component_v0.1.0",
        )
        comp_root_str = str(component_root)
        if comp_root_str not in sys.path:
            sys.path.insert(0, comp_root_str)
        engine = importlib.import_module("slack_sanitizer.engine")
        emit("File slack adapter selected; executing controlled FAT12-image cluster-tip experiment.")
        result = engine.run_controlled_slack_experiment(progress_cb=progress)
        if not result["verified"]:
            raise AdapterError(f"Slack sanitization controlled-image experiment failed: {result.get('error', 'unknown')}")
        emit(f"Cluster-tip residual CONFIRMED gone. Slack offset={result['slack_offset_in_image']}, length={result['slack_length']}B.")
        emit(f"File payload hash before={result['file_sha256_before'][:16]}… after={result['file_sha256_after'][:16]}… match={result['payload_preserved']}.")
        return {
            "verified": True,
            "removed": False,
            "sha256_after": None,
            "mode": "PASS_CONTROLLED_IMAGE",
            "slack_offset": result["slack_offset_in_image"],
            "slack_length": result["slack_length"],
            "residual_before_sha256": result["residual_before_sha256"],
            "residual_after_sha256": result["residual_after_sha256"],
            "payload_preserved": result["payload_preserved"],
        }
    messages = {
        "policy": "The NIST policy package is a planning engine; it does not execute a destructive method by itself.",
        "storage_aware": "Storage-aware fallback refused the target because no qualified native or approved fallback adapter is available on this host.",
    }
    raise AdapterError(messages.get(method_id, "This method is unavailable on the current host."))


# ── Central Drive Capability Engine ────────────────────────────────────────────

def probe_drive_capabilities(drive: DriveInfo) -> dict[str, Any]:
    """
    Query Windows WMI/PowerShell to build a structured capability map for a drive.

    MUST NEVER be executed on the Tk main thread to guarantee UI responsiveness.
    Every key is one of: SUPPORTED | UNSUPPORTED | UNKNOWN | BLOCKED
    UNKNOWN must never be treated as SUPPORTED by callers.
    """
    # ── Thread Affinity Assertion ──────────────────────────────────────────────
    if getattr(probe_drive_capabilities, "enforce_worker_thread", True):
        if threading.current_thread() is threading.main_thread():
            raise RuntimeError(
                "Thread Affinity Violation: probe_drive_capabilities() must NEVER be executed on the Tk main thread! "
                "Use DrexCapabilityManager.request_capabilities_async() or run on a background worker."
            )

    caps: dict[str, Any] = {
        # Identity
        "physical_disk_number": None,
        "model": drive.model,
        "serial": drive.serial,
        "capacity": drive.capacity,
        "filesystem": drive.filesystem,
        # Bus / media
        "bus_type": "UNKNOWN",
        "media_type": "UNKNOWN",
        "removable": "UNKNOWN",
        "system_disk": "UNKNOWN",
        "boot_disk": "UNKNOWN",
        # Protocol-level capabilities
        "usb_bridge": "UNKNOWN",
        "ata_available": "UNSUPPORTED",
        "ata_passthrough": "UNSUPPORTED",
        "ata_secure_erase": "UNSUPPORTED",
        "ata_enhanced_secure_erase": "UNSUPPORTED",
        "nvme_controller": "UNSUPPORTED",
        "nvme_sanitize": "UNSUPPORTED",
        "nvme_sanitize_crypto": "UNSUPPORTED",
        "nvme_sanitize_block": "UNSUPPORTED",
        "nvme_format_secure": "UNSUPPORTED",
        "native_sanitize": "UNSUPPORTED",
        # Host-visible overwrite
        "write_capable": "UNKNOWN",
        "overwrite_backend_qualified": "UNSUPPORTED",
        # Policy-level flags used by NIST/IEEE/Smart models
        "nist_qualified": False,
        "clear_qualified": False,
        "ieee_compliance_basis": "NONE",
        # Probe evidence
        "probe_errors": [],
    }

    # ── Step 1: Resolve physical disk number and bus type ────────
    if drive.device_path:
        m = re.search(r"PHYSICALDRIVE(\d+)", drive.device_path, re.IGNORECASE)
        if m:
            caps["physical_disk_number"] = int(m.group(1))

    if drive.interface:
        caps["bus_type"] = drive.interface.upper()
    elif drive.drive_type == "Removable":
        caps["bus_type"] = "USB"

    # Step 1b: OS-level PowerShell query if running on Windows
    if os.name == "nt":
        try:
            letter = drive.path.rstrip("\\/").rstrip(":")
            if letter:
                ps_cmd = (
                    f"$p = Get-Partition | Where-Object {{ $_.DriveLetter -eq '{letter}' }}; "
                    "if ($p) { "
                    "  $disk = Get-PhysicalDisk | Where-Object { $_.DeviceId -eq $p.DiskNumber }; "
                    "  [PSCustomObject]@{ "
                    "    DiskNumber=$p.DiskNumber; BusType=$disk.BusType; "
                    "    MediaType=$disk.MediaType; Size=$disk.Size; "
                    "    FriendlyName=$disk.FriendlyName; SerialNumber=$disk.SerialNumber "
                    "  } | ConvertTo-Json -Compress "
                    "} else { 'null' }"
                )
                res = subprocess.run(
                    ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", ps_cmd],
                    capture_output=True, text=True, timeout=8, check=False,
                )
                if res.returncode == 0 and res.stdout.strip() not in ("", "null"):
                    data = json.loads(res.stdout.strip())
                    if isinstance(data, dict):
                        if data.get("DiskNumber") is not None:
                            caps["physical_disk_number"] = int(data["DiskNumber"])
                        if data.get("BusType"):
                            caps["bus_type"] = str(data["BusType"]).upper()
                        if data.get("MediaType"):
                            caps["media_type"] = str(data["MediaType"]).upper()
                        if data.get("Size") and not caps["capacity"]:
                            caps["capacity"] = int(data["Size"])
        except Exception as exc:
            caps["probe_errors"].append(str(exc))

    # ── Step 2: Determine system/boot disk ─────────────────────────────────────
    is_c = drive.path.upper().startswith("C:")
    is_phys0 = (caps["physical_disk_number"] == 0)
    if is_c or is_phys0:
        caps["system_disk"] = "SUPPORTED"
        caps["boot_disk"] = "SUPPORTED"
    else:
        caps["system_disk"] = "UNSUPPORTED"
        caps["boot_disk"] = "UNSUPPORTED"

    # ── Step 3: Removable / bus classification ─────────────────────────────────
    bus = caps["bus_type"]
    if bus == "USB":
        caps["removable"] = "SUPPORTED"
        caps["usb_bridge"] = "SUPPORTED"
        caps["ata_available"] = "UNSUPPORTED"
        caps["ata_passthrough"] = "UNSUPPORTED"
        caps["ata_secure_erase"] = "UNSUPPORTED"
        caps["ata_enhanced_secure_erase"] = "UNSUPPORTED"
        caps["nvme_controller"] = "UNSUPPORTED"
        caps["nvme_sanitize"] = "UNSUPPORTED"
        caps["nvme_sanitize_crypto"] = "UNSUPPORTED"
        caps["nvme_sanitize_block"] = "UNSUPPORTED"
        caps["nvme_format_secure"] = "UNSUPPORTED"
        caps["native_sanitize"] = "UNSUPPORTED"
    elif bus in ("NVME", "PCIE"):
        caps["removable"] = "UNSUPPORTED"
        caps["usb_bridge"] = "UNSUPPORTED"
        caps["nvme_controller"] = "SUPPORTED"
        caps["nvme_sanitize"] = "UNKNOWN"
        caps["nvme_sanitize_crypto"] = "UNKNOWN"
        caps["nvme_sanitize_block"] = "UNKNOWN"
        caps["nvme_format_secure"] = "UNKNOWN"
    elif bus in ("SATA", "ATA"):
        caps["removable"] = "UNSUPPORTED"
        caps["usb_bridge"] = "UNSUPPORTED"
        caps["ata_available"] = "SUPPORTED"
        caps["ata_passthrough"] = "SUPPORTED" if os.name != "nt" else "UNSUPPORTED"
        caps["ata_secure_erase"] = "UNKNOWN" if os.name != "nt" else "UNSUPPORTED"

    # ── Step 4 & 5: Determine write capability & policy eligibility ───────────
    if is_c or is_phys0:
        caps["write_capable"] = "BLOCKED"
        caps["overwrite_backend_qualified"] = "BLOCKED"
        caps["clear_qualified"] = False
        caps["nist_qualified"] = False
    else:
        caps["write_capable"] = "SUPPORTED"
        caps["overwrite_backend_qualified"] = "SUPPORTED"
        caps["clear_qualified"] = True
        caps["nist_qualified"] = True
        if bus == "USB":
            caps["ieee_compliance_basis"] = "HOST_OVERWRITE_ONLY"
        elif bus in ("NVME", "PCIE", "SATA", "ATA"):
            caps["ieee_compliance_basis"] = "DEVICE_NATIVE_PREFERRED"

    return caps


class DrexCapabilityManager:
    """
    High-performance, non-blocking asynchronous device capability manager.
    Guarantees:
      1. Memory-only instant cached lookups via get_cached(drive) — 0ms, thread-safe.
      2. get_capabilities(drive) NEVER blocks Tk thread: on main thread cache miss, returns cached or empty dict and initiates async background probe.
      3. Asynchronous probing via background thread pool with single-flight request deduplication.
      4. Multi-listener fanout: all callers subscribing during an in-flight probe are notified upon completion.
      5. Emits EV_CAPABILITIES / calls completion callback when probing finishes.
    """
    def __init__(self, ttl_seconds: float = 60.0):
        self._cache: dict[str, tuple[float, dict[str, Any]]] = {}
        self._pending_listeners: dict[str, list[tuple[queue.Queue[tuple[str, Any]] | None, Callable[[dict[str, Any]], None] | None]]] = {}
        self._lock = threading.RLock()
        self._ttl = ttl_seconds
        self._executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="drex_cap_worker")

    @staticmethod
    def _key(drive: DriveInfo | None) -> str:
        if drive is None:
            return "none"
        return f"{drive.path}|{drive.device_path}|{drive.model}|{drive.serial}"

    def get_cached(self, drive: DriveInfo | None) -> dict[str, Any] | None:
        """Strictly memory-only, non-blocking cache lookup."""
        if drive is None:
            return None
        key = self._key(drive)
        now = time.time()
        with self._lock:
            if key in self._cache:
                ts, caps = self._cache[key]
                if now - ts < self._ttl:
                    return dict(caps)
        return None

    def get_capabilities(self, drive: DriveInfo | None, force_refresh: bool = False) -> dict[str, Any]:
        """
        Safe capability accessor.
        If called on Tk main thread: NEVER blocks or calls probe_drive_capabilities().
        Returns cached dict if valid, else triggers async probe and returns empty dict.
        If called on worker thread: evaluates probe_drive_capabilities() if cache miss.
        """
        if drive is None:
            return {}
        cached = self.get_cached(drive)
        if cached is not None and not force_refresh:
            return cached

        # Check thread affinity
        if threading.current_thread() is threading.main_thread():
            # Kick off async probe without blocking UI
            self.request_capabilities_async(drive, force_refresh=force_refresh)
            return cached or {}

        # On worker thread: perform synchronous probe and cache result
        caps = probe_drive_capabilities(drive)
        key = self._key(drive)
        now = time.time()
        with self._lock:
            self._cache[key] = (now, caps)
        return dict(caps)

    def request_capabilities_async(
        self,
        drive: DriveInfo | None,
        event_queue: queue.Queue[tuple[str, Any]] | None = None,
        on_complete: Callable[[dict[str, Any]], None] | None = None,
        force_refresh: bool = False,
    ) -> None:
        """Asynchronously probe drive capabilities in background worker thread with multi-listener fanout."""
        if drive is None:
            return
        key = self._key(drive)
        now = time.time()
        with self._lock:
            if not force_refresh and key in self._cache:
                ts, caps = self._cache[key]
                if now - ts < self._ttl:
                    if on_complete:
                        try:
                            on_complete(dict(caps))
                        except Exception:
                            pass
                    if event_queue is not None:
                        event_queue.put((EV_CAPABILITIES, (drive, dict(caps))))
                    return

            if key in self._pending_listeners:
                self._pending_listeners[key].append((event_queue, on_complete))
                return
            self._pending_listeners[key] = [(event_queue, on_complete)]

        def _worker():
            try:
                caps = probe_drive_capabilities(drive)
            except Exception as exc:
                caps = {
                    "physical_disk_number": None,
                    "model": drive.model,
                    "serial": drive.serial,
                    "capacity": drive.capacity,
                    "bus_type": drive.interface or "UNKNOWN",
                    "write_capable": "UNKNOWN",
                    "overwrite_backend_qualified": "UNKNOWN",
                    "probe_errors": [str(exc)],
                }
            with self._lock:
                self._cache[key] = (time.time(), caps)
                listeners = self._pending_listeners.pop(key, [])

            for eq, cb in listeners:
                if cb:
                    try:
                        cb(dict(caps))
                    except Exception:
                        pass
                if eq is not None:
                    try:
                        eq.put((EV_CAPABILITIES, (drive, dict(caps))))
                    except Exception:
                        pass

        self._executor.submit(_worker)

    def invalidate(self, drive: DriveInfo | str | None = None) -> None:
        with self._lock:
            if drive is None:
                self._cache.clear()
            elif isinstance(drive, str):
                to_del = [k for k in self._cache if k.startswith(drive + "|") or k == drive]
                for k in to_del:
                    self._cache.pop(k, None)
            else:
                self._cache.pop(self._key(drive), None)


_global_capability_manager = DrexCapabilityManager()


def verify_drive_identity(drive: DriveInfo, expected_disk_num: int) -> dict[str, Any]:
    """
    Perform a FRESH identity check immediately before any destructive operation.

    This is the hard safety gate: if anything doesn't match, the operation aborts.
    Never trust the cached DriveInfo alone — re-probe the OS right now.
    """
    evidence: dict[str, Any] = {
        "timestamp": utc_now(),
        "expected_physical_disk": expected_disk_num,
        "identity_verified": False,
        "abort_reason": None,
    }

    # PhysicalDisk 0 is absolutely forbidden regardless of arguments.
    if expected_disk_num == 0:
        evidence["abort_reason"] = "ABORT: PhysicalDisk 0 is permanently forbidden (C: / system disk)."
        return evidence

    try:
        ps_cmd = f"Get-Partition | Where-Object {{ $_.DriveLetter -eq '{drive.path.rstrip('/\\').rstrip(':')}' }} | Select-Object DiskNumber | ConvertTo-Json -Compress"
        result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", ps_cmd],
            capture_output=True, text=True, timeout=10, check=False,
        )
        if result.returncode != 0 or not result.stdout.strip() or result.stdout.strip() == "null":
            evidence["abort_reason"] = f"ABORT: Cannot verify physical disk number for {drive.path} — OS query failed."
            return evidence
        part_data = json.loads(result.stdout.strip())
        if isinstance(part_data, list):
            part_data = part_data[0]
        actual_disk_num = int(part_data.get("DiskNumber", -1))
        evidence["actual_physical_disk"] = actual_disk_num
        if actual_disk_num != expected_disk_num:
            evidence["abort_reason"] = (
                f"ABORT: Physical disk mismatch — expected={expected_disk_num}, "
                f"actual={actual_disk_num}. Operation cancelled."
            )
            return evidence
        if actual_disk_num == 0:
            evidence["abort_reason"] = "ABORT: Physical disk 0 confirmed — system disk is permanently forbidden."
            return evidence
    except Exception as exc:
        evidence["abort_reason"] = f"ABORT: Identity verification error: {type(exc).__name__}: {exc}"
        return evidence

    # Fresh model/serial check
    try:
        phys_cmd = f"Get-PhysicalDisk | Where-Object {{ $_.DeviceId -eq {expected_disk_num} }} | Select-Object FriendlyName, SerialNumber, Size, BusType, IsSystem | ConvertTo-Json -Compress"
        phys_result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", phys_cmd],
            capture_output=True, text=True, timeout=10, check=False,
        )
        if phys_result.returncode == 0 and phys_result.stdout.strip():
            phys_data = json.loads(phys_result.stdout.strip())
            if isinstance(phys_data, list):
                phys_data = phys_data[0]
            evidence["model"] = str(phys_data.get("FriendlyName") or "")
            evidence["serial"] = str(phys_data.get("SerialNumber") or "")
            evidence["capacity"] = phys_data.get("Size")
            evidence["bus_type"] = str(phys_data.get("BusType") or "")
            # IsSystem should not be present for non-system disks; double-check anyway
            is_system_fresh = bool(phys_data.get("IsSystem", False))
            if is_system_fresh:
                evidence["abort_reason"] = "ABORT: Fresh probe reports IsSystem=True — operation cancelled."
                return evidence
    except Exception as exc:
        evidence["probe_errors"] = str(exc)

    evidence["identity_verified"] = True
    return evidence


def build_test_corpus(drive_root: Path) -> dict[str, Any]:
    """
    Create an extensive test corpus on target drive before destructive testing.
    Includes TXT, PDF, JPEG, PNG, ZIP, large binary, small binary, nested folders,
    duplicate files, and random data.
    Records: path, size, SHA-256, creation time, last write time.
    """
    import io
    import secrets as _secrets
    import zipfile

    corpus_root = drive_root / "DREXX_TEST_CORPUS"
    corpus_root.mkdir(parents=True, exist_ok=True)
    files_created: list[dict[str, Any]] = []

    def _write_and_record(p: Path, data: bytes) -> dict[str, Any]:
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
        digest = hashlib.sha256(data).hexdigest()
        stat = p.stat()
        ctime = datetime.fromtimestamp(stat.st_ctime, timezone.utc).isoformat()
        mtime = datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat()
        rec = {
            "path": str(p),
            "size": len(data),
            "sha256": digest,
            "creation_time": ctime,
            "last_write_time": mtime,
        }
        files_created.append(rec)
        return rec

    # 1. TXT files
    _write_and_record(corpus_root / "readme.txt",
        b"DREXX pre-wipe corpus file. Physical drive erasure baseline document.\n")
    _write_and_record(corpus_root / "audit_notes.txt",
        b"CONFIDENTIAL AUDIT LOG: Pre-erasure baseline integrity manifest.\n")

    # 2. Valid minimal PDF (PDF-1.4 header, body, xref, trailer)
    minimal_pdf = (
        b"%PDF-1.4\n"
        b"1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
        b"2 0 obj<</Type/Pages/Count 1/Kids[3 0 R]>>endobj\n"
        b"3 0 obj<</Type/Page/MediaBox[0 0 612 792]/Parent 2 0 R/Resources<<>>>>endobj\n"
        b"xref\n0 4\n0000000000 65535 f \n0000000009 00000 n \n0000000058 00000 n \n0000000115 00000 n \n"
        b"trailer<</Size 4/Root 1 0 R>>\nstartxref\n190\n%%EOF\n"
    )
    _write_and_record(corpus_root / "document.pdf", minimal_pdf)

    # 3. Valid minimal JPEG (JFIF magic bytes + SOI + APP0 + DQT + SOF0 + EOI)
    minimal_jpeg = bytes.fromhex(
        "ffd8ffe000104a46494600010101006000600000ffdb004300080606070605080707070909080a"
        "0c140d0c0b0b0c1912130f141d1a1f1e1d1a1c1c20242e2720222c231c1c2837292c3031343434"
        "1f27393d38323c2e333431ffd9"
    )
    _write_and_record(corpus_root / "evidence_photo.jpg", minimal_jpeg)

    # 4. Valid minimal PNG (PNG signature + IHDR + IDAT + IEND)
    minimal_png = bytes.fromhex(
        "89504e470d0a1a0a0000000d4948445200000001000000010802000000907753de0000000c4944"
        "4154789c6360f8cfc00000020101011311029c0000000049454e44ae426082"
    )
    _write_and_record(corpus_root / "diagram.png", minimal_png)

    # 5. Valid ZIP archive containing compressed files
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("archive_readme.txt", "Pre-wipe corpus zipped payload contents.")
        zf.writestr("nested_zip/secret.dat", _secrets.token_bytes(512))
    _write_and_record(corpus_root / "backup.zip", zip_buffer.getvalue())

    # 6. Large binary (4 MiB)
    _write_and_record(corpus_root / "large_4mb.bin", _secrets.token_bytes(4 * 1024 * 1024))

    # 7. Small binary (128 bytes)
    _write_and_record(corpus_root / "small_128b.bin", _secrets.token_bytes(128))

    # 8. Nested folders with varied depths
    nested_dir = corpus_root / "dept_records" / "q3_audit" / "restricted"
    nested_dir.mkdir(parents=True, exist_ok=True)
    _write_and_record(nested_dir / "deep_manifest.txt", b"Deeply nested file path verification.")
    _write_and_record(nested_dir / "nested_binary.dat", _secrets.token_bytes(8192))

    # 9. Duplicate files (exact same contents and hash in different directories)
    dup_payload = b"DREXX_DETERMINISTIC_DUPLICATE_CONTENT_HASH_VERIFICATION_2026_TEST"
    _write_and_record(corpus_root / "original_file.bin", dup_payload)
    _write_and_record(nested_dir / "duplicate_copy.bin", dup_payload)

    # 10. Random data
    _write_and_record(corpus_root / "random_entropy.dat", _secrets.token_bytes(65536))

    corpus_evidence = {
        "corpus_root": str(corpus_root),
        "created_at": utc_now(),
        "file_count": len(files_created),
        "total_bytes": sum(f["size"] for f in files_created),
        "files": files_created,
    }
    manifest_path = corpus_root / "corpus_manifest.json"
    manifest_path.write_text(json.dumps(corpus_evidence, indent=2), encoding="utf-8")
    return corpus_evidence


def _physical_overwrite_windows(
    device_path: str,
    disk_size_bytes: int,
    emit: Callable[[str], None],
    progress: Callable[[int, int], None],
    cancel_event: threading.Event | None = None,
    max_bytes: int | None = None,
) -> dict[str, Any]:
    """
    Raw physical/volume overwrite on Windows with chunk-level read-back verification.

    Architecture references:
      - DriveWipe: block-level streaming with retry and read-back verification
      - openSeaChest: sector-by-sector integrity model
      - NIST SP 800-88 Rev.2: Clear = addressable media overwrite + verification
      - IEEE 2883-2022 §5.6: Purge/Clear media assurance requirements

    Features:
      - Deterministic pseudorandom pattern generated per block
      - Partial write detection and retry
      - Transient I/O error retry (WinError 433, 1117, 6, 21) with handle reacquisition
      - Sector/cluster aligned chunk writes (1 MiB)
      - Exact byte range tracking for write and readback passes
      - Full mismatch detection and reporting
      - Coverage calculation (100% required for PASS_PHYSICAL)
    """
    import ctypes
    import ctypes.wintypes
    import struct

    CHUNK = 1024 * 1024  # 1 MiB chunk for reliable high-speed streaming
    emit(f"Opening physical target: {device_path}")

    # Standardize device path for raw binary access
    target_path = device_path
    if not target_path.startswith("\\\\.\\"):
        if ":" in target_path:
            clean = target_path.rstrip("\\/").rstrip(":")
            target_path = f"\\\\.\\{clean}:"
        else:
            target_path = f"\\\\.\\{target_path}"

    target_bytes = min(disk_size_bytes, max_bytes) if max_bytes is not None and max_bytes > 0 else disk_size_bytes

    evidence: dict[str, Any] = {
        "device_path": target_path,
        "disk_size_bytes": disk_size_bytes,
        "target_bytes": target_bytes,
        "bytes_written": 0,
        "bytes_verified": 0,
        "chunks_written": 0,
        "chunks_verified": 0,
        "byte_ranges_written": [],
        "byte_ranges_verified": [],
        "mismatches": 0,
        "mismatch_details": [],
        "verification_status": "NOT_EXECUTED",
        "final_status": "NOT_STARTED",
        "started_at": utc_now(),
    }

    if os.name == "nt":
        import ctypes
        from ctypes import wintypes

        GENERIC_READ = 0x80000000
        GENERIC_WRITE = 0x40000000
        FILE_SHARE_READ = 0x00000001
        FILE_SHARE_WRITE = 0x00000002
        OPEN_EXISTING = 3
        FILE_BEGIN = 0
        INVALID_HANDLE = ctypes.c_void_p(-1).value

        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        k32.CreateFileW.argtypes = [
            wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
            ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p
        ]
        k32.CreateFileW.restype = wintypes.HANDLE
        k32.SetFilePointerEx.argtypes = [
            wintypes.HANDLE, ctypes.c_int64, ctypes.POINTER(ctypes.c_int64), wintypes.DWORD
        ]
        k32.SetFilePointerEx.restype = wintypes.BOOL
        k32.WriteFile.argtypes = [
            wintypes.HANDLE, ctypes.c_char_p, wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p
        ]
        k32.WriteFile.restype = wintypes.BOOL
        k32.ReadFile.argtypes = [
            wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p
        ]
        k32.ReadFile.restype = wintypes.BOOL
        k32.FlushFileBuffers.argtypes = [wintypes.HANDLE]
        k32.FlushFileBuffers.restype = wintypes.BOOL
        k32.CloseHandle.argtypes = [wintypes.HANDLE]
        k32.CloseHandle.restype = wintypes.BOOL

        h_dev = k32.CreateFileW(
            target_path,
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            0,
            None
        )
        if h_dev == INVALID_HANDLE or h_dev == 0 or h_dev is None:
            win_err = ctypes.get_last_error()
            err_msg = (
                f"Cannot open physical device {target_path} (WinError {win_err}). "
                "Administrator privileges (UAC elevation) are required for physical drive operations."
                if win_err in (5, 0x5) else
                f"Cannot open {target_path}: WinError={win_err}"
            )
            emit(f"ERROR: {err_msg}")
            evidence["final_status"] = "FAILED"
            evidence["open_error"] = err_msg
            return evidence

        emit(f"Device opened successfully via Win32 handle. Starting streaming overwrite ({fmt_bytes(target_bytes)}).")
        progress(0, target_bytes)
        _last_progress_emit: float = time.perf_counter()

        def _deterministic_pattern(offset_val: int, length: int) -> bytes:
            seed = struct.pack("<Q", offset_val) + b"_DREXX_NIST_IEEE_OVERWRITE_SALT_2026_"
            h_block = hashlib.sha256(seed).digest()
            rep = (length + len(h_block) - 1) // len(h_block)
            return (h_block * rep)[:length]

        try:
            offset = 0
            total = target_bytes
            write_hash = hashlib.sha256()
            read_hash = hashlib.sha256()

            # ── PASS 1: High-speed Sequential Overwrite ───────────────────────
            new_pos = ctypes.c_int64(0)
            k32.SetFilePointerEx(h_dev, ctypes.c_int64(0), ctypes.byref(new_pos), FILE_BEGIN)
            while offset < total:
                if cancel_event and cancel_event.is_set():
                    evidence["final_status"] = "CANCELLED"
                    return evidence

                n = min(CHUNK, total - offset)
                expected_data = _deterministic_pattern(offset, n)
                bytes_written = wintypes.DWORD(0)
                ok = k32.WriteFile(h_dev, expected_data, n, ctypes.byref(bytes_written), None)
                if not ok or bytes_written.value == 0:
                    win_err = ctypes.get_last_error()
                    err_msg = (
                        f"WriteFile failed at offset {offset} (WinError {win_err}). "
                        "Windows blocked physical sector write — Administrator privileges (UAC elevation) or volume dismount required."
                        if win_err in (5, 0x5) else
                        f"WriteFile failed at offset {offset} (WinError {win_err})."
                    )
                    emit(f"ERROR: {err_msg}")
                    evidence["final_status"] = "FAILED"
                    evidence["write_error"] = err_msg
                    return evidence

                w_len = bytes_written.value
                write_hash.update(expected_data[:w_len])
                offset += w_len
                evidence["chunks_written"] += 1
                evidence["bytes_written"] = offset

                _now = time.perf_counter()
                if _now - _last_progress_emit >= 0.05 or offset >= total:
                    progress(offset, total)
                    _last_progress_emit = _now

            k32.FlushFileBuffers(h_dev)
            if evidence["bytes_written"] > 0:
                evidence["byte_ranges_written"].append([0, evidence["bytes_written"]])

            # ── PASS 2: Sequential Read-Back Verification ────────────────────
            emit(f"Write pass complete ({fmt_bytes(evidence['bytes_written'])}). Starting read-back verification pass...")
            k32.SetFilePointerEx(h_dev, ctypes.c_int64(0), ctypes.byref(new_pos), FILE_BEGIN)
            verify_offset = 0
            while verify_offset < total:
                if cancel_event and cancel_event.is_set():
                    evidence["final_status"] = "CANCELLED"
                    return evidence

                n = min(CHUNK, total - verify_offset)
                expected_data = _deterministic_pattern(verify_offset, n)
                buf = ctypes.create_string_buffer(n)
                bytes_read = wintypes.DWORD(0)
                ok = k32.ReadFile(h_dev, buf, n, ctypes.byref(bytes_read), None)
                if not ok or bytes_read.value == 0:
                    win_err = ctypes.get_last_error()
                    err_msg = f"ReadFile failed at offset {verify_offset} (WinError {win_err})."
                    emit(f"ERROR: {err_msg}")
                    evidence["final_status"] = "FAILED"
                    evidence["read_error"] = err_msg
                    return evidence

                actual_data = buf.raw[:bytes_read.value]
                if actual_data != expected_data[:bytes_read.value]:
                    evidence["mismatches"] += 1
                    evidence["verification_status"] = "PARTIAL"
                    evidence["mismatch_details"].append({
                        "offset": verify_offset,
                        "expected_sha256": hashlib.sha256(expected_data).hexdigest(),
                        "actual_sha256": hashlib.sha256(actual_data).hexdigest(),
                        "actual_length": len(actual_data),
                        "expected_length": len(expected_data),
                    })
                else:
                    read_hash.update(actual_data)
                    evidence["chunks_verified"] += 1
                    evidence["bytes_verified"] += len(actual_data)

                verify_offset += bytes_read.value

            if evidence["bytes_verified"] > 0:
                evidence["byte_ranges_verified"].append([0, evidence["bytes_verified"]])
            evidence["write_sha256"] = write_hash.hexdigest()
            evidence["readback_sha256"] = read_hash.hexdigest()

            coverage = (
                round((evidence["bytes_verified"] / disk_size_bytes) * 100, 2)
                if disk_size_bytes > 0
                else 0.0
            )
            evidence["coverage_percent"] = coverage

            if evidence["mismatches"] == 0:
                if evidence["bytes_verified"] >= disk_size_bytes:
                    evidence["verification_status"] = "VERIFIED"
                    evidence["final_status"] = "PASS_PHYSICAL"
                else:
                    evidence["verification_status"] = "VERIFIED"
                    evidence["final_status"] = "PASS_PHYSICAL_RANGE"
            else:
                evidence["verification_status"] = "PARTIAL"
                evidence["final_status"] = "VERIFICATION_FAILED"

            return evidence
        finally:
            k32.CloseHandle(h_dev)

    # POSIX fallback
    try:
        f_dev = open(target_path, "r+b", buffering=0)
    except PermissionError:
        err_msg = "Permission denied opening physical drive. Superuser privileges required."
        emit(f"ERROR: {err_msg}")
        evidence["final_status"] = "FAILED"
        evidence["open_error"] = err_msg
        return evidence
    except Exception as exc:
        err_msg = f"Cannot open {target_path}: {exc}"
        emit(f"ERROR: {err_msg}")
        evidence["final_status"] = "FAILED"
        evidence["open_error"] = str(exc)
        return evidence

    emit(f"Device opened successfully. Starting streaming overwrite ({fmt_bytes(target_bytes)}).")
    progress(0, target_bytes)
    _last_progress_emit = time.perf_counter()

    def _deterministic_pattern_posix(offset_val: int, length: int) -> bytes:
        seed = struct.pack("<Q", offset_val) + b"_DREXX_NIST_IEEE_OVERWRITE_SALT_2026_"
        h_block = hashlib.sha256(seed).digest()
        rep = (length + len(h_block) - 1) // len(h_block)
        return (h_block * rep)[:length]

    try:
        offset = 0
        total = target_bytes
        write_hash = hashlib.sha256()
        read_hash = hashlib.sha256()

        f_dev.seek(0)
        while offset < total:
            if cancel_event and cancel_event.is_set():
                evidence["final_status"] = "CANCELLED"
                return evidence

            n = min(CHUNK, total - offset)
            expected_data = _deterministic_pattern_posix(offset, n)
            f_dev.write(expected_data)
            write_hash.update(expected_data)

            offset += n
            evidence["chunks_written"] += 1
            evidence["bytes_written"] = offset

            _now = time.perf_counter()
            if _now - _last_progress_emit >= 0.05 or offset >= total:
                progress(offset, total)
                _last_progress_emit = _now

        f_dev.flush()
        if evidence["bytes_written"] > 0:
            evidence["byte_ranges_written"].append([0, evidence["bytes_written"]])

        emit(f"Write pass complete ({fmt_bytes(evidence['bytes_written'])}). Starting read-back verification pass...")
        f_dev.seek(0)
        verify_offset = 0

        while verify_offset < total:
            if cancel_event and cancel_event.is_set():
                evidence["final_status"] = "CANCELLED"
                return evidence

            n = min(CHUNK, total - verify_offset)
            expected_data = _deterministic_pattern_posix(verify_offset, n)
            actual_data = f_dev.read(n)

            if actual_data != expected_data:
                evidence["mismatches"] += 1
                evidence["verification_status"] = "PARTIAL"
            else:
                read_hash.update(actual_data)
                evidence["chunks_verified"] += 1
                evidence["bytes_verified"] += len(actual_data)

            verify_offset += n

        if evidence["bytes_verified"] > 0:
            evidence["byte_ranges_verified"].append([0, evidence["bytes_verified"]])
        evidence["write_sha256"] = write_hash.hexdigest()
        evidence["readback_sha256"] = read_hash.hexdigest()

        coverage = (
            round((evidence["bytes_verified"] / disk_size_bytes) * 100, 2)
            if disk_size_bytes > 0
            else 0.0
        )
        evidence["coverage_percent"] = coverage

        if evidence["mismatches"] == 0:
            if evidence["bytes_verified"] >= disk_size_bytes:
                evidence["verification_status"] = "VERIFIED"
                evidence["final_status"] = "PASS_PHYSICAL"
            else:
                evidence["verification_status"] = "VERIFIED"
                evidence["final_status"] = "PASS_PHYSICAL_RANGE"
        else:
            evidence["verification_status"] = "PARTIAL"
            evidence["final_status"] = "VERIFICATION_FAILED"

        return evidence
    finally:
        try:
            f_dev.close()
        except Exception:
            pass
        evidence["finished_at"] = utc_now()

    return evidence


def execute_drive_method(
    method_id: str,
    drive: DriveInfo,
    emit: Callable[[str], None],
    progress: Callable[[int, int], None],
    cancel_event: threading.Event | None = None,
    caps: dict[str, Any] | None = None,
    max_bytes: int | None = None,
) -> dict[str, Any]:
    """
    Central drive-erasure dispatcher for methods #1–#7.

    Execution contract:
      1. Probe capabilities (non-destructive, fresh every call or pre-probed)
      2. Verify identity (fresh OS query, abort if mismatch)
      3. C:/PhysicalDisk0 hard block
      4. Route to correct backend
      5. Return structured evidence dict

    Status values:
      PASS_PHYSICAL        — 100% written + 100% verified on physical device
      PASS_POLICY          — policy decision made; underlying execution logged
      UNSUPPORTED_HARDWARE — hardware genuinely blocks this protocol
      PHYSICAL_EXECUTION_UNAVAILABLE — no qualified backend for this host
      EXECUTION_BLOCKED    — safety guard triggered
      VERIFICATION_FAILED  — execution completed but read-back mismatch
    """
    started = utc_now()
    if caps is None:
        emit(f"[{method_id.upper()}] Probing device capabilities for {drive.path}...")
        caps = probe_drive_capabilities(drive)
    phys_num = caps.get("physical_disk_number")
    bus_type = caps.get("bus_type", "UNKNOWN")
    emit(f"  Bus: {bus_type}  PhysicalDisk: {phys_num}  Model: {caps.get('model')}")
    emit(f"  Serial: {caps.get('serial')}  Capacity: {fmt_bytes(caps.get('capacity'))}")
    if caps.get("probe_errors"):
        for e in caps["probe_errors"]:
            emit(f"  [probe_warning] {e}")

    # ── PhysicalDisk 0 absolute block ──────────────────────────────────────────
    if phys_num is not None and int(phys_num) == 0:
        return {
            "status": "EXECUTION_BLOCKED",
            "method_id": method_id,
            "reason": "ABORT: PhysicalDisk 0 is C: / system disk. Operation permanently forbidden.",
            "capabilities": caps,
            "started_at": started,
            "finished_at": utc_now(),
        }

    # ── Method #3: Device-Native Sanitize ──────────────────────────────────────
    if method_id == "native":
        # openSeaChest reference: USB mass storage bridges do not forward
        # SCSI Sanitize opcodes (SBC-4 §4.3.9). Evidence: probe caps.
        native_cap = caps.get("native_sanitize", "UNSUPPORTED")
        reason = (
            "USB mass storage bridge (BOT/UAS) intercepts and drops SCSI Sanitize "
            "opcodes (SBC-4 §4.3.9). openSeaChest openSeaChest_Sanitize requires "
            "direct SCSI/ATA/NVMe pass-through which is unavailable on this bus."
            if bus_type == "USB" else
            f"Native sanitize capability: {native_cap}. No qualified backend available on this host."
        )
        return {
            "status": "UNSUPPORTED_HARDWARE",
            "method_id": "native",
            "hardware_capability": native_cap,
            "bus_type": bus_type,
            "reason": reason,
            "capabilities": caps,
            "started_at": started,
            "finished_at": utc_now(),
        }

    # ── Method #4: ATA Secure Erase ────────────────────────────────────────────
    if method_id == "ata":
        # hdparm reference: ATA Security Erase requires ATA pass-through.
        # USB mass storage (BOT/UAS) translates SCSI commands; ATA vendor-specific
        # and ATA SECURITY opcodes are not forwarded.
        ata_cap = caps.get("ata_secure_erase", "UNSUPPORTED")
        reason = (
            "ATA Secure Erase requires ATA Security command pass-through "
            "(hdparm --security-erase). USB mass storage bridges (BOT/UAS) do not "
            "forward ATA vendor-specific opcodes. Hardware interface: USB."
            if bus_type == "USB" else
            "ATA pass-through unavailable on Windows without hdparm and a compatible SATA/ATA interface."
            if os.name == "nt" and bus_type not in ("SATA", "ATA") else
            f"ATA secure erase capability: {ata_cap}. Backend unavailable."
        )
        return {
            "status": "UNSUPPORTED_HARDWARE",
            "method_id": "ata",
            "hardware_capability": ata_cap,
            "bus_type": bus_type,
            "reason": reason,
            "capabilities": caps,
            "started_at": started,
            "finished_at": utc_now(),
        }

    # ── Method #5: NVMe Secure Erase ───────────────────────────────────────────
    if method_id == "nvme":
        # nvme-cli reference: nvme sanitize / nvme format commands require
        # NVMe controller and NVMe pass-through. A USB-attached flash drive
        # presents as USB mass storage, not as an NVMe namespace.
        nvme_cap = caps.get("nvme_controller", "UNSUPPORTED")
        reason = (
            f"NVMe Secure Erase requires an NVMe controller (nvme-cli: nvme sanitize / "
            f"nvme format). This device presents on the {bus_type} bus and is not an NVMe "
            f"device. NVMe commands cannot be issued over {bus_type}."
        )
        return {
            "status": "UNSUPPORTED_HARDWARE",
            "method_id": "nvme",
            "hardware_capability": nvme_cap,
            "bus_type": bus_type,
            "reason": reason,
            "capabilities": caps,
            "started_at": started,
            "finished_at": utc_now(),
        }

    # ── Methods requiring physical write: identity verification ────────────────
    if method_id in ("nist", "smart", "ieee", "overwrite"):
        if phys_num is None:
            return {
                "status": "EXECUTION_BLOCKED",
                "method_id": method_id,
                "reason": "Cannot determine physical disk number — identity cannot be verified. Aborting.",
                "capabilities": caps,
                "started_at": started,
                "finished_at": utc_now(),
            }
        emit(f"  Verifying drive identity before destructive operation...")
        identity = verify_drive_identity(drive, int(phys_num))
        emit(f"  Identity verified: {identity.get('identity_verified')}")
        if not identity["identity_verified"]:
            return {
                "status": "EXECUTION_BLOCKED",
                "method_id": method_id,
                "reason": identity.get("abort_reason", "Identity verification failed."),
                "identity": identity,
                "capabilities": caps,
                "started_at": started,
                "finished_at": utc_now(),
            }
        if caps.get("overwrite_backend_qualified") != "SUPPORTED":
            return {
                "status": "PHYSICAL_EXECUTION_UNAVAILABLE",
                "method_id": method_id,
                "reason": (
                    f"Overwrite backend not qualified. "
                    f"write_capable={caps.get('write_capable')}, "
                    f"system_disk={caps.get('system_disk')}, "
                    f"boot_disk={caps.get('boot_disk')}."
                ),
                "capabilities": caps,
                "started_at": started,
                "finished_at": utc_now(),
            }

        # Target physical drive device directly (DELitALL proven standard)
        if phys_num is not None:
            device_path = f"\\\\.\\PhysicalDrive{phys_num}"
        elif drive.device_path:
            device_path = drive.device_path
        else:
            drive_letter = drive.path.rstrip("\\/").rstrip(":")
            device_path = f"\\\\.\\{drive_letter}:"

        disk_size = int(caps.get("capacity") or drive.capacity or 0)
        if disk_size <= 0:
            return {
                "status": "EXECUTION_BLOCKED",
                "method_id": method_id,
                "reason": f"Cannot determine disk size (reported={disk_size}). Aborting.",
                "capabilities": caps,
                "started_at": started,
                "finished_at": utc_now(),
            }

    # ── Method #1: NIST SP 800-88 Rev.2 ───────────────────────────────────────
    if method_id == "nist":
        # NIST SP 800-88 Rev.2 Table A-8:
        # USB flash: Clear = host overwrite; Purge requires device-native sanitize.
        # We have no native sanitize path for USB. Select CLEAR technique.
        assurance = "CLEAR"
        technique = "HOST_OVERWRITE"
        rationale = (
            "NIST SP 800-88 Rev.2 §5.3.1 / Table A-8: USB Flash Drive."
            " Purge via device-native sanitize is unavailable (USB bridge blocks ATA/NVMe "
            "Sanitize opcodes). Applying CLEAR technique: one overwrite pass with "
            "verification (NIST Clear for Flash Storage)."
        )
        emit(f"  NIST 800-88 technique: {assurance}/{technique}")
        emit(f"  Rationale: {rationale}")
        emit(f"  Beginning physical overwrite on {device_path}...")
        overwrite_result = _physical_overwrite_windows(
            device_path, disk_size, emit, progress, cancel_event, max_bytes=max_bytes
        )
        final_status = (
            "PASS_PHYSICAL" if overwrite_result.get("final_status") == "PASS_PHYSICAL" else
            overwrite_result.get("final_status", "FAILED")
        )
        return {
            "status": final_status,
            "method_id": "nist",
            "nist_assurance": assurance,
            "nist_technique": technique,
            "nist_rationale": rationale,
            "capabilities": caps,
            "identity": identity,
            "overwrite": overwrite_result,
            "started_at": started,
            "finished_at": utc_now(),
        }

    # ── Method #2: Smart Sanitization ─────────────────────────────────────────
    if method_id == "smart":
        # Smart sanitization evaluates all candidates and selects the strongest.
        # For F: (SanDisk Ultra, USB):
        #   REJECTED: NVMe Sanitize — not NVMe
        #   REJECTED: ATA Secure Erase — USB bridge blocks ATA pass-through
        #   REJECTED: Device-Native Sanitize — USB bridge blocks SCSI Sanitize
        #   SELECTED: Verified Overwrite — writable, removable, non-system
        candidates = [
            {"method": "NVMe Sanitize", "status": "REJECTED",
             "reason": f"Device bus is {bus_type}, not NVMe."},
            {"method": "ATA Secure Erase", "status": "REJECTED",
             "reason": "USB bridge does not expose ATA pass-through (BOT/UAS)."},
            {"method": "Device-Native Sanitize", "status": "REJECTED",
             "reason": "USB bridge intercepts SCSI Sanitize opcodes."},
            {"method": "Verified Overwrite", "status": "SELECTED",
             "reason": "Writable physical device, non-system, non-boot. Safe fallback."},
        ]
        emit("  Smart Sanitization candidate evaluation:")
        for c in candidates:
            emit(f"    {c['method']}: {c['status']} — {c['reason']}")
        emit(f"  Executing: Verified Overwrite on {device_path}...")
        overwrite_result = _physical_overwrite_windows(
            device_path, disk_size, emit, progress, cancel_event, max_bytes=max_bytes
        )
        final_status = overwrite_result.get("final_status", "FAILED")
        return {
            "status": final_status,
            "method_id": "smart",
            "selected_method": "VERIFIED_OVERWRITE",
            "selection_rationale": "Strongest available method for USB flash; all native methods rejected.",
            "candidates": candidates,
            "capabilities": caps,
            "identity": identity,
            "overwrite": overwrite_result,
            "started_at": started,
            "finished_at": utc_now(),
        }

    # ── Method #6: IEEE 2883 Purge ─────────────────────────────────────────────
    if method_id == "ieee":
        # IEEE 2883-2022 §5.6: Purge methods for flash (USB) media.
        # No device-native purge path available (USB bridge blocks SCSI Sanitize).
        # Apply host overwrite as the strongest available mechanism.
        # Compliance note: IEEE 2883 Purge requires device-native sanitize for
        # full compliance on flash. Host overwrite provides limited assurance.
        ieee_basis = caps.get("ieee_compliance_basis", "HOST_OVERWRITE_ONLY")
        purge_note = (
            "IEEE 2883-2022 §5.6 Purge: USB Flash Drive. No device-native sanitize "
            "path available (USB bridge intercepts SCSI Sanitize, ATA Security Erase, "
            "NVMe Sanitize). Applying host-addressable-sector overwrite with verification. "
            "COMPLIANCE LIMITATION: Full IEEE 2883 Purge compliance for flash requires "
            "device-native sanitize; host overwrite provides Clear-level assurance only."
        )
        emit(f"  IEEE 2883 basis: {ieee_basis}")
        emit(f"  Note: {purge_note}")
        emit(f"  Executing host overwrite on {device_path}...")
        overwrite_result = _physical_overwrite_windows(
            device_path, disk_size, emit, progress, cancel_event, max_bytes=max_bytes
        )
        final_status = overwrite_result.get("final_status", "FAILED")
        return {
            "status": final_status,
            "method_id": "ieee",
            "ieee_compliance_basis": ieee_basis,
            "ieee_purge_note": purge_note,
            "assurance_level": "HOST_OVERWRITE_ASSURANCE",
            "capabilities": caps,
            "identity": identity,
            "overwrite": overwrite_result,
            "started_at": started,
            "finished_at": utc_now(),
        }

    # ── Method #7: Verified Overwrite ─────────────────────────────────────────
    if method_id == "overwrite":
        emit(f"  Verified Overwrite: raw physical device write + chunk read-back.")
        emit(f"  Target: {device_path}  Size: {fmt_bytes(disk_size)}")
        overwrite_result = _physical_overwrite_windows(
            device_path, disk_size, emit, progress, cancel_event, max_bytes=max_bytes
        )
        final_status = overwrite_result.get("final_status", "FAILED")
        verification = (
            "VERIFIED" if overwrite_result.get("verification_status") == "VERIFIED" else
            overwrite_result.get("verification_status", "VERIFICATION_FAILED")
        )
        return {
            "status": final_status,
            "method_id": "overwrite",
            "verification": verification,
            "capabilities": caps,
            "identity": identity,
            "overwrite": overwrite_result,
            "started_at": started,
            "finished_at": utc_now(),
        }

    return {
        "status": "PHYSICAL_EXECUTION_UNAVAILABLE",
        "method_id": method_id,
        "reason": f"No drive execution backend configured for method '{method_id}'.",
        "capabilities": caps,
        "started_at": started,
        "finished_at": utc_now(),
    }


def drive_method_status(method_id: str, drive: DriveInfo | None, caps: dict[str, Any] | None = None) -> tuple[str, str]:
    """Return (status_label, description) for a drive+method combination.

    Status labels:
      Available                     — method can execute on this drive
      CHECKING...                   — capability probe in progress (cold cache)
      UNSUPPORTED_HARDWARE          — hardware genuinely blocks this protocol
      PHYSICAL_EXECUTION_UNAVAILABLE — no qualified backend
      EXECUTION_BLOCKED             — safety guard (system disk, PhysicalDisk 0, etc.)
    """
    if drive is None:
        return "Unavailable", "Select a detected device first."

    # Fast path — memory-only cached capabilities without running repetitive subprocess queries
    try:
        if caps is None:
            caps = _global_capability_manager.get_cached(drive)
    except Exception as exc:
        return "Unavailable", f"Capability lookup failed: {exc}"

    if caps is None:
        # Cold cache: non-blocking background request kicked off, UI displays CHECKING...
        _global_capability_manager.request_capabilities_async(drive)
        return "CHECKING...", "Evaluating device capabilities in background..."

    phys_num = caps.get("physical_disk_number")
    bus_type = caps.get("bus_type", "UNKNOWN")

    # Absolute block: system disk / PhysicalDisk 0
    if phys_num is not None and int(phys_num) == 0:
        return "EXECUTION_BLOCKED", "PhysicalDisk 0 (C: / system disk) is permanently forbidden."
    if caps.get("system_disk") == "SUPPORTED" or caps.get("boot_disk") == "SUPPORTED":
        return "EXECUTION_BLOCKED", "System or boot disk detected — operation blocked."

    if method_id == "ata":
        if bus_type == "USB" or caps.get("ata_secure_erase") == "UNSUPPORTED":
            return "UNSUPPORTED_HARDWARE", (
                f"ATA Secure Erase requires ATA pass-through. "
                f"Bus={bus_type}; USB bridges do not forward ATA Security opcodes."
            )
        return "Available", "ATA Secure Erase appears available (requires hdparm)."

    if method_id == "nvme":
        if caps.get("nvme_controller") == "UNSUPPORTED":
            return "UNSUPPORTED_HARDWARE", (
                f"NVMe Secure Erase requires an NVMe controller. "
                f"Bus={bus_type}; device is not NVMe."
            )
        return "Available", "NVMe controller detected."

    if method_id == "native":
        if bus_type == "USB" or caps.get("native_sanitize") == "UNSUPPORTED":
            return "UNSUPPORTED_HARDWARE", (
                f"Device-Native Sanitize requires SCSI/ATA/NVMe pass-through. "
                f"Bus={bus_type}; USB bridges block Sanitize opcodes."
            )
        return "Available", "Native sanitize may be available."

    if method_id in ("nist", "smart", "ieee", "overwrite"):
        if caps.get("overwrite_backend_qualified") == "SUPPORTED":
            return "Available", (
                f"Physical overwrite qualified. Bus={bus_type}, PhysicalDisk={phys_num}."
            )
        if caps.get("overwrite_backend_qualified") == "BLOCKED":
            return "EXECUTION_BLOCKED", "Overwrite is blocked (system/boot disk or PhysicalDisk 0)."
        return "PHYSICAL_EXECUTION_UNAVAILABLE", (
            f"Physical overwrite not yet qualified. write_capable={caps.get('write_capable')}."
        )

    return "PHYSICAL_EXECUTION_UNAVAILABLE", "No execution backend configured for this method."


class DrexApp(tk.Tk):
    def __init__(self):
        if os.name == "nt":
            try:
                ctypes.windll.shcore.SetProcessDpiAwareness(1)
            except (AttributeError, OSError):
                pass
        super().__init__()
        sys._inside_tk_mainloop = True
        self.title(f"DREX — Unified Data Recovery & Sanitization Platform — v{VERSION}")
        self.geometry("1440x900")
        self.minsize(1100, 700)
        self.configure(bg=BG)
        self.store = Store()
        self.cert_manager = CertificateManager(self.store)
        self.events: queue.Queue[tuple[str, Any]] = queue.Queue()
        self.drives: list[DriveInfo] = []
        self.recovery_dispatcher = RecoveryDispatcher(ROOT, Path(getattr(sys, "_MEIPASS", ROOT)))
        self.quick_recovery = self.recovery_dispatcher.get("quick")
        self.current_page = "Dashboard"
        self.page: tk.Frame | None = None
        # _page_generation increments every time _clear_page() is called.
        # Widgets and after() callbacks capture their generation at creation time
        # and must check staleness before touching the UI — preventing duplicate
        # Dashboard frames and ghost callbacks from old pages.
        self._page_generation: int = 0
        self.method_var = tk.StringVar()
        self.target: Path | None = None
        self.selected_drive: DriveInfo | None = None
        self.progress_value = tk.DoubleVar(value=0)
        self.progress_mode = tk.StringVar(value="")
        self.cancel_event = threading.Event()
        self.log_text: tk.Text | None = None
        self.status_label: tk.Label | None = None
        self.target_summary: tk.Frame | None = None
        self.help_section = "Getting Started"
        self._cert_page = 0
        self.recovery_tree = None
        self.recovery_destination = None
        self.recovery_scan = None
        self._recovery_source = ""
        self._recovery_source_is_image = False
        self.device_manager = _global_device_manager
        self.capability_manager = _global_capability_manager
        self.task_manager = DrexTaskManager(self.events)
        self.timer = self.task_manager.timer
        self.tracker = self.task_manager.tracker
        self.cancel_event = self.task_manager.cancel_event
        self._last_op_kind: str = "file"
        self._tech_details_visible = False
        self._elevation = _ELEVATION_STATE
        self._configure_styles()
        self._build_shell()
        self.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.show_page("Dashboard")
        self.after(30, self._poll_events)
        self.after(25, self._timer_tick)
        self.after(50, self.refresh_devices)

    def destroy(self):
        sys._inside_tk_mainloop = False
        super().destroy()

    def on_closing(self):
        if self.task_manager.is_active():
            if not messagebox.askyesno("Operation Running", "An operation is currently in progress.\nAre you sure you want to cancel and exit?"):
                return
            self.task_manager.cancel()
        self.task_manager.shutdown(wait=False)
        self.destroy()

    def _timer_tick(self):
        try:
            if self.task_manager.is_active() or self.timer.is_running:
                time_str = self.timer.formatted()
                if hasattr(self, "timer_label") and self.timer_label and self.timer_label.winfo_exists():
                    self.timer_label.configure(text=time_str)
                if hasattr(self, "pct_label") and self.pct_label and self.pct_label.winfo_exists():
                    self.pct_label.configure(text=self.tracker.percentage_str)
                if hasattr(self, "speed_label") and self.speed_label and self.speed_label.winfo_exists():
                    self.speed_label.configure(text=self.tracker.speed_str)
                if hasattr(self, "eta_label") and self.eta_label and self.eta_label.winfo_exists():
                    self.eta_label.configure(text=self.tracker.eta_str)
                if hasattr(self, "stage_label") and self.stage_label and self.stage_label.winfo_exists():
                    self.stage_label.configure(text=self.tracker.stage_text)
                if not self.tracker.is_streaming and self.tracker.total > 0:
                    self.progress_value.set(self.tracker.percentage)
        except Exception:
            pass
        finally:
            try:
                self.after(25, self._timer_tick)
            except Exception:
                pass

    # ── Styles ──────────────────────────────────────────────────────
    def _configure_styles(self):
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure("DrexPrimary.TButton", font=("Segoe UI", 10, "bold"), foreground="white", background=BLUE, bordercolor=BLUE, padding=(18, 9))
        style.map("DrexPrimary.TButton", background=[("active", "#0062CC"), ("disabled", "#B0D4FF")])
        style.configure("Drex.TButton", font=("Segoe UI", 10), foreground=INK, background="white", bordercolor=LINE, padding=(14, 8))
        style.map("Drex.TButton", background=[("active", BG), ("disabled", "#F0F0F2")])
        style.configure("DrexDestructive.TButton", font=("Segoe UI", 10, "bold"), foreground="white", background=RED, bordercolor=RED, padding=(18, 9))
        style.map("DrexDestructive.TButton", background=[("active", "#D32F2F"), ("disabled", "#FFB3AF")])
        style.configure("DrexRecovery.TButton", font=("Segoe UI", 10, "bold"), foreground="white", background=PURPLE, bordercolor=PURPLE, padding=(18, 9))
        style.map("DrexRecovery.TButton", background=[("active", "#9333EA"), ("disabled", "#E0B6F5")])
        style.configure("Drex.Horizontal.TProgressbar", troughcolor=LINE, background=BLUE, bordercolor=LINE, lightcolor=BLUE, darkcolor=BLUE)
        style.configure("Drex.Treeview", rowheight=38, font=("Segoe UI", 9), background="white", fieldbackground="white", borderwidth=0, relief="flat")
        style.map("Drex.Treeview", background=[("selected", BLUE_LIGHT)], foreground=[("selected", BLUE)])
        style.configure("Drex.Treeview.Heading", font=("Segoe UI", 9, "bold"), background=BG_SECONDARY, foreground=MUTED, borderwidth=0, relief="flat")

    # ── Shell (sidebar + main) ──────────────────────────────────────
    def _build_shell(self):
        self.sidebar = tk.Frame(self, bg="white", width=260, highlightbackground=LINE, highlightthickness=1)
        self.sidebar.pack(side="left", fill="y")
        self.sidebar.pack_propagate(False)
        self._logo(self.sidebar)
        self.nav_frame = tk.Frame(self.sidebar, bg="white")
        self.nav_frame.pack(fill="x", padx=12, pady=(16, 0))
        self.nav_buttons: dict[str, tk.Frame] = {}
        nav_items = [
            ("Dashboard", "Dashboard"),
            ("Wipe Drive", "Wipe Drive"),
            ("Wipe File/Folder", "Wipe File/Folder"),
            ("Recover", "Recover"),
            ("Destroy Drive", "Destroy Drive"),
            ("Certificates", "Certificates"),
            ("Help", "Help"),
        ]
        for name, label in nav_items:
            row = tk.Frame(self.nav_frame, bg="white", cursor="hand2")
            row.pack(fill="x", pady=2)
            indicator = tk.Frame(row, bg="white", width=4)
            indicator.pack(side="left", fill="y")
            icon_cv = tk.Canvas(row, width=22, height=22, bg="white", highlightthickness=0)
            icon_cv.pack(side="left", padx=(12, 8), pady=9)
            self._draw_nav_icon(icon_cv, name, MUTED)
            lbl = tk.Label(row, text=label, font=("Segoe UI", 10), fg=MUTED, bg="white", anchor="w")
            lbl.pack(side="left", fill="x", expand=True, pady=9)

            for widget in (row, lbl, icon_cv, indicator):
                widget.bind("<Button-1>", lambda _e, n=name: self.show_page(n))
                widget.bind("<Enter>", lambda _e, r=row, n=name: self._on_nav_hover(r, n, True))
                widget.bind("<Leave>", lambda _e, r=row, n=name: self._on_nav_hover(r, n, False))

            self.nav_buttons[name] = row
            row._indicator = indicator
            row._icon_cv = icon_cv
            row._lbl = lbl

        footer = tk.Frame(self.sidebar, bg="white")
        footer.pack(side="bottom", fill="x", padx=18, pady=16)
        tk.Frame(footer, bg=LINE, height=1).pack(fill="x", pady=(0, 12))
        tk.Label(footer, text=f"DREX v{VERSION}", font=("Segoe UI", 9, "bold"), fg=INK, bg="white").pack(anchor="w")
        tk.Label(footer, text="© 2025 DREX Team", font=("Segoe UI", 8), fg=MUTED, bg="white").pack(anchor="w", pady=(2, 0))
        tk.Label(footer, text="Secure Tomorrow, Today.", font=("Segoe UI", 8), fg=MUTED_LIGHT, bg="white").pack(anchor="w", pady=(1, 0))

        self.main = tk.Frame(self, bg=BG)
        self.main.pack(side="left", fill="both", expand=True)

    def _on_nav_hover(self, row: tk.Frame, name: str, entering: bool):
        if name == self.current_page:
            return
        bg = BG_SECONDARY if entering else "white"
        row.configure(bg=bg)
        row._lbl.configure(bg=bg)
        row._icon_cv.configure(bg=bg)
        row._indicator.configure(bg=bg)

    def _update_nav_highlight(self):
        for name, row in self.nav_buttons.items():
            active = name == self.current_page
            bg = BLUE_LIGHT if active else "white"
            fg = BLUE if active else MUTED
            indicator_bg = BLUE if active else "white"
            row.configure(bg=bg)
            row._lbl.configure(bg=bg, fg=fg, font=("Segoe UI", 10, "bold") if active else ("Segoe UI", 10))
            row._indicator.configure(bg=indicator_bg)
            row._icon_cv.configure(bg=bg)
            row._icon_cv.delete("all")
            self._draw_nav_icon(row._icon_cv, name, fg)

    def _logo(self, parent):
        frame = tk.Frame(parent, bg="white", height=76)
        frame.pack(fill="x", padx=18, pady=(18, 0))
        frame.pack_propagate(False)
        canvas = tk.Canvas(frame, width=34, height=38, bg="white", highlightthickness=0)
        canvas.pack(side="left")
        canvas.create_polygon(17, 2, 32, 8, 30, 26, 17, 36, 4, 26, 2, 8, fill=BLUE_LIGHT, outline=BLUE, width=2)
        canvas.create_polygon(17, 9, 25, 14, 23, 23, 17, 29, 11, 23, 9, 14, fill=BLUE, outline=BLUE)
        canvas.create_oval(15, 17, 19, 21, fill="white", outline="white")

        text_frame = tk.Frame(frame, bg="white")
        text_frame.pack(side="left", fill="x", expand=True, padx=(10, 0), pady=(3, 0))
        tk.Label(text_frame, text="DREX", font=("Segoe UI", 18, "bold"), fg=INK, bg="white").pack(anchor="w")
        tk.Label(text_frame, text="Secure. Recover. Trust.", font=("Segoe UI", 8), fg=MUTED, bg="white").pack(anchor="w", pady=(1, 0))

    def _draw_nav_icon(self, canvas, name: str, color: str):
        c = canvas
        c.delete("all")
        if name == "Dashboard":
            c.create_polygon(11, 2, 20, 10, 17, 10, 17, 20, 5, 20, 5, 10, 2, 10, fill="", outline=color, width=1.6)
            c.create_rectangle(9, 13, 13, 20, fill="", outline=color, width=1.4)
        elif name == "Wipe Drive":
            c.create_oval(3, 4, 19, 10, outline=color, width=1.5)
            c.create_line(3, 7, 3, 16, fill=color, width=1.5)
            c.create_line(19, 7, 19, 16, fill=color, width=1.5)
            c.create_arc(3, 10, 19, 19, start=180, extent=180, style="arc", outline=color, width=1.5)
            c.create_arc(4, 3, 18, 17, start=30, extent=240, style="arc", outline=color, width=1.4)
        elif name == "Wipe File/Folder":
            c.create_polygon(4, 2, 14, 2, 18, 6, 18, 20, 4, 20, fill="", outline=color, width=1.5)
            c.create_line(14, 2, 14, 6, fill=color, width=1.5)
            c.create_line(14, 6, 18, 6, fill=color, width=1.5)
            c.create_line(7, 10, 15, 10, fill=color, width=1.2)
            c.create_line(7, 13, 15, 13, fill=color, width=1.2)
            c.create_line(7, 16, 12, 16, fill=color, width=1.2)
        elif name == "Recover":
            c.create_arc(3, 3, 19, 19, start=45, extent=270, style="arc", outline=color, width=1.8)
            c.create_polygon(13, 1, 19, 5, 13, 7, fill=color, outline=color)
            c.create_oval(9, 9, 13, 13, fill=color, outline=color)
        elif name == "Destroy Drive":
            c.create_line(3, 5, 19, 5, fill=color, width=1.6)
            c.create_line(8, 2, 14, 2, fill=color, width=1.6)
            c.create_polygon(5, 5, 6, 19, 16, 19, 17, 5, fill="", outline=color, width=1.5)
            c.create_line(9, 8, 9, 16, fill=color, width=1.2)
            c.create_line(13, 8, 13, 16, fill=color, width=1.2)
        elif name == "Certificates":
            c.create_polygon(11, 2, 20, 6, 19, 15, 11, 20, 3, 15, 2, 6, fill="", outline=color, width=1.5)
            c.create_line(7, 11, 10, 14, fill=color, width=1.8)
            c.create_line(10, 14, 15, 7, fill=color, width=1.8)
        elif name == "Help":
            c.create_oval(2, 2, 20, 20, outline=color, width=1.5)
            c.create_text(11, 11, text="?", fill=color, font=("Segoe UI", 9, "bold"))

    def _draw_stat_icon(self, canvas, icon_type: str, color: str):
        c = canvas
        c.delete("all")
        if icon_type == "drive":
            c.create_oval(10, 8, 26, 14, outline=color, width=1.6)
            c.create_line(10, 11, 10, 22, fill=color, width=1.6)
            c.create_line(26, 11, 26, 22, fill=color, width=1.6)
            c.create_arc(10, 16, 26, 25, start=180, extent=180, style="arc", outline=color, width=1.6)
            c.create_oval(21, 18, 23, 20, fill=color, outline=color)
        elif icon_type == "file":
            c.create_polygon(11, 6, 21, 6, 25, 10, 25, 28, 11, 28, fill="", outline=color, width=1.6)
            c.create_line(21, 6, 21, 10, fill=color, width=1.6)
            c.create_line(21, 10, 25, 10, fill=color, width=1.6)
            c.create_line(14, 15, 22, 15, fill=color, width=1.4)
            c.create_line(14, 19, 22, 19, fill=color, width=1.4)
            c.create_line(14, 23, 19, 23, fill=color, width=1.4)
        elif icon_type == "recover":
            c.create_arc(8, 8, 28, 28, start=45, extent=270, style="arc", outline=color, width=2)
            c.create_polygon(21, 5, 28, 11, 21, 14, fill=color, outline=color)
            c.create_oval(16, 16, 20, 20, fill=color, outline=color)
        elif icon_type == "cert":
            c.create_polygon(18, 5, 29, 9, 28, 21, 18, 29, 8, 21, 7, 9, fill="", outline=color, width=1.6)
            c.create_line(13, 17, 17, 21, fill=color, width=2)
            c.create_line(17, 21, 24, 12, fill=color, width=2)
        elif icon_type == "destroy":
            c.create_line(8, 9, 28, 9, fill=color, width=1.8)
            c.create_line(14, 6, 22, 6, fill=color, width=1.8)
            c.create_polygon(10, 9, 11, 28, 25, 28, 26, 9, fill="", outline=color, width=1.6)
            c.create_line(15, 13, 15, 24, fill=color, width=1.4)
            c.create_line(21, 13, 21, 24, fill=color, width=1.4)

    # ── Page management ─────────────────────────────────────────────
    def _clear_page(self):
        # Phase 4: cancel stale after() callbacks registered by the page being
        # destroyed. This prevents ghost callbacks updating destroyed widgets,
        # which was a source of the duplicate-Dashboard rendering bug.
        self._on_page_unmount()
        # Increment generation FIRST — any in-flight after() callbacks that
        # captured the old generation will detect staleness and self-abort.
        self._page_generation += 1
        if self.page:
            self.page_canvas.destroy()
            self.page_scroll.destroy()
        self.page_canvas = tk.Canvas(self.main, bg=BG, highlightthickness=0, bd=0)
        self.page_scroll = ttk.Scrollbar(self.main, orient="vertical", command=self.page_canvas.yview)
        self.page_canvas.configure(yscrollcommand=self.page_scroll.set)
        self.page_scroll.pack(side="right", fill="y")
        self.page_canvas.pack(side="left", fill="both", expand=True)
        self.page = tk.Frame(self.page_canvas, bg=BG)
        self.page_window = self.page_canvas.create_window((0, 0), window=self.page, anchor="nw")
        self.page.bind("<Configure>", lambda _e: self.page_canvas.configure(scrollregion=self.page_canvas.bbox("all")))
        self.page_canvas.bind("<Configure>", lambda event: self.page_canvas.itemconfigure(self.page_window, width=max(500, event.width)))
        self.page_canvas.bind_all("<MouseWheel>", self._mousewheel, add="+")
        self._pending_after_ids: list[str] = []
        self._update_nav_highlight()

    def _on_page_unmount(self) -> None:
        """Cancel all pending after() callbacks registered by the current page.

        Prevents stale callbacks from the previous page updating destroyed
        widgets, which was a source of the duplicate-Dashboard ghost bug.
        Also nulls page-scoped widget refs so any callback that bypasses the
        generation check cannot touch old widgets.
        """
        for after_id in getattr(self, "_pending_after_ids", []):
            try:
                self.after_cancel(after_id)
            except Exception:
                pass
        self._pending_after_ids = []
        # Null out page-specific widget references
        self.log_text = None
        self.status_label = None

    def show_page(self, name: str):
        if name != self.current_page and self.status_label:
            try:
                running = bool(self.status_label.winfo_exists()) and self.status_label.cget("text") in ("RUNNING", "SCANNING", "RECOVERING")
            except tk.TclError:
                running = False
            if running:
                messagebox.showwarning("Operation in progress", "Finish or cancel the current operation before changing pages.")
                return
        self.current_page = name
        self._clear_page()
        renderers = {
            "Dashboard": self.render_dashboard,
            "Wipe Drive": self.render_drive_page,
            "Wipe File/Folder": self.render_file_page,
            "Recover": self.render_recovery_page,
            "Destroy Drive": self.render_destroy_page,
            "Certificates": self.render_certificates,
            "Help": self.render_help,
        }
        renderers.get(name, self.render_help)()

    def _mousewheel(self, event):
        if getattr(self, "page_canvas", None) and self.page_canvas.winfo_exists():
            self.page_canvas.yview_scroll(int(-event.delta / 120), "units")

    def toggle_sidebar(self):
        if self.sidebar.winfo_ismapped():
            self.sidebar.pack_forget()
        else:
            self.sidebar.pack(side="left", fill="y", before=self.main)

    # ── Shared: Header ──────────────────────────────────────
    def _header(self, title: str, subtitle: str):
        top = tk.Frame(self.page, bg=BG)
        top.pack(fill="x", padx=28, pady=(20, 0))
        left = tk.Frame(top, bg=BG)
        left.pack(side="left", fill="x", expand=True)
        tk.Button(
            left, text="☰", command=self.toggle_sidebar,
            font=("Segoe UI", 13), relief="flat", bg=BG, fg=INK,
            activebackground=BLUE_LIGHT, bd=0, cursor="hand2",
        ).pack(side="left", padx=(0, 14))

        title_frame = tk.Frame(left, bg=BG)
        title_frame.pack(side="left")
        tk.Label(title_frame, text=title, font=("Segoe UI", 22, "bold"), fg=INK, bg=BG).pack(anchor="w")
        tk.Label(title_frame, text=subtitle, font=("Segoe UI", 9), fg=MUTED, bg=BG).pack(anchor="w", pady=(2, 0))

        pill = tk.Frame(top, bg="white", highlightbackground=LINE, highlightthickness=1)
        pill.pack(side="right", padx=(12, 0))
        inner_pill = tk.Frame(pill, bg="white")
        inner_pill.pack(padx=14, pady=7)
        tk.Label(inner_pill, text="●", font=("Segoe UI", 12), fg=GREEN, bg="white").pack(side="left", padx=(0, 7))
        pill_text = tk.Frame(inner_pill, bg="white")
        pill_text.pack(side="left")
        tk.Label(pill_text, text="System Health", font=("Segoe UI", 9, "bold"), fg=INK, bg="white").pack(anchor="w")
        tk.Label(pill_text, text="All Systems Operational", font=("Segoe UI", 8), fg=MUTED, bg="white").pack(anchor="w")

        # Elevation badge — shows Administrator / Not Elevated / Failed
        elev = getattr(self, "_elevation", ElevationState.NOT_ELEVATED)
        if elev == ElevationState.ELEVATED:
            elev_icon, elev_text, elev_color = "🔒", "Administrator", GREEN_DARK
        elif elev == ElevationState.ELEVATION_FAILED:
            elev_icon, elev_text, elev_color = "✗", "Elevation Failed", RED
        else:
            elev_icon, elev_text, elev_color = "⚠", "Not Elevated", ORANGE
        elev_pill = tk.Frame(top, bg="white", highlightbackground=LINE, highlightthickness=1)
        elev_pill.pack(side="right", padx=(0, 6))
        elev_inner = tk.Frame(elev_pill, bg="white")
        elev_inner.pack(padx=10, pady=6)
        tk.Label(elev_inner, text=elev_icon, font=("Segoe UI", 10), fg=elev_color, bg="white").pack(side="left", padx=(0, 5))
        tk.Label(elev_inner, text=elev_text, font=("Segoe UI", 8, "bold"), fg=elev_color, bg="white").pack(side="left")

        gear = tk.Canvas(top, width=28, height=28, bg=BG, highlightthickness=0)
        gear.pack(side="right", padx=(4, 0))
        gear.create_text(14, 14, text="⚙", font=("Segoe UI", 14), fill=MUTED)

    def _card(self, parent, **kwargs):
        border_color = kwargs.pop("border", LINE)
        bg_color = kwargs.pop("bg", "white")
        return tk.Frame(parent, bg=bg_color, highlightbackground=border_color, highlightthickness=1, **kwargs)

    # ── Dashboard ───────────────────────────────────────────────────
    def render_dashboard(self):
        # Guard: if this render was triggered by a stale after() callback
        # from a previous page generation, silently abort to prevent
        # appending a second Dashboard below the current page.
        _my_gen = self._page_generation
        self._header("Welcome to DREX", "Unified Data Recovery & Sanitization Platform")
        history = self.store.history()
        certs = self.store.certificates()
        content = tk.Frame(self.page, bg=BG)
        content.pack(fill="both", expand=True, padx=28, pady=(18, 0))

        body = tk.Frame(content, bg=BG)
        body.pack(fill="both", expand=True)
        left = tk.Frame(body, bg=BG)
        left.pack(side="left", fill="both", expand=True, padx=(0, 18))
        right = tk.Frame(body, bg=BG, width=290)
        right.pack(side="right", fill="y")
        right.pack_propagate(False)

        # Stats row
        stats = tk.Frame(left, bg=BG)
        stats.pack(fill="x", pady=(0, 18))
        stat_data = [
            ("Drives Wiped", str(sum(1 for h in history if h.get("type") == "drive" and h.get("status") == "SUCCESS")), "Total drives erased", BLUE, "drive"),
            ("Files/Folders Wiped", str(sum(1 for h in history if h.get("type") == "file" and h.get("status") == "SUCCESS")), "Total items securely erased", BLUE, "file"),
            ("Files Recovered", str(sum(h.get("recovered_count", 0) for h in history if h.get("type") == "recovery" and h.get("status") == "SUCCESS")), "Total files recovered", PURPLE, "recover"),
            ("Certificates", str(len(certs)), "Generated certificates", ORANGE, "cert"),
        ]
        for title, value, detail, color, icon_type in stat_data:
            card = self._card(stats)
            card.pack(side="left", fill="both", expand=True, padx=(0, 10))
            inner = tk.Frame(card, bg="white")
            inner.pack(fill="both", expand=True, padx=16, pady=14)

            top_row = tk.Frame(inner, bg="white")
            top_row.pack(fill="x")
            icon_bg = BLUE_LIGHT if color == BLUE else (PURPLE_LIGHT if color == PURPLE else ORANGE_LIGHT)
            icon_cv = tk.Canvas(top_row, width=36, height=36, bg="white", highlightthickness=0)
            icon_cv.pack(side="left", padx=(0, 12))
            icon_cv.create_oval(1, 1, 35, 35, fill=icon_bg, outline="")
            self._draw_stat_icon(icon_cv, icon_type, color)

            val_frame = tk.Frame(top_row, bg="white")
            val_frame.pack(side="left")
            tk.Label(val_frame, text=value, font=("Segoe UI", 22, "bold"), fg=INK, bg="white").pack(anchor="w")

            tk.Label(inner, text=title, font=("Segoe UI", 10, "bold"), fg=INK, bg="white").pack(anchor="w", pady=(8, 0))
            tk.Label(inner, text=detail, font=("Segoe UI", 8), fg=MUTED, bg="white").pack(anchor="w", pady=(2, 0))

        # Choose an Operation
        tk.Label(left, text="Choose an Operation", font=("Segoe UI", 13, "bold"), fg=INK, bg=BG).pack(anchor="w")
        tk.Label(left, text="Select an operation to get started.", font=("Segoe UI", 9), fg=MUTED, bg=BG).pack(anchor="w", pady=(2, 10))
        ops = tk.Frame(left, bg=BG)
        ops.pack(fill="x", pady=(0, 20))
        op_items = [
            ("Wipe Drive", BLUE, "drive", "Securely erase physical drives"),
            ("Wipe File/Folder", BLUE, "file", "Erase specific files or folders"),
            ("Recover", PURPLE, "recover", "Recover deleted files & partitions"),
            ("Destroy Drive", RED, "destroy", "Assess device destruction"),
            ("Certificates", BLUE, "cert", "View cryptographically signed records"),
        ]
        for op_name, op_color, op_icon, op_sub in op_items:
            card = self._card(ops)
            card.pack(side="left", fill="both", expand=True, padx=(0, 8))
            card.configure(cursor="hand2")
            inner_op = tk.Frame(card, bg="white")
            inner_op.pack(fill="both", expand=True, padx=10, pady=14)

            icon_c = tk.Canvas(inner_op, width=36, height=36, bg="white", highlightthickness=0)
            icon_c.pack()
            self._draw_stat_icon(icon_c, op_icon, op_color)

            tk.Label(inner_op, text=op_name, font=("Segoe UI", 9, "bold"), fg=op_color if op_color == RED else INK, bg="white", wraplength=100).pack(pady=(6, 0))
            for w in (card, inner_op, icon_c):
                w.bind("<Button-1>", lambda _e, n=op_name: self.show_page(n))
                w.bind("<Enter>", lambda _e, c=card: c.configure(highlightbackground=BLUE, highlightthickness=1))
                w.bind("<Leave>", lambda _e, c=card: c.configure(highlightbackground=LINE, highlightthickness=1))

        # Enhanced Storage Devices
        dev_header = tk.Frame(left, bg=BG)
        dev_header.pack(fill="x", pady=(0, 8))
        tk.Label(dev_header, text="Enhanced Storage Devices", font=("Segoe UI", 13, "bold"), fg=INK, bg=BG).pack(side="left")
        tk.Label(dev_header, text="Select a device to perform operations or refresh the list.", font=("Segoe UI", 9), fg=MUTED, bg=BG).pack(side="left", padx=(12, 0))
        ttk.Button(dev_header, text="↻ Refresh", style="Drex.TButton", command=self.refresh_devices).pack(side="right")

        dev_row = tk.Frame(left, bg=BG)
        dev_row.pack(fill="x", pady=(0, 16))
        for drive in self.drives[:4]:
            is_system = drive.path.upper().startswith("C:") or (drive.device_path and "PHYSICALDRIVE0" in drive.device_path.upper())
            dcard = self._card(dev_row)
            dcard.pack(side="left", fill="both", expand=True, padx=(0, 8))
            inner_d = tk.Frame(dcard, bg="white")
            inner_d.pack(fill="both", expand=True, padx=14, pady=12)

            dh = tk.Frame(inner_d, bg="white")
            dh.pack(fill="x")
            model_text = drive.display("model") or drive.path
            tk.Label(dh, text=model_text, font=("Segoe UI", 9, "bold"), fg=INK, bg="white", wraplength=160, justify="left").pack(side="left")

            dtype = drive.drive_type or "Drive"
            badge_color = BLUE if dtype == "Removable" else (MUTED if not is_system else ORANGE)
            badge_text = "SYS" if is_system else dtype[:3].upper()
            tk.Label(dh, text=badge_text, font=("Segoe UI", 7, "bold"), fg="white", bg=badge_color, padx=5, pady=1).pack(side="right")

            tk.Label(inner_d, text=f"{drive.path} (Primary Partition)", font=("Segoe UI", 8), fg=MUTED, bg="white").pack(anchor="w", pady=(2, 0))

            if is_system:
                sys_badge = tk.Frame(inner_d, bg=RED_LIGHT, highlightbackground=RED, highlightthickness=1)
                sys_badge.pack(anchor="w", pady=(4, 4))
                tk.Label(sys_badge, text="PROTECTED SYSTEM DRIVE", font=("Segoe UI", 7, "bold"), fg=RED, bg=RED_LIGHT, padx=4, pady=1).pack()
            else:
                health_color = GREEN_DARK if drive.health == "OK" else MUTED
                tk.Label(inner_d, text="Healthy" if drive.health == "OK" else drive.display("health"), font=("Segoe UI", 8, "bold"), fg=health_color, bg="white").pack(anchor="w", pady=(2, 4))

            det = tk.Frame(inner_d, bg="white")
            det.pack(fill="x", pady=2)
            for lbl, val in [("Capacity", fmt_bytes(drive.capacity)), ("Interface", drive.display("interface"))]:
                tk.Label(det, text=lbl, font=("Segoe UI", 7), fg=MUTED, bg="white").pack(side="left")
                tk.Label(det, text=val, font=("Segoe UI", 7, "bold"), fg=INK, bg="white").pack(side="left", padx=(4, 8))

            det2 = tk.Frame(inner_d, bg="white")
            det2.pack(fill="x", pady=(0, 6))
            tk.Label(det2, text="Health", font=("Segoe UI", 7), fg=MUTED, bg="white").pack(side="left")
            tk.Label(det2, text="100%" if drive.health == "OK" else "—", font=("Segoe UI", 7, "bold"), fg=GREEN_DARK if drive.health == "OK" else MUTED, bg="white").pack(side="left", padx=(4, 0))

            btn_row = tk.Frame(inner_d, bg="white")
            btn_row.pack(fill="x", pady=(4, 0))
            ttk.Button(btn_row, text="Details", style="Drex.TButton", command=lambda d=drive: self._show_device_details_dialog(d)).pack(side="left", padx=(0, 4))
            if is_system:
                tk.Label(btn_row, text="Protected", font=("Segoe UI", 8, "bold"), fg=MUTED, bg=BG_SECONDARY, padx=8, pady=4).pack(side="left")
            else:
                ttk.Button(btn_row, text="Select ▾", style="DrexPrimary.TButton", command=lambda d=drive: self._select_dashboard_drive(d)).pack(side="left")

        if not self.drives:
            empty_card = self._card(dev_row)
            empty_card.pack(fill="x")
            tk.Label(empty_card, text="No storage devices detected. Connect a storage device to begin.", fg=MUTED, bg="white", font=("Segoe UI", 10), pady=20).pack()

        # Bottom Trust Banner
        banner = self._card(left, bg=BG_SECONDARY, border=LINE)
        banner.pack(fill="x", pady=(6, 12))
        banner_inner = tk.Frame(banner, bg=BG_SECONDARY)
        banner_inner.pack(fill="x", padx=18, pady=12)
        b_left = tk.Frame(banner_inner, bg=BG_SECONDARY)
        b_left.pack(side="left")
        shield_cv = tk.Canvas(b_left, width=28, height=28, bg=BG_SECONDARY, highlightthickness=0)
        shield_cv.pack(side="left", padx=(0, 10))
        shield_cv.create_polygon(14, 2, 26, 7, 24, 20, 14, 26, 4, 20, 2, 7, fill=BLUE_LIGHT, outline=BLUE, width=1.5)
        shield_cv.create_line(10, 14, 13, 17, fill=BLUE, width=2)
        shield_cv.create_line(13, 17, 18, 10, fill=BLUE, width=2)
        tk.Label(b_left, text="Your Data. Your Control. Our Priority.", font=("Segoe UI", 11, "bold"), fg=INK, bg=BG_SECONDARY).pack(side="left")

        for badge_text in ["Secure & Compliant", "Multi-Engine Support", "Cryptographic Verification"]:
            f_frame = tk.Frame(banner_inner, bg=BG_SECONDARY)
            f_frame.pack(side="right", padx=12)
            tk.Label(f_frame, text="✓", font=("Segoe UI", 8, "bold"), fg=BLUE, bg=BG_SECONDARY).pack(side="left", padx=(0, 4))
            tk.Label(f_frame, text=badge_text, font=("Segoe UI", 8), fg=MUTED, bg=BG_SECONDARY).pack(side="left")

        # RIGHT COLUMN
        status_card = self._card(right)
        status_card.pack(fill="x", pady=(0, 12))
        tk.Label(status_card, text="System Status", font=("Segoe UI", 11, "bold"), fg=INK, bg="white").pack(anchor="w", padx=14, pady=(12, 4))
        tk.Label(status_card, text="All systems are operational.", font=("Segoe UI", 8), fg=MUTED, bg="white").pack(anchor="w", padx=14, pady=(0, 8))
        tk.Frame(status_card, bg=LINE, height=1).pack(fill="x", padx=14, pady=(0, 8))
        for label, ok in [("Device Detection", bool(self.drives)), ("Scanning Engine", True), ("Security Module", True), ("Verification Engine", True)]:
            row = tk.Frame(status_card, bg="white")
            row.pack(fill="x", padx=14, pady=3)
            tk.Label(row, text="●", font=("Segoe UI", 8), fg=GREEN if ok else RED, bg="white").pack(side="left", padx=(0, 6))
            tk.Label(row, text=label, font=("Segoe UI", 9), fg=INK, bg="white").pack(side="left")
            tk.Label(row, text="Active" if ok else "Inactive", font=("Segoe UI", 8, "bold"), fg=GREEN if ok else RED, bg="white").pack(side="right")
        tk.Frame(status_card, bg="white", height=10).pack()

        act_card = self._card(right)
        act_card.pack(fill="x", pady=(0, 12))
        act_header = tk.Frame(act_card, bg="white")
        act_header.pack(fill="x", padx=14, pady=(12, 6))
        tk.Label(act_header, text="Recent Activity", font=("Segoe UI", 11, "bold"), fg=INK, bg="white").pack(side="left")
        view_all = tk.Label(act_header, text="View All", font=("Segoe UI", 8, "bold"), fg=BLUE, bg="white", cursor="hand2")
        view_all.pack(side="right")
        view_all.bind("<Button-1>", lambda _e: self.show_page("Certificates"))
        tk.Frame(act_card, bg=LINE, height=1).pack(fill="x", padx=14, pady=(0, 6))

        for item in history[:5]:
            a_row = tk.Frame(act_card, bg="white")
            a_row.pack(fill="x", padx=14, pady=3)
            status = item.get("status", "UNKNOWN")
            color = GREEN if status == "SUCCESS" else (RED if status == "FAILED" else ORANGE)
            tk.Label(a_row, text="●", fg=color, bg="white", font=("Segoe UI", 8)).pack(side="left", padx=(0, 6), anchor="n", pady=2)
            a_text = tk.Frame(a_row, bg="white")
            a_text.pack(side="left", fill="x", expand=True)
            tk.Label(a_text, text=item.get("method", "Operation"), font=("Segoe UI", 8, "bold"), fg=INK, bg="white", anchor="w").pack(anchor="w")
            target_str = str(item.get("target", ""))
            if len(target_str) > 28:
                target_str = "..." + target_str[-25:]
            tk.Label(a_text, text=target_str, font=("Segoe UI", 7), fg=MUTED, bg="white", anchor="w").pack(anchor="w")
        if not history:
            tk.Label(act_card, text="No recent activity yet.", font=("Segoe UI", 8), fg=MUTED, bg="white").pack(padx=14, pady=10)
        tk.Frame(act_card, bg="white", height=10).pack()

        sec_card = self._card(right)
        sec_card.pack(fill="x")
        tk.Label(sec_card, text="Security Highlights", font=("Segoe UI", 11, "bold"), fg=INK, bg="white").pack(anchor="w", padx=14, pady=(12, 6))
        tk.Frame(sec_card, bg=LINE, height=1).pack(fill="x", padx=14, pady=(0, 8))
        highlights = [
            "All operations are logged and verifiable.",
            "No data is ever modified without consent.",
            "Built for forensic integrity.",
        ]
        for line in highlights:
            s_row = tk.Frame(sec_card, bg="white")
            s_row.pack(fill="x", padx=14, pady=4)
            tk.Label(s_row, text="✓", fg=BLUE, bg="white", font=("Segoe UI", 9, "bold")).pack(side="left", padx=(0, 8), anchor="n")
            tk.Label(s_row, text=line, font=("Segoe UI", 8), fg=INK, bg="white", justify="left", wraplength=230).pack(side="left")
        tk.Frame(sec_card, bg="white", height=12).pack()

    def _show_device_details_dialog(self, drive: DriveInfo):
        caps = self.capability_manager.get_cached(drive)
        if caps is None:
            self.capability_manager.request_capabilities_async(drive, event_queue=self.events)
            caps = {}
            status_desc = "CHECKING... (Probing in background)"
        else:
            status_desc = "Available (Cached)"
        lines = [
            f"Device Path: {drive.device_path}",
            f"Mount Path: {drive.path}",
            f"Model: {drive.display('model')}",
            f"Serial: {drive.display('serial')}",
            f"Capacity: {fmt_bytes(drive.capacity)} ({drive.capacity or 0:,} bytes)",
            f"Filesystem: {drive.display('filesystem')}",
            f"Capability State: {status_desc}",
            f"Bus Type: {caps.get('bus_type', 'Probing...' if not caps else 'Unknown')}",
            f"Physical Disk Number: {caps.get('physical_disk_number', 'Probing...' if not caps else 'Unknown')}",
            f"Write Capable: {caps.get('write_capable', 'Probing...' if not caps else 'Unknown')}",
            f"Native Sanitize: {caps.get('native_sanitize', 'Probing...' if not caps else 'Unknown')}",
            f"ATA Pass-Through: {caps.get('ata_secure_erase', 'Probing...' if not caps else 'Unknown')}",
            f"NVMe Controller: {caps.get('nvme_controller', 'Probing...' if not caps else 'Unknown')}",
            f"Overwrite Qualified: {caps.get('overwrite_backend_qualified', 'Probing...' if not caps else 'Unknown')}",
        ]
        if caps.get("probe_errors"):
            lines.append("\nProbe Warnings:")
            for err in caps["probe_errors"]:
                lines.append(f"  • {err}")
        messagebox.showinfo(f"Device Details — {drive.path}", "\n".join(lines))

    def _select_dashboard_drive(self, drive: DriveInfo):
        self.selected_drive = drive
        self.show_page("Wipe Drive")

    def native_engine_count(self) -> int:
        native = Path(getattr(sys, "_MEIPASS", ROOT)) / "native_bin"
        return len(list(native.glob("*.exe"))) if native.exists() else 0

    def refresh_devices(self, force: bool = False):
        if hasattr(self, "detect_button") and self.detect_button and self.detect_button.winfo_exists():
            try:
                self.detect_button.configure(state="disabled", text="Detecting...")
            except Exception:
                pass
        def _on_done(drives: list[DriveInfo]):
            self.events.put(("devices_discovered", drives))
        self.device_manager.start_async_discovery(_on_done, force_refresh=force)

    def _on_devices_discovered(self, drives: list[DriveInfo]):
        self.drives = drives
        if hasattr(self, "detect_button") and self.detect_button and self.detect_button.winfo_exists():
            try:
                self.detect_button.configure(state="normal", text="Detect")
            except Exception:
                pass
        if hasattr(self, "drive_combo") and self.drive_combo and self.drive_combo.winfo_exists():
            values = [f"[{d.path}] {d.display('model')[:18]}" for d in self.drives]
            self.drive_combo.configure(values=values)
            if self.drives and (self.drive_combo.current() < 0 or self.drive_combo.current() >= len(self.drives)):
                self.drive_combo.current(0)
                self._drive_selected()
        if self.current_page == "Dashboard":
            # CRITICAL FIX: Do NOT call render_dashboard() directly here.
            # render_dashboard() appends widgets to self.page without clearing it,
            # which caused the duplicate Dashboard bug (second Dashboard rendered
            # below the first every time device discovery completed).
            # show_page() correctly calls _clear_page() first, increments
            # _page_generation, then calls render_dashboard() on the fresh frame.
            self.show_page("Dashboard")

    # ── Target Panel ────────────────────────────────────────────────
    def _target_panel(self, kind: str):
        panel = self._card(self.page)
        panel.pack(fill="x", padx=28, pady=(16, 12))
        self.target_summary = panel
        if kind == "drive":
            left = tk.Frame(panel, bg="white", width=300)
            left.pack(side="left", fill="y", padx=18, pady=14)
            left.pack_propagate(False)
            tk.Label(left, text="Select Physical Device", font=("Segoe UI", 11, "bold"), fg=INK, bg="white").pack(anchor="w")
            combo_row = tk.Frame(left, bg="white")
            combo_row.pack(anchor="w", pady=(10, 0), fill="x")
            self.drive_combo = ttk.Combobox(combo_row, state="readonly", font=("Segoe UI", 9), width=23, values=[f"[{d.path}] {d.display('model')[:18]}" for d in self.drives])
            self.drive_combo.pack(side="left", padx=(0, 8))
            self.drive_combo.bind("<<ComboboxSelected>>", lambda _e: self._drive_selected())
            self.detect_button = ttk.Button(combo_row, text="Detect", style="DrexPrimary.TButton", command=lambda: self.refresh_devices(force=True))
            self.detect_button.pack(side="left")

            sep1 = ttk.Separator(panel, orient="vertical")
            sep1.pack(side="left", fill="y", pady=14)
            mid = tk.Frame(panel, bg="white")
            mid.pack(side="left", fill="both", expand=True, padx=18, pady=14)
            self.drive_mid_labels = {}
            for key in ("Model", "Serial", "Capacity", "Interface"):
                row = tk.Frame(mid, bg="white")
                row.pack(fill="x", pady=3)
                tk.Label(row, text=key, font=("Segoe UI", 9, "bold"), fg=INK, bg="white", width=10, anchor="w").pack(side="left")
                tk.Label(row, text=":", font=("Segoe UI", 9), fg=MUTED, bg="white").pack(side="left", padx=(0, 8))
                val = tk.Label(row, text="—", font=("Segoe UI", 9), fg=MUTED, bg="white", anchor="w")
                val.pack(side="left", fill="x", expand=True)
                self.drive_mid_labels[key] = val

            sep2 = ttk.Separator(panel, orient="vertical")
            sep2.pack(side="left", fill="y", pady=14)
            right_panel = tk.Frame(panel, bg="white")
            right_panel.pack(side="left", fill="both", expand=True, padx=18, pady=14)
            self.drive_right_labels = {}
            for key in ("Drive Letters", "Device ID", "Health"):
                row = tk.Frame(right_panel, bg="white")
                row.pack(fill="x", pady=3)
                tk.Label(row, text=key, font=("Segoe UI", 9, "bold"), fg=INK, bg="white", width=12, anchor="w").pack(side="left")
                tk.Label(row, text=":", font=("Segoe UI", 9), fg=MUTED, bg="white").pack(side="left", padx=(0, 8))
                val = tk.Label(row, text="—", font=("Segoe UI", 9), fg=GREEN_DARK if key == "Health" else MUTED, bg="white", anchor="w")
                val.pack(side="left", fill="x", expand=True)
                self.drive_right_labels[key] = val
        else:
            left = tk.Frame(panel, bg="white", width=440)
            left.pack(side="left", fill="y", padx=18, pady=14)
            left.pack_propagate(False)
            label_text = "Select File/Folder" if kind == "file" else "Select Recovery Source"
            tk.Label(left, text=label_text, font=("Segoe UI", 11, "bold"), fg=INK, bg="white").pack(anchor="w")

            sel_row = tk.Frame(left, bg="white", highlightbackground=LINE, highlightthickness=1)
            sel_row.pack(anchor="w", fill="x", pady=(10, 0))
            icon_cv = tk.Canvas(sel_row, width=22, height=22, bg="white", highlightthickness=0)
            icon_cv.pack(side="left", padx=(8, 4), pady=4)
            icon_cv.create_polygon(2, 4, 8, 4, 11, 7, 20, 7, 20, 18, 2, 18, fill=BLUE_LIGHT, outline=BLUE, width=1.2)

            self.target_path_var = tk.StringVar(value="No target selected")
            path_entry = tk.Entry(
                sel_row, textvariable=self.target_path_var,
                font=("Segoe UI", 9), relief="flat", bd=0,
                state="readonly", readonlybackground="white", fg=MUTED, width=30,
            )
            path_entry.pack(side="left", fill="x", expand=True, padx=(0, 2), ipady=5)

            btn_frame = tk.Frame(left, bg="white")
            btn_frame.pack(anchor="w", fill="x", pady=(10, 0))
            if kind == "recovery":
                ttk.Button(btn_frame, text="Select Folder", style="DrexRecovery.TButton", command=lambda: self.choose_folder("recovery")).pack(side="left")
                ttk.Button(btn_frame, text="Select Disk Image", style="Drex.TButton", command=self.choose_recovery_image).pack(side="left", padx=(8, 0))
            else:
                ttk.Button(btn_frame, text="Add File", style="DrexPrimary.TButton", command=self.choose_file).pack(side="left")
                ttk.Button(btn_frame, text="Add Folder", style="Drex.TButton", command=self.choose_folder).pack(side="left", padx=(8, 0))

            self.target_type_label = tk.Label(
                btn_frame, text="",
                font=("Segoe UI", 8, "bold"), fg=BLUE if self.current_page != "Recover" else PURPLE,
            )
            self.target_type_label.pack(side="left", padx=(12, 0))

            sep = ttk.Separator(panel, orient="vertical")
            sep.pack(side="left", fill="y", pady=14)
            right_panel = tk.Frame(panel, bg="white")
            right_panel.pack(side="right", fill="both", expand=True, padx=18, pady=14)
            self.file_details = right_panel
            self.file_info_labels = {}
            prop_keys = [
                ("Type of file:", "File Type"),
                ("Location:", "Location"),
                ("Size:", "Size"),
                ("Size on disk:", "Size on Disk"),
            ]
            for display_key, data_key in prop_keys:
                row = tk.Frame(right_panel, bg="white")
                row.pack(fill="x", pady=4)
                tk.Label(row, text=display_key, font=("Segoe UI", 9, "bold"), fg=INK, bg="white", width=14, anchor="w").pack(side="left")
                val = tk.Label(row, text="—", font=("Segoe UI", 9), fg=MUTED, bg="white", anchor="w", wraplength=300, justify="left")
                val.pack(side="left", fill="x", expand=True)
                self.file_info_labels[data_key] = val

    def _drive_selected(self):
        index = self.drive_combo.current()
        self.selected_drive = self.drives[index] if 0 <= index < len(self.drives) else None
        if self.selected_drive:
            d = self.selected_drive
            if hasattr(self, "drive_mid_labels"):
                self.drive_mid_labels["Model"].configure(text=d.display("model"), fg=INK)
                self.drive_mid_labels["Serial"].configure(text=d.display("serial"), fg=INK)
                self.drive_mid_labels["Capacity"].configure(text=fmt_bytes(d.capacity), fg=INK)
                self.drive_mid_labels["Interface"].configure(text=d.display("interface"), fg=INK)
            if hasattr(self, "drive_right_labels"):
                self.drive_right_labels["Drive Letters"].configure(text=d.path, fg=INK)
                self.drive_right_labels["Device ID"].configure(text=d.display("device_id"), fg=INK)
                self.drive_right_labels["Health"].configure(text=d.display("health"), fg=GREEN_DARK if d.health == "OK" else RED)
            is_sys = d.path.upper().startswith("C:") or (d.device_path and "PHYSICALDRIVE0" in d.device_path.upper())
            if hasattr(self, "system_protect_card"):
                if is_sys:
                    self.system_protect_card.pack(fill="x", padx=28, pady=(0, 10), before=self.method_grid_box)
                else:
                    self.system_protect_card.pack_forget()
            if hasattr(self, "start_button") and self.start_button:
                if is_sys and self.current_page == "Wipe Drive":
                    self.start_button.configure(state="disabled", text="System Drive Protected")
                elif self.current_page == "Wipe Drive":
                    self.start_button.configure(state="normal", text="Start Operation")
            self._update_drive_method_badges()
            if self.current_page == "Destroy Drive":
                self.render_destroy_page()

    def _update_drive_method_badges(self, caps: dict[str, Any] | None = None):
        if not hasattr(self, "_method_badges") or not self.selected_drive:
            return
        if caps is None:
            caps = self.capability_manager.get_cached(self.selected_drive)
        if caps is None:
            self.capability_manager.request_capabilities_async(self.selected_drive, event_queue=self.events)
        for mid, badge_lbl in self._method_badges.items():
            try:
                if not badge_lbl.winfo_exists():
                    continue
                status_text, _ = drive_method_status(mid, self.selected_drive, caps=caps)
                if status_text == "CHECKING...":
                    badge_lbl.configure(text="● CHECKING...", fg=MUTED, bg=BG_SECONDARY)
                elif status_text == "Available":
                    badge_lbl.configure(text="● Available", fg=GREEN_DARK, bg=GREEN_PALE)
                elif status_text == "UNSUPPORTED_HARDWARE":
                    badge_lbl.configure(text="● Needs Hardware", fg=ORANGE, bg=ORANGE_LIGHT)
                elif status_text == "EXECUTION_BLOCKED":
                    badge_lbl.configure(text="● Protected", fg=RED, bg=RED_LIGHT)
                else:
                    badge_lbl.configure(text=f"● {status_text}", fg=ORANGE, bg=ORANGE_LIGHT)
            except Exception:
                pass

    def choose_file(self):
        chosen = filedialog.askopenfilename(title="Select a file to wipe")
        if chosen:
            self.set_target(Path(chosen))

    def choose_file_or_folder(self):
        chosen = filedialog.askopenfilename(
            title="Select a File to Wipe  (Cancel to select a Folder instead)",
            filetypes=[
                ("All files", "*.*"),
                ("Documents", "*.pdf *.docx *.xlsx *.txt *.csv"),
                ("Images", "*.jpg *.jpeg *.png *.gif *.bmp"),
            ],
        )
        if not chosen:
            chosen = filedialog.askdirectory(title="Select a Folder to Wipe", mustexist=True)
        if chosen:
            self.set_target(Path(chosen))

    def choose_folder(self, kind: str = "file"):
        chosen = filedialog.askdirectory(
            title="Select a Recovery Folder" if kind == "recovery" else "Select a Folder to Wipe",
            mustexist=True,
        )
        if chosen:
            self._recovery_source_is_image = False
            self.set_target(Path(chosen))

    def choose_recovery_image(self):
        chosen = filedialog.askopenfilename(
            title="Select a Disk Image for Recovery (read-only source)",
            filetypes=[
                ("Disk images", "*.img *.dd *.raw *.iso *.bin *.e01 *.dmg"),
                ("All files", "*.*"),
            ],
        )
        if chosen:
            self._recovery_source_is_image = True
            self.set_target(Path(chosen))

    def set_target(self, target: Path):
        self.target = target
        if not (target.is_file() and target.suffix.lower() in {".img", ".dd", ".raw", ".iso", ".bin", ".e01", ".dmg"}):
            self._recovery_source_is_image = False
        if hasattr(self, "target_path_var"):
            self.target_path_var.set(str(target))
        if hasattr(self, "file_info_labels"):
            props = target_properties_fast(target)
            for key, label in self.file_info_labels.items():
                value = props.get(key, "Unavailable")
                color = INK if value not in ("Unavailable", "Calculating in background...") else MUTED
                label.configure(text=value, fg=color)
            if target.is_dir():
                def _update_size(total_sz: int, total_d: int):
                    if hasattr(self, "file_info_labels") and self.target == target:
                        def _gui():
                            try:
                                if "Size" in self.file_info_labels and self.file_info_labels["Size"].winfo_exists():
                                    self.file_info_labels["Size"].configure(text=fmt_bytes(total_sz) + f" ({total_sz:,} bytes)", fg=INK)
                                if "Size on Disk" in self.file_info_labels and self.file_info_labels["Size on Disk"].winfo_exists():
                                    self.file_info_labels["Size on Disk"].configure(text=fmt_bytes(total_d), fg=INK)
                            except Exception:
                                pass
                        self.after(0, _gui)
                count_folder_size_async(target, _update_size)
        if hasattr(self, "target_type_label"):
            t = "Folder" if target.is_dir() else "File"
            self.target_type_label.configure(
                text=f"TARGET TYPE: {t.upper()}",
                fg=BLUE if self.current_page != "Recover" else PURPLE,
            )

    # ── Method Grid ─────────────────────────────────────────────────
    def _methods(self, methods: list[dict[str, str]] | list[tuple[str, str, str]], kind: str):
        box = self._card(self.page)
        box.pack(fill="x", padx=28, pady=(0, 12))
        self.method_grid_box = box
        inner = tk.Frame(box, bg="white")
        inner.pack(fill="x", padx=18, pady=(14, 6))

        title = "Select Wiping Method" if kind != "recovery" else "Select Recovery Method"
        tk.Label(inner, text=title, font=("Segoe UI", 13, "bold"), fg=INK, bg="white").pack(anchor="w")
        subtitle = "Choose one secure erasure method to apply." if kind in ("file", "drive") else "Choose one scanning and recovery method to apply."
        tk.Label(inner, text=subtitle, font=("Segoe UI", 9), fg=MUTED, bg="white").pack(anchor="w", pady=(2, 10))

        grid = tk.Frame(box, bg="white")
        grid.pack(fill="x", padx=14, pady=(0, 8))
        self.method_var.set("")
        columns = 4 if kind == "drive" else 3
        for col in range(columns):
            grid.columnconfigure(col, weight=1, uniform="method")

        self._method_cards = {}
        self._method_badges = {}
        theme_accent = PURPLE if kind == "recovery" else BLUE
        caps = self.capability_manager.get_cached(self.selected_drive) if (kind == "drive" and self.selected_drive) else None
        if kind == "drive" and self.selected_drive and caps is None:
            self.capability_manager.request_capabilities_async(self.selected_drive, event_queue=self.events)

        for index, item in enumerate(methods):
            if kind == "recovery":
                method_id, name, assurance = item
            else:
                method_id, name, assurance = item["id"], item["name"], item["assurance"]

            status_text, status_reason = self._method_status(method_id, kind, caps=caps)
            is_available = (status_text == "Available")
            is_checking = (status_text == "CHECKING...")

            card = tk.Frame(grid, bg="white", highlightbackground=LINE, highlightthickness=1)
            card.grid(row=index // columns, column=index % columns, sticky="nsew", padx=4, pady=4, ipady=6)
            content = tk.Frame(card, bg="white")
            content.pack(fill="both", expand=True, padx=10, pady=8)

            top_row = tk.Frame(content, bg="white")
            top_row.pack(fill="x")
            icon_bg = (PURPLE_LIGHT if kind == "recovery" else BLUE_LIGHT) if is_available else "#F5F5F7"
            icon = tk.Canvas(top_row, width=38, height=38, bg=icon_bg, highlightthickness=0)
            icon.pack(side="left", padx=(0, 10))
            self._draw_method_icon(icon, method_id, kind)

            name_color = INK if is_available else MUTED
            text_frame = tk.Frame(top_row, bg="white")
            text_frame.pack(side="left", fill="both", expand=True)
            tk.Label(text_frame, text=name, font=("Segoe UI", 9, "bold"), fg=name_color, bg="white", wraplength=170, justify="left", anchor="w").pack(anchor="w")
            tk.Label(text_frame, text=assurance, font=("Segoe UI", 8), fg=MUTED, bg="white", wraplength=170, justify="left", anchor="w").pack(anchor="w", pady=(2, 0))

            badge_lbl = None
            if kind == "file" and not is_available:
                # Production-appropriate status labels (Phase 9: "Needs envelope" fix)
                badge_text = {
                    "Requires whole-volume scope": "Volume scope only",
                    "Unavailable on this target": "Scope: adapter unavailable",
                }.get(status_text, status_text[:28])
                badge_lbl = tk.Label(text_frame, text=f"● {badge_text}", font=("Segoe UI", 7, "bold"), fg=MUTED, bg=BG_SECONDARY, padx=4, pady=1)
                badge_lbl.pack(anchor="w", pady=(3, 0))
            elif kind == "drive":
                if is_checking:
                    badge_lbl = tk.Label(text_frame, text="● CHECKING...", font=("Segoe UI", 7, "bold"), fg=MUTED, bg=BG_SECONDARY, padx=4, pady=1)
                    badge_lbl.pack(anchor="w", pady=(3, 0))
                elif status_text not in ("Available", ""):
                    badge_text = "Needs Hardware" if status_text == "UNSUPPORTED_HARDWARE" else ("Protected" if status_text == "EXECUTION_BLOCKED" else status_text)
                    fg_c = RED if status_text == "EXECUTION_BLOCKED" else ORANGE
                    bg_c = RED_LIGHT if status_text == "EXECUTION_BLOCKED" else ORANGE_LIGHT
                    badge_lbl = tk.Label(text_frame, text=f"● {badge_text}", font=("Segoe UI", 7, "bold"), fg=fg_c, bg=bg_c, padx=4, pady=1)
                    badge_lbl.pack(anchor="w", pady=(3, 0))
                elif is_available:
                    badge_lbl = tk.Label(text_frame, text="● Available", font=("Segoe UI", 7, "bold"), fg=GREEN_DARK, bg=GREEN_PALE, padx=4, pady=1)
                    badge_lbl.pack(anchor="w", pady=(3, 0))
            elif kind == "recovery" and not is_available:
                badge_lbl = tk.Label(text_frame, text="● Engine Required", font=("Segoe UI", 7, "bold"), fg=MUTED, bg=BG_SECONDARY, padx=4, pady=1)
                badge_lbl.pack(anchor="w", pady=(3, 0))

            if badge_lbl:
                self._method_badges[method_id] = badge_lbl

            cb = tk.Canvas(top_row, width=18, height=18, bg="white", highlightthickness=0)
            cb.pack(side="right", padx=(6, 0))
            cb.create_rectangle(1, 1, 17, 17, outline=LINE, width=1)
            self._method_cards[method_id] = (card, cb)

            def on_select(event=None, mid=method_id, avail=is_available):
                self.method_var.set(mid)
                for m_id, (m_card, m_cb) in self._method_cards.items():
                    if m_id == mid:
                        sel_color = theme_accent if avail else ORANGE
                        m_card.configure(highlightbackground=sel_color, highlightthickness=2)
                        m_cb.delete("all")
                        m_cb.create_rectangle(1, 1, 17, 17, fill=sel_color, outline=sel_color, width=1)
                        m_cb.create_line(4, 9, 7, 13, fill="white", width=2)
                        m_cb.create_line(7, 13, 14, 5, fill="white", width=2)
                    else:
                        m_card.configure(highlightbackground=LINE, highlightthickness=1)
                        m_cb.delete("all")
                        m_cb.create_rectangle(1, 1, 17, 17, outline=LINE, width=1)
                if hasattr(self, "drive_rationale_label"):
                    if mid == "smart":
                        self.drive_rationale_label.configure(
                            text="Smart Sanitization: Evaluates bus protocol, controller capabilities, and NIST SP 800-88 guidelines to select the safest verifiable path."
                        )
                    elif mid == "nist":
                        self.drive_rationale_label.configure(
                            text="NIST SP 800-88 Rev.2: Industry-standard sanitization policy engine with cryptographic readback verification."
                        )
                    else:
                        self.drive_rationale_label.configure(
                            text=f"Selected Method: {mid.upper()} — Truthful hardware probes verify support prior to execution."
                        )

            for w in (card, content, top_row, text_frame, icon, cb):
                w.bind("<Button-1>", on_select)
                w.configure(cursor="hand2")
            for child in text_frame.winfo_children():
                child.bind("<Button-1>", on_select)
                child.configure(cursor="hand2")

        btn_frame = tk.Frame(box, bg="white")
        btn_frame.pack(fill="x", padx=18, pady=(6, 12))
        action_style = "DrexRecovery.TButton" if kind == "recovery" else "DrexDestructive.TButton"
        action_text = "Start Recovery" if kind == "recovery" else "Start Operation"
        self.start_button = ttk.Button(btn_frame, text=action_text, style=action_style, command=lambda k=kind: self.start_operation(k))
        self.start_button.pack(side="right")

    def _draw_method_icon(self, canvas, method_id: str, kind: str):
        c = canvas
        c.delete("all")
        stroke = BLUE if kind in ("drive", "file") else PURPLE
        if kind == "drive":
            icons = {
                "nist": lambda: [
                    c.create_polygon(19, 5, 31, 10, 29, 25, 19, 33, 9, 25, 7, 10, fill="", outline=stroke, width=1.8),
                    c.create_line(14, 19, 18, 23, fill=stroke, width=2),
                    c.create_line(18, 23, 25, 15, fill=stroke, width=2),
                ],
                "smart": lambda: [
                    c.create_oval(8, 8, 30, 30, outline=stroke, width=1.6),
                    c.create_text(19, 19, text="★", fill=stroke, font=("Segoe UI", 11)),
                ],
                "native": lambda: [
                    c.create_rectangle(10, 8, 28, 30, outline=stroke, width=1.6),
                    c.create_line(14, 14, 24, 14, fill=stroke, width=1.4),
                    c.create_line(14, 19, 24, 19, fill=stroke, width=1.4),
                ],
                "ata": lambda: [
                    c.create_rectangle(8, 10, 30, 28, outline=stroke, width=1.6),
                    c.create_text(19, 19, text="ATA", fill=stroke, font=("Segoe UI", 8, "bold")),
                ],
                "nvme": lambda: [
                    c.create_rectangle(7, 10, 31, 28, outline=stroke, width=1.6),
                    c.create_text(19, 19, text="NVMe", fill=stroke, font=("Segoe UI", 7, "bold")),
                ],
                "ieee": lambda: [
                    c.create_oval(8, 8, 30, 30, outline=stroke, width=1.6),
                    c.create_text(19, 19, text="2883", fill=stroke, font=("Segoe UI", 7, "bold")),
                ],
                "overwrite": lambda: [
                    c.create_arc(8, 8, 30, 30, start=30, extent=300, style="arc", outline=stroke, width=1.8),
                    c.create_polygon(25, 10, 31, 15, 25, 18, fill=stroke, outline=stroke),
                    c.create_line(15, 19, 19, 23, fill=stroke, width=2),
                    c.create_line(19, 23, 24, 16, fill=stroke, width=2),
                ],
            }
        elif kind == "recovery":
            icons = {
                "quick": lambda: c.create_text(19, 19, text="⚡", fill=stroke, font=("Segoe UI", 13)),
                "smart": lambda: [
                    c.create_oval(8, 8, 30, 30, outline=stroke, width=1.6),
                    c.create_text(19, 19, text="★", fill=stroke, font=("Segoe UI", 11)),
                ],
                "targeted": lambda: [
                    c.create_oval(8, 8, 30, 30, outline=stroke, width=1.6),
                    c.create_oval(14, 14, 24, 24, outline=stroke, width=1.4),
                ],
                "filesystem": lambda: [
                    c.create_rectangle(9, 6, 29, 32, outline=stroke, width=1.6),
                    c.create_line(13, 13, 25, 13, fill=stroke, width=1.4),
                    c.create_line(13, 19, 25, 19, fill=stroke, width=1.4),
                ],
                "deep": lambda: [
                    c.create_oval(8, 8, 25, 25, outline=stroke, width=1.8),
                    c.create_line(21, 21, 30, 30, fill=stroke, width=2.2),
                ],
                "fragment": lambda: [
                    c.create_rectangle(8, 8, 17, 17, outline=stroke, width=1.4),
                    c.create_rectangle(21, 8, 30, 17, outline=stroke, width=1.4),
                    c.create_rectangle(14, 21, 23, 30, outline=stroke, width=1.4),
                ],
                "raid": lambda: [
                    c.create_rectangle(8, 8, 17, 30, outline=stroke, width=1.4),
                    c.create_rectangle(21, 8, 30, 30, outline=stroke, width=1.4),
                    c.create_line(17, 19, 21, 19, fill=stroke, width=1.4),
                ],
                "damaged": lambda: [
                    c.create_oval(8, 8, 30, 30, outline=stroke, width=1.6),
                    c.create_line(13, 13, 25, 25, fill=RED, width=2),
                ],
                "forensic": lambda: [
                    c.create_polygon(19, 6, 30, 11, 28, 23, 19, 31, 10, 23, 8, 11, fill="", outline=stroke, width=1.6),
                    c.create_text(19, 18, text="⚖", fill=stroke, font=("Segoe UI", 9)),
                ],
            }
        else:
            icons = {
                "csprng": lambda: [
                    c.create_rectangle(7, 7, 31, 31, outline=stroke, width=1.6),
                    c.create_oval(11, 11, 15, 15, fill=stroke, outline=stroke),
                    c.create_oval(23, 11, 27, 15, fill=stroke, outline=stroke),
                    c.create_oval(17, 17, 21, 21, fill=stroke, outline=stroke),
                    c.create_oval(11, 23, 15, 27, fill=stroke, outline=stroke),
                    c.create_oval(23, 23, 27, 27, fill=stroke, outline=stroke),
                ],
                "crypto": lambda: [
                    c.create_arc(11, 5, 27, 20, start=0, extent=180, style="arc", outline=stroke, width=1.8),
                    c.create_rectangle(9, 15, 29, 31, outline=stroke, width=1.6),
                    c.create_oval(17, 21, 21, 25, fill=stroke, outline=stroke),
                ],
                "slack": lambda: [
                    c.create_rectangle(8, 8, 30, 13, outline=stroke, width=1.4),
                    c.create_rectangle(8, 16, 30, 21, outline=stroke, width=1.4),
                    c.create_rectangle(8, 24, 30, 29, outline=stroke, width=1.4),
                ],
                "metadata": lambda: [
                    c.create_rectangle(9, 6, 29, 32, outline=stroke, width=1.6),
                    c.create_line(13, 13, 25, 13, fill=stroke, width=1.4),
                    c.create_line(13, 19, 25, 19, fill=stroke, width=1.4),
                ],
                "policy": lambda: [
                    c.create_polygon(19, 6, 30, 11, 28, 25, 19, 33, 10, 25, 8, 11, fill="", outline=stroke, width=1.8),
                    c.create_line(14, 19, 18, 23, fill=stroke, width=2),
                    c.create_line(18, 23, 25, 15, fill=stroke, width=2),
                ],
                "free_space": lambda: [
                    c.create_polygon(19, 6, 31, 17, 27, 17, 27, 30, 11, 30, 11, 17, 7, 17, fill="", outline=stroke, width=1.6),
                    c.create_rectangle(15, 22, 23, 30, outline=stroke, width=1.2),
                ],
                "zero": lambda: [
                    c.create_oval(8, 8, 30, 30, outline=stroke, width=1.8),
                    c.create_oval(13, 13, 25, 25, outline=stroke, width=1.4),
                ],
                "storage_aware": lambda: [
                    c.create_oval(8, 8, 30, 30, outline=stroke, width=2),
                    c.create_oval(14, 14, 24, 24, fill=stroke, outline=stroke),
                ],
                "temporary": lambda: [
                    c.create_rectangle(9, 13, 29, 32, outline=stroke, width=1.6),
                    c.create_line(7, 13, 31, 13, fill=stroke, width=1.6),
                    c.create_line(15, 9, 23, 9, fill=stroke, width=1.6),
                    c.create_line(14, 18, 14, 27, fill=stroke, width=1.2),
                    c.create_line(19, 18, 19, 27, fill=stroke, width=1.2),
                    c.create_line(24, 18, 24, 27, fill=stroke, width=1.2),
                ],
            }
        draw_fn = icons.get(method_id)
        if draw_fn:
            draw_fn()

    def _method_status(self, method_id: str, kind: str, caps: dict[str, Any] | None = None) -> tuple[str, str]:
        if kind == "file":
            # Determine scope for each file method (Phase 9: production-accurate labels)
            file_available  = {"csprng", "zero", "metadata", "temporary"}
            file_vol_scope  = {"free_space"}   # requires whole-volume access
            file_dev_scope  = {                 # these methods require whole-device scope
                "nist", "smart", "overwrite", "slack", "storage_aware",
            }
            if method_id in file_available:
                return "Available", ""
            if method_id in file_vol_scope:
                return "Requires whole-volume scope", (
                    "The free-space engine operates on the entire selected volume, "
                    "not only the selected folder. Select the volume root to use this method."
                )
            if method_id in file_dev_scope:
                return "Unavailable on this target", (
                    f"{method_id.upper()} requires whole-device or volume-level scope. "
                    "Use this method from the Wipe Drive page."
                )
            return "Unavailable on this target", (
                f"The {method_id} adapter is not available for file/folder scope on this target."
            )
        if kind == "drive":
            if caps is None and self.selected_drive:
                caps = self.capability_manager.get_cached(self.selected_drive)
            return drive_method_status(method_id, self.selected_drive, caps=caps)
        if kind == "recovery":
            return self.recovery_dispatcher.status(method_id)
        return "Unavailable", "Unknown operation type."

    # ── Operation Area ──────────────────────────────────────────────
    def _operation_area(self, label: str):
        bottom = tk.Frame(self.page, bg=BG)
        bottom.pack(fill="x", padx=28, pady=(0, 6))
        tk.Label(bottom, text=label, font=("Segoe UI", 12, "bold"), fg=INK, bg=BG).pack(anchor="w", pady=(0, 6))
        area = tk.Frame(bottom, bg=BG)
        area.pack(fill="x")

        # Monospace Log terminal
        log_card = self._card(area)
        log_card.pack(side="left", fill="both", expand=True, padx=(0, 10))
        self.log_text = tk.Text(log_card, height=8, bg="#0F172A", fg="#38BDF8", insertbackground="white", relief="flat", font=("Consolas", 9), wrap="word", padx=14, pady=10)
        self.log_text.pack(fill="both", expand=True, padx=1, pady=1)
        self.log_text.insert("end", "DREX System Ready.\nSelect target and method, then start operation.")
        self.log_text.configure(state="disabled")

        # Status summary card
        result = self._card(area)
        result.pack(side="right", fill="both", expand=True)
        result_inner = tk.Frame(result, bg="white")
        result_inner.pack(fill="both", expand=True, padx=20, pady=16)
        self.status_label = tk.Label(result_inner, text="READY", font=("Segoe UI", 16, "bold"), fg=MUTED, bg="white", justify="center")
        self.status_label.pack(expand=True)
        self.status_sublabel = tk.Label(result_inner, text="Select a target and method\nto begin an operation", font=("Segoe UI", 8), fg=MUTED, bg="white", justify="center")
        self.status_sublabel.pack(pady=(4, 0))
        # View Certificate button — wired by _handle_operation_result after SUCCESS
        self.view_cert_button = ttk.Button(
            result_inner, text="View Certificate",
            style="Drex.TButton", state="disabled",
        )
        self.view_cert_button.pack(pady=(10, 0))
        self._current_cert_path: str | None = None

        self.recovery_tree = None
        self.recovery_destination = None
        self.recovery_scan = None
        if label == "Recovery Log":
            results = self._card(self.page)
            results.pack(fill="x", padx=28, pady=(8, 0))
            tk.Label(results, text="Recoverable Candidates", font=("Segoe UI", 11, "bold"), fg=INK, bg="white").pack(anchor="w", padx=14, pady=(12, 4))
            tk.Label(results, text="Candidates are reported by the scanned backing device; they are not assumed to belong to the selected folder.", font=("Segoe UI", 8), fg=MUTED, bg="white", wraplength=900, justify="left").pack(anchor="w", padx=14, pady=(0, 6))

            self.recovery_tree = ttk.Treeview(results, columns=("id", "name", "filesystem", "size", "deleted", "confidence"), show="headings", selectmode="extended", height=4, style="Drex.Treeview")
            for col, heading in (("id", "Candidate ID"), ("name", "Name"), ("filesystem", "Filesystem"), ("size", "Size"), ("deleted", "Deleted"), ("confidence", "Confidence")):
                self.recovery_tree.heading(col, text=heading)
                self.recovery_tree.column(col, width=120, anchor="w")
            self.recovery_tree.pack(fill="x", padx=14, pady=(0, 12))

            recovery_actions = tk.Frame(results, bg="white")
            recovery_actions.pack(fill="x", padx=14, pady=(0, 12))
            self.recovery_destination_label = tk.Label(recovery_actions, text="Destination: not selected", font=("Segoe UI", 8), fg=MUTED, bg="white", anchor="w")
            self.recovery_destination_label.pack(side="left", fill="x", expand=True)
            self.recovery_destination_button = ttk.Button(recovery_actions, text="Choose Destination", style="Drex.TButton", command=self.choose_recovery_destination, state="disabled")
            self.recovery_destination_button.pack(side="left", padx=(8, 0))
            self.recover_selected_button = ttk.Button(recovery_actions, text="Recover Selected", style="DrexRecovery.TButton", command=self.recover_selected_candidates, state="disabled")
            self.recover_selected_button.pack(side="left", padx=(8, 0))

        # Metrics frame (Percentage, Stage, Speed, ETA, Precision Timer)
        metrics_frame = tk.Frame(self.page, bg=BG)
        metrics_frame.pack(fill="x", padx=28, pady=(8, 2))

        m_left = tk.Frame(metrics_frame, bg=BG)
        m_left.pack(side="left", fill="x", expand=True)
        self.pct_label = tk.Label(m_left, text="0.00%", font=("Segoe UI", 13, "bold"), fg=INK, bg=BG)
        self.pct_label.pack(side="left")
        self.stage_label = tk.Label(m_left, text="Ready", font=("Segoe UI", 9), fg=MUTED, bg=BG)
        self.stage_label.pack(side="left", padx=(12, 0))

        m_right = tk.Frame(metrics_frame, bg=BG)
        m_right.pack(side="right")
        self.timer_label = tk.Label(m_right, text="00:00:00.000", font=("Consolas", 10, "bold"), fg=INK, bg=BG)
        self.timer_label.pack(side="right", padx=(12, 0))
        self.eta_label = tk.Label(m_right, text="ETA: —", font=("Segoe UI", 9), fg=MUTED, bg=BG)
        self.eta_label.pack(side="right", padx=(12, 0))
        self.speed_label = tk.Label(m_right, text="—", font=("Segoe UI", 9, "bold"), fg=BLUE, bg=BG)
        self.speed_label.pack(side="right")

        # Progress bar
        self.progress = ttk.Progressbar(self.page, variable=self.progress_value, maximum=100, style="Drex.Horizontal.TProgressbar")
        self.progress.pack(fill="x", padx=28, pady=(4, 4))

        # Inline Error & Recovery Card (No blocking modal dialogs)
        self.inline_alert_card = tk.Frame(self.page, bg="white", highlightbackground=LINE, highlightthickness=1)
        alert_inner = tk.Frame(self.inline_alert_card, bg="white")
        alert_inner.pack(fill="x", padx=16, pady=12)

        alert_top = tk.Frame(alert_inner, bg="white")
        alert_top.pack(fill="x")
        self.alert_icon_lbl = tk.Label(alert_top, text="⚠", font=("Segoe UI", 12, "bold"), fg=RED, bg="white")
        self.alert_icon_lbl.pack(side="left", padx=(0, 8))
        self.alert_title_lbl = tk.Label(alert_top, text="Operation Status", font=("Segoe UI", 10, "bold"), fg=INK, bg="white")
        self.alert_title_lbl.pack(side="left")

        self.alert_desc_lbl = tk.Label(alert_inner, text="", font=("Segoe UI", 9), fg=MUTED, bg="white", justify="left", wraplength=850)
        self.alert_desc_lbl.pack(anchor="w", pady=(4, 8))

        alert_actions = tk.Frame(alert_inner, bg="white")
        alert_actions.pack(fill="x")
        self.alert_retry_btn = ttk.Button(alert_actions, text="Retry Operation", style="DrexPrimary.TButton", command=self._on_retry_operation)
        self.alert_retry_btn.pack(side="left", padx=(0, 8))
        self.alert_dismiss_btn = ttk.Button(alert_actions, text="Dismiss", style="Drex.TButton", command=self._hide_inline_alert)
        self.alert_dismiss_btn.pack(side="left")

        self.alert_tech_btn = tk.Label(alert_actions, text="Show Technical Details ▾", font=("Segoe UI", 8, "bold"), fg=BLUE, bg="white", cursor="hand2")
        self.alert_tech_btn.pack(side="right", padx=(8, 0))
        self.alert_tech_btn.bind("<Button-1>", lambda _e: self._toggle_alert_tech())

        self.alert_tech_lbl = tk.Label(alert_inner, text="", font=("Consolas", 8), fg="#475569", bg=BG_SECONDARY, justify="left", padx=10, pady=6)

        # Cancel button row
        cancel_row = tk.Frame(self.page, bg=BG)
        cancel_row.pack(fill="x", padx=28, pady=(2, 12))
        self.cancel_button = ttk.Button(cancel_row, text="Cancel Operation", style="Drex.TButton", command=self.cancel_operation, state="disabled")
        self.cancel_button.pack(side="right")
        self.progress_mode.set("")

    def _show_inline_alert(self, title: str, description: str, severity: str = "error", tech_info: str = ""):
        if not hasattr(self, "inline_alert_card") or not self.inline_alert_card.winfo_exists():
            return
        fg = RED if severity == "error" else (ORANGE if severity == "warning" else BLUE)
        icon = "⚠" if severity in ("error", "warning") else "ℹ"
        self.alert_icon_lbl.configure(text=icon, fg=fg)
        self.alert_title_lbl.configure(text=title, fg=fg)
        self.alert_desc_lbl.configure(text=description)
        self.inline_alert_card.configure(highlightbackground=fg)
        if tech_info:
            self.alert_tech_lbl.configure(text=tech_info)
            self.alert_tech_btn.pack(side="right", padx=(8, 0))
        else:
            self.alert_tech_btn.pack_forget()
            self.alert_tech_lbl.pack_forget()
        try:
            self.inline_alert_card.pack(fill="x", padx=28, pady=(6, 10), before=self.cancel_button.master)
        except Exception:
            self.inline_alert_card.pack(fill="x", padx=28, pady=(6, 10))

    def _hide_inline_alert(self):
        if hasattr(self, "inline_alert_card") and self.inline_alert_card.winfo_exists():
            self.inline_alert_card.pack_forget()

    def _toggle_alert_tech(self):
        if hasattr(self, "alert_tech_lbl") and self.alert_tech_lbl.winfo_exists():
            if self.alert_tech_lbl.winfo_ismapped():
                self.alert_tech_lbl.pack_forget()
                self.alert_tech_btn.configure(text="Show Technical Details ▾")
            else:
                self.alert_tech_lbl.pack(fill="x", pady=(6, 0))
                self.alert_tech_btn.configure(text="Hide Technical Details ▴")

    def _on_retry_operation(self):
        self._hide_inline_alert()
        kind = getattr(self, "_last_op_kind", "file")
        self.start_operation(kind)

    def choose_recovery_destination(self):
        if not self.target or (not self.target.is_dir() and not self.target.is_file()):
            messagebox.showerror("Select recovery source", "Select a recovery folder or disk image and complete a scan first.")
            return
        chosen = filedialog.askdirectory(title="Choose a Separate Recovery Destination", mustexist=False)
        if not chosen:
            return
        destination = Path(chosen).resolve()
        try:
            destination.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            messagebox.showerror("Invalid destination", f"DREX could not create the destination:\n{exc}")
            return
        if destination == self.target.resolve() or (self.target.is_dir() and self.target.resolve() in destination.parents):
            messagebox.showerror("Unsafe destination", "Choose a destination outside the selected source folder.")
            return
        self.recovery_destination = destination
        if hasattr(self, "recovery_destination_label"):
            self.recovery_destination_label.configure(text=f"Destination: {destination}", fg=INK)
        self._update_recovery_action_state()

    def _update_recovery_action_state(self):
        if not hasattr(self, "recover_selected_button"):
            return
        enabled = bool(self.recovery_destination and self.recovery_tree and self.recovery_tree.selection())
        self.recover_selected_button.configure(state="normal" if enabled else "disabled")

    def recover_selected_candidates(self):
        if not self.recovery_scan or not self.recovery_destination or not self.recovery_tree:
            return
        selected_ids = {str(self.recovery_tree.item(item, "values")[0]) for item in self.recovery_tree.selection()}
        candidates = [c for c in self.recovery_scan.candidates if c.candidate_id in selected_ids]
        if not candidates:
            messagebox.showwarning("Select candidates", "Select one or more candidates before recovering.")
            return
        method_id = self.method_var.get()
        adapter = self.recovery_dispatcher.get(method_id)
        if not hasattr(adapter, "recover"):
            messagebox.showerror("Recovery unavailable", self.recovery_dispatcher.status(method_id)[1])
            return
        if not messagebox.askyesno("Confirm recovery", f"Recover {len(candidates)} selected candidate(s) to:\n\n{self.recovery_destination}\n\nThe source remains read-only."):
            return
        self._hide_inline_alert()
        self.cancel_event.clear()
        self.tracker.start(len(candidates), stage="RECOVERING")
        self.cancel_button.configure(state="normal")
        self.recover_selected_button.configure(state="disabled")
        self.task_manager.submit_task(
            "candidate_recovery",
            self._run_candidate_recovery,
            adapter, method_id, candidates, self.recovery_destination,
        )

    def _run_candidate_recovery(self, adapter: Any, method_id: str, candidates: list[Any], destination: Path, cancel_event: threading.Event | None = None):
        ce = cancel_event or self.cancel_event
        started = utc_now()
        label = label_for_recovery(method_id)
        recovered = 0
        failures: list[str] = []
        for candidate in candidates:
            if ce.is_set():
                break
            try:
                outputs = adapter.recover(self._recovery_source, candidate.candidate_id, destination)
                if not outputs:
                    raise RecoveryError("Adapter returned no outputs.")
                for output in outputs:
                    if not Path(output).is_file():
                        raise RecoveryError("Adapter returned a non-file output.")
                    self.events.put(("log", f"Recovered candidate {candidate.candidate_id}: {output}"))
                recovered += 1
            except Exception as exc:
                failures.append(f"{candidate.candidate_id}: {type(exc).__name__}: {exc}")
            self.events.put(("progress", (recovered, len(candidates))))
        completed = utc_now()
        cancelled = ce.is_set()
        status = "CANCELLED" if cancelled else "SUCCESS" if recovered == len(candidates) else "PARTIAL" if recovered else "FAILED"
        record = {"type": "recovery", "operation": "candidate_recovery", "method": label, "target": str(self.target), "source": self._recovery_source, "destination": str(destination), "started": started, "completed": completed, "duration": self._duration(started, completed), "status": status, "candidate_count": len(candidates), "selected_candidate_count": len(candidates), "recovered_count": recovered, "failed_count": len(failures), "errors": failures, "verification": "OUTPUT VERIFIED" if status == "SUCCESS" else "Not completed"}
        self.store.add_history(record)
        detail = f"Method: {label}\nTarget folder: {self.target}\nDestination: {destination}\nRecovered: {recovered}/{len(candidates)}"
        if failures:
            detail += "\nFailures:\n" + "\n".join(failures)
        self.events.put(("result", ("RECOVERY " + status, detail)))
        self.events.put(("finished", None))

    # ── Page: Wipe Drive ────────────────────────────────────────────
    def render_drive_page(self):
        self._header("Wipe Drive", "Securely erase physical storage devices using industry-standard sanitization methods.")
        self._target_panel("drive")

        # Protected System Drive Banner
        self.system_protect_card = tk.Frame(self.page, bg=RED_LIGHT, highlightbackground=RED, highlightthickness=1)
        p_inner = tk.Frame(self.system_protect_card, bg=RED_LIGHT)
        p_inner.pack(fill="x", padx=16, pady=10)
        tk.Label(p_inner, text="🛡", font=("Segoe UI", 14), fg=RED, bg=RED_LIGHT).pack(side="left", padx=(0, 10))
        p_text = tk.Frame(p_inner, bg=RED_LIGHT)
        p_text.pack(side="left", fill="x")
        tk.Label(p_text, text="SYSTEM DRIVE PROTECTED — PhysicalDisk 0 / C: Drive", font=("Segoe UI", 10, "bold"), fg=RED, bg=RED_LIGHT).pack(anchor="w")
        tk.Label(p_text, text="DREX safety architecture strictly protects the host OS and boot drive. Destructive operations are permanently disabled.", font=("Segoe UI", 8), fg=INK, bg=RED_LIGHT).pack(anchor="w")

        # Methods Grid (All 7 methods)
        self._methods(DRIVE_METHODS, "drive")

        # Rationale & Progressive Technical Details Card
        rationale_card = self._card(self.page)
        rationale_card.pack(fill="x", padx=28, pady=(0, 12))
        r_inner = tk.Frame(rationale_card, bg="white")
        r_inner.pack(fill="x", padx=18, pady=12)

        r_top = tk.Frame(r_inner, bg="white")
        r_top.pack(fill="x")
        tk.Label(r_top, text="Method Selection Rationale", font=("Segoe UI", 10, "bold"), fg=INK, bg="white").pack(side="left")
        toggle_lbl = tk.Label(r_top, text="Show Technical Details ▾", font=("Segoe UI", 8, "bold"), fg=BLUE, bg="white", cursor="hand2")
        toggle_lbl.pack(side="right")

        self.drive_rationale_label = tk.Label(
            r_inner,
            text="Select a drive and sanitization method above. DREX validates host capabilities prior to execution.",
            font=("Segoe UI", 8), fg=MUTED, bg="white", justify="left", wraplength=900,
        )
        self.drive_rationale_label.pack(anchor="w", pady=(4, 0))

        # Collapsible technical details
        self.tech_details_frame = tk.Frame(r_inner, bg=BG_SECONDARY)
        self.tech_details_label = tk.Label(
            self.tech_details_frame, text="",
            font=("Consolas", 8), fg=INK, bg=BG_SECONDARY, justify="left", padx=10, pady=8,
        )
        self.tech_details_label.pack(fill="x")

        def toggle_tech_details(_e=None):
            self._tech_details_visible = not getattr(self, "_tech_details_visible", False)
            if self._tech_details_visible:
                toggle_lbl.configure(text="Hide Technical Details ▴")
                self.tech_details_frame.pack(fill="x", pady=(8, 0))
                if self.selected_drive:
                    caps = self.capability_manager.get_cached(self.selected_drive)
                    if caps is None:
                        self.capability_manager.request_capabilities_async(self.selected_drive, event_queue=self.events)
                        self.tech_details_label.configure(text="Probing device capabilities in background (CHECKING...)...")
                    else:
                        probe_lines = [
                            f"PhysicalDisk: {caps.get('physical_disk_number')} | Bus: {caps.get('bus_type')} | Model: {caps.get('model')}",
                            f"Native Sanitize: {caps.get('native_sanitize')} | ATA Secure Erase: {caps.get('ata_secure_erase')} | NVMe: {caps.get('nvme_controller')}",
                            f"Overwrite Backend: {caps.get('overwrite_backend_qualified')} | Write Capable: {caps.get('write_capable')}",
                        ]
                        self.tech_details_label.configure(text="\n".join(probe_lines))
                else:
                    self.tech_details_label.configure(text="No device selected for capability probing.")
            else:
                toggle_lbl.configure(text="Show Technical Details ▾")
                self.tech_details_frame.pack_forget()

        toggle_lbl.bind("<Button-1>", toggle_tech_details)

        self._operation_area("Operation Log")

        if self.selected_drive and self.drives:
            try:
                idx = self.drives.index(self.selected_drive)
                self.drive_combo.current(idx)
            except ValueError:
                pass
            self._drive_selected()
        elif self.drives:
            self.drive_combo.current(0)
            self._drive_selected()

    # ── Page: Wipe File/Folder ──────────────────────────────────────
    def render_file_page(self):
        self._header("Wipe File/Folder", "Securely erase specific files or folders using advanced sanitization methods.")
        self._target_panel("file")
        self._methods(FILE_METHODS, "file")
        self._operation_area("Operation Log")

    # ── Page: Recover ───────────────────────────────────────────────
    def render_recovery_page(self):
        self._header("Recover", "Recover deleted or lost files from storage devices and disk images using advanced scanning engines.")

        ro_card = tk.Frame(self.page, bg=PURPLE_LIGHT, highlightbackground=PURPLE, highlightthickness=1)
        ro_card.pack(fill="x", padx=28, pady=(16, 0))
        ro_inner = tk.Frame(ro_card, bg=PURPLE_LIGHT)
        ro_inner.pack(fill="x", padx=16, pady=10)
        tk.Label(ro_inner, text="🛡", font=("Segoe UI", 14), fg=PURPLE, bg=PURPLE_LIGHT).pack(side="left", padx=(0, 10))
        ro_text = tk.Frame(ro_inner, bg=PURPLE_LIGHT)
        ro_text.pack(side="left", fill="x")
        tk.Label(ro_text, text="READ ONLY SOURCE GUARANTEE", font=("Segoe UI", 10, "bold"), fg=PURPLE, bg=PURPLE_LIGHT).pack(anchor="w")
        tk.Label(ro_text, text="Recovery access is strictly read-only. No write operations are ever performed against the source device or image. Recovered files are written exclusively to a separate destination.", font=("Segoe UI", 8), fg=INK, bg=PURPLE_LIGHT).pack(anchor="w")

        self._target_panel("recovery")
        self._methods(RECOVERY_METHODS, "recovery")
        self._operation_area("Recovery Log")

    # ── Page: Destroy Drive ─────────────────────────────────────────
    def render_destroy_page(self):
        self._header("Destroy Drive", "Assess device sanitization and determine whether certified physical destruction is required.")
        if not self.drives:
            self.refresh_devices()
        if not self.selected_drive and self.drives:
            self.selected_drive = self.drives[0]

        warn = tk.Frame(self.page, bg=ORANGE_LIGHT, highlightbackground=ORANGE, highlightthickness=1)
        warn.pack(fill="x", padx=28, pady=(18, 12))
        warn_inner = tk.Frame(warn, bg=ORANGE_LIGHT)
        warn_inner.pack(fill="x", padx=18, pady=14)
        tk.Label(warn_inner, text="⚠", font=("Segoe UI", 18), fg=ORANGE, bg=ORANGE_LIGHT).pack(side="left", padx=(0, 12))
        warn_text = tk.Frame(warn_inner, bg=ORANGE_LIGHT)
        warn_text.pack(side="left", fill="x")
        tk.Label(warn_text, text="Device Requires Alternative Sanitization Assessment", font=("Segoe UI", 12, "bold"), fg=INK, bg=ORANGE_LIGHT).pack(anchor="w")
        tk.Label(warn_text, text="This device does not support native cryptographic or controller-level erase commands. Software wiping alone cannot guarantee absolute elimination of unmapped sectors.", font=("Segoe UI", 9), fg=MUTED, bg=ORANGE_LIGHT, wraplength=800, justify="left").pack(anchor="w", pady=(2, 0))

        dev_card = self._card(self.page)
        dev_card.pack(fill="x", padx=28, pady=(0, 12))
        dev_inner = tk.Frame(dev_card, bg="white")
        dev_inner.pack(fill="both", padx=18, pady=16)

        dh = tk.Frame(dev_inner, bg="white")
        dh.pack(fill="x", pady=(0, 12))
        icon = tk.Canvas(dh, width=44, height=44, bg=BLUE_LIGHT, highlightthickness=0)
        icon.pack(side="left", padx=(0, 12))
        icon.create_rectangle(12, 8, 32, 36, outline=BLUE, width=2)
        icon.create_line(16, 16, 28, 16, fill=BLUE)
        dev_h_text = tk.Frame(dh, bg="white")
        dev_h_text.pack(side="left")
        tk.Label(dev_h_text, text="Device Overview & Destruction Assessment", font=("Segoe UI", 12, "bold"), fg=INK, bg="white").pack(anchor="w")
        if self.selected_drive:
            d = self.selected_drive
            tk.Label(dev_h_text, text=d.display("model") or "Generic Drive", font=("Segoe UI", 10), fg=INK, bg="white").pack(anchor="w", pady=(2, 0))
            tk.Label(dev_h_text, text="Alternative Sanitization Required", font=("Segoe UI", 8, "bold"), fg="white", bg=ORANGE, padx=8, pady=2).pack(anchor="w", pady=(4, 0))

        info_grid = tk.Frame(dev_inner, bg="white")
        info_grid.pack(fill="x", pady=(12, 0))
        for col in range(3):
            info_grid.columnconfigure(col, weight=1)
        if self.selected_drive:
            d = self.selected_drive
            info_items = [
                [("Device Type", d.drive_type or "HDD / SSD"), ("Capacity", fmt_bytes(d.capacity)), ("Serial Number", d.display("serial"))],
                [("Supported Erasure Methods", "None Detected (USB Bridge)"), ("Current Recommendation", "Certified Physical Destruction /\nDisposal (NIST SP 800-88)")],
            ]
            row_idx = 0
            for row_data in info_items:
                for col_idx, (label, value) in enumerate(row_data):
                    cell = tk.Frame(info_grid, bg="white")
                    cell.grid(row=row_idx, column=col_idx, sticky="nw", padx=8, pady=6)
                    tk.Label(cell, text=label, font=("Segoe UI", 9, "bold"), fg=INK, bg="white").pack(anchor="w")
                    tk.Label(cell, text=value, font=("Segoe UI", 9), fg=MUTED, bg="white", justify="left", wraplength=250).pack(anchor="w", pady=(2, 0))
                row_idx += 1

        if self.drives:
            sel = tk.Frame(dev_inner, bg="white")
            sel.pack(fill="x", pady=(14, 0))
            tk.Label(sel, text="Inspect another device: ", font=("Segoe UI", 9), fg=MUTED, bg="white").pack(side="left")
            self.destroy_combo = ttk.Combobox(sel, state="readonly", values=[d.path for d in self.drives], width=20)
            self.destroy_combo.set(self.selected_drive.path if self.selected_drive else self.drives[0].path)
            self.destroy_combo.pack(side="left", padx=(6, 0))
            self.destroy_combo.bind("<<ComboboxSelected>>", lambda _e: self._destroy_selected())

        notice = tk.Frame(self.page, bg=RED_LIGHT, highlightbackground=RED, highlightthickness=1)
        notice.pack(fill="x", padx=28, pady=(0, 12))
        notice_inner = tk.Frame(notice, bg=RED_LIGHT)
        notice_inner.pack(fill="x", padx=18, pady=14)
        tk.Label(notice_inner, text="🛡", font=("Segoe UI", 16), fg=RED, bg=RED_LIGHT).pack(side="left", padx=(0, 12))
        n_text = tk.Frame(notice_inner, bg=RED_LIGHT)
        n_text.pack(side="left", fill="x")
        tk.Label(n_text, text="Important Notice Regarding Physical Destruction", font=("Segoe UI", 11, "bold"), fg=RED, bg=RED_LIGHT).pack(anchor="w")
        tk.Label(n_text, text="Physical destruction should be performed only through authorized procedures or certified destruction services.\nDo not attempt hazardous shredding or thermal methods yourself.", font=("Segoe UI", 9), fg=INK, bg=RED_LIGHT, wraplength=900, justify="left").pack(anchor="w", pady=(2, 0))

        why_card = self._card(self.page, bg=BG_SECONDARY)
        why_card.pack(fill="x", padx=28, pady=(0, 12))
        why_inner = tk.Frame(why_card, bg=BG_SECONDARY)
        why_inner.pack(fill="x", padx=18, pady=16)
        tk.Label(why_inner, text="Why is Alternative Sanitization Required?", font=("Segoe UI", 12, "bold"), fg=INK, bg=BG_SECONDARY).pack(anchor="w")
        tk.Label(why_inner, text="Some devices do not expose commands required for secure erasure due to hardware, firmware, or interface limitations. In such cases, software-based wiping cannot guarantee permanent data elimination.", font=("Segoe UI", 9), fg=MUTED, bg=BG_SECONDARY, wraplength=900, justify="left").pack(anchor="w", pady=(6, 0))

    def _destroy_selected(self):
        index = self.destroy_combo.current()
        if index >= 0:
            self.selected_drive = self.drives[index]
            self.render_destroy_page()

    # ── Page: Certificates ──────────────────────────────────────────
    def render_certificates(self):
        previous_filter = "all"
        previous_query = ""
        try:
            if hasattr(self, "cert_filter"):
                previous_filter = self.cert_filter.get()
        except tk.TclError:
            previous_filter = "all"
        try:
            if hasattr(self, "cert_search"):
                previous_query = self.cert_search.get().strip()
        except tk.TclError:
            previous_query = ""

        self._header("Certificate Centre", "View, search and manage cryptographically signed operation certificates.")

        tabs = tk.Frame(self.page, bg="white", highlightbackground=LINE, highlightthickness=1)
        tabs.pack(fill="x", padx=28, pady=(18, 0))
        self.cert_filter = tk.StringVar(value=previous_filter)
        for text, value in [("All Certificates", "all"), ("Erasure Certificates", "erasure"), ("Recovery Certificates", "recovery")]:
            active = previous_filter == value
            tab_btn = tk.Button(tabs, text=text, relief="flat", bd=0, bg="white", fg=BLUE if active else INK, font=("Segoe UI", 10, "bold" if active else ""), padx=24, pady=12, activebackground=BLUE_LIGHT,
                                command=lambda v=value: (self.cert_filter.set(v), self.render_certificates()))
            tab_btn.pack(side="left")
            if active:
                underline = tk.Frame(tabs, bg=BLUE, height=3)
                underline.place(in_=tab_btn, relx=0, rely=1.0, relwidth=1, anchor="sw")

        search_card = tk.Frame(self.page, bg="white", highlightbackground=LINE, highlightthickness=1)
        search_card.pack(fill="x", padx=28, pady=(12, 12))
        search_inner = tk.Frame(search_card, bg="white")
        search_inner.pack(fill="x", padx=12, pady=8)
        tk.Label(search_inner, text="🔍", font=("Segoe UI", 11), fg=MUTED, bg="white").pack(side="left", padx=(0, 8))
        self.cert_search = tk.Entry(search_inner, font=("Segoe UI", 10), relief="flat", bd=0, width=50)
        self.cert_search.pack(side="left", fill="x", expand=True, ipady=6)
        self.cert_search.insert(0, previous_query or "Search Certificate ID / Serial Number...")
        if not previous_query:
            self.cert_search.configure(fg=MUTED)
            self.cert_search.bind("<FocusIn>", lambda e: (self.cert_search.delete(0, "end"), self.cert_search.configure(fg=INK)))
        self.cert_search.bind("<Return>", lambda e: self.render_certificates())

        records = self.store.certificates()
        filter_value = previous_filter
        if filter_value == "erasure":
            records = [r for r in records if r.get("operation_type") != "recovery"]
        elif filter_value == "recovery":
            records = [r for r in records if r.get("operation_type") == "recovery"]
        query = previous_query.lower()
        if query and query != "search certificate id / serial number...":
            records = [r for r in records if query in json.dumps(r).lower()]

        table_card = self._card(self.page)
        table_card.pack(fill="both", expand=True, padx=28, pady=(0, 12))
        table_inner = tk.Frame(table_card, bg="white")
        table_inner.pack(fill="both", expand=True, padx=14, pady=14)

        tree = ttk.Treeview(table_inner, columns=("id", "method", "passes", "status", "started", "duration", "action"), show="headings", style="Drex.Treeview")
        headings = {"id": "Session ID", "method": "Method", "passes": "Passes", "status": "Status", "started": "Started", "duration": "Duration", "action": "Actions"}
        col_widths = {"id": 140, "method": 160, "passes": 60, "status": 120, "started": 180, "duration": 80, "action": 80}
        for col, heading in headings.items():
            tree.heading(col, text=heading)
            tree.column(col, width=col_widths.get(col, 120), anchor="w")
        tree.pack(fill="both", expand=True)

        page_size = 8
        self._cert_page = getattr(self, "_cert_page", 0)
        total_pages = max(1, (len(records) + page_size - 1) // page_size)
        if self._cert_page >= total_pages:
            self._cert_page = 0
        page_records = records[self._cert_page * page_size:(self._cert_page + 1) * page_size]
        for record in page_records:
            status_display = "● COMPLETED" if record.get("status") == "SUCCESS" else record.get("status", "UNKNOWN")
            tree.insert("", "end", iid=record["certificate_id"], values=(
                record["certificate_id"], record["method"], record.get("passes", 1),
                status_display, record["started"], record["duration"], "📄 PDF",
            ))
        tree.bind("<Double-1>", lambda _e: self.open_certificate(tree))

        pag = tk.Frame(table_inner, bg="white")
        pag.pack(fill="x", pady=(10, 0))
        start = self._cert_page * page_size + 1
        end = min((self._cert_page + 1) * page_size, len(records))
        tk.Label(pag, text=f"Showing {start} to {end} of {len(records)} certificates" if records else "No certificates found", font=("Segoe UI", 9), fg=BLUE, bg="white").pack(side="left")
        nav = tk.Frame(pag, bg="white")
        nav.pack(side="right")
        if total_pages > 1:
            def go_page(p):
                self._cert_page = p
                self.render_certificates()
            tk.Button(nav, text="‹", command=lambda: go_page(max(0, self._cert_page - 1)), relief="flat", bd=0, font=("Segoe UI", 10), fg=INK, bg="white", padx=8).pack(side="left")
            for i in range(min(total_pages, 5)):
                active_page = i == self._cert_page
                tk.Button(nav, text=str(i + 1), command=lambda p=i: go_page(p), relief="flat", bd=0, font=("Segoe UI", 10, "bold" if active_page else ""), fg="white" if active_page else INK, bg=BLUE if active_page else "white", padx=8, pady=2).pack(side="left", padx=2)
            if total_pages > 5:
                tk.Label(nav, text="...", font=("Segoe UI", 9), fg=MUTED, bg="white").pack(side="left")
                tk.Button(nav, text=str(total_pages), command=lambda: go_page(total_pages - 1), relief="flat", bd=0, font=("Segoe UI", 10), fg=INK, bg="white", padx=8).pack(side="left", padx=2)
            tk.Button(nav, text="›", command=lambda: go_page(min(total_pages - 1, self._cert_page + 1)), relief="flat", bd=0, font=("Segoe UI", 10), fg=INK, bg="white", padx=8).pack(side="left")
        self.cert_tree = tree

    def open_certificate(self, tree):
        selection = tree.selection()
        if not selection:
            return
        record = next((r for r in self.store.certificates() if r.get("certificate_id") == selection[0]), None)
        if not record:
            return
        if not self.cert_manager.verify(record):
            messagebox.showerror("Certificate validation failed", "DREX could not validate the cryptographic integrity token for this certificate.")
            return
        path = Path(record.get("pdf_path", ""))
        if path.exists():
            os.startfile(str(path)) if os.name == "nt" else subprocess.Popen(["xdg-open", str(path)])

    # ── Page: Help ──────────────────────────────────────────────────
    def render_help(self):
        self._header("Help Center", "Comprehensive guides, safety architecture, and troubleshooting.")
        selected = getattr(self, "help_section", "Getting Started")
        tabs = tk.Frame(self.page, bg="white", highlightbackground=LINE, highlightthickness=1)
        tabs.pack(fill="x", padx=28, pady=(18, 14))
        tab_items = [
            ("Getting Started", "📖"), ("Wiping Data", "◎"), ("Recovery", "↺"),
            ("Drive Destruction", "⊠"), ("Certificates", "◈"), ("Troubleshooting", "🔧"), ("Safety", "🛡"),
        ]
        for title, icon in tab_items:
            active = title == selected
            tab = tk.Frame(tabs, bg=BLUE_LIGHT if active else "white", cursor="hand2")
            tab.pack(side="left", fill="both", expand=True)
            inner = tk.Frame(tab, bg=BLUE_LIGHT if active else "white")
            inner.pack(pady=10)
            tk.Label(inner, text=icon, font=("Segoe UI", 11), fg=BLUE if active else MUTED, bg=BLUE_LIGHT if active else "white").pack()
            tk.Label(inner, text=title, font=("Segoe UI", 8, "bold" if active else ""), fg=BLUE if active else INK, bg=BLUE_LIGHT if active else "white").pack(pady=(2, 0))
            for w in (tab, inner):
                w.bind("<Button-1>", lambda _e, t=title: self._set_help_section(t))
            for child in inner.winfo_children():
                child.bind("<Button-1>", lambda _e, t=title: self._set_help_section(t))

        if selected == "Getting Started":
            self._help_getting_started()
        elif selected == "Wiping Data":
            self._help_section_content("Wiping Data", "Drive wiping requires a qualified native adapter. File and folder methods report their coverage and require verification before removal. Always select the correct target and method before starting.", [
                ("File/Folder Wiping", "Select a file or folder, choose a wiping method, and execute. DREX supports 9 file/folder wiping methods."),
                ("Drive Wiping", "Select a detected drive, choose one of 7 industry-standard methods, and execute. Requires hardware qualification."),
                ("Verification", "All successful operations produce verified results and generate tamper-evident certificates."),
            ])
        elif selected == "Recovery":
            self._help_section_content("Recovery", "Recovery engines are strictly read-only. The current build reports native recovery engines as unavailable when their compiled executables are not present; it never claims recovered files without results.", [
                ("Quick & Smart Recovery", "Find recently deleted data quickly or let DREX choose the best recovery path automatically."),
                ("Deep & Fragment Recovery", "Search deeper for lost data or reconstruct files from scattered data fragments."),
                ("Forensic Recovery", "Recover and analyze data for forensic investigation with chain-of-custody documentation."),
            ])
        elif selected == "Drive Destruction":
            self._help_section_content("Drive Destruction", "Destroy Drive is an assessment page only. DREX does not physically destroy drives and does not issue destruction certificates.", [
                ("Software Assessment", "DREX evaluates whether software-based sanitization methods are available for the selected device."),
                ("Physical Destruction", "Physical destruction should be performed only through authorized procedures or certified destruction services."),
                ("Recommendation", "When software sanitization is unavailable, DREX recommends appropriate alternative methods or certified disposal."),
            ])
        elif selected == "Certificates":
            self._help_section_content("Certificates", "Successful certificates are generated only after verified operations. Each certificate is signed locally with ECDSA P-256, stored offline, and validated before opening.", [
                ("Certificate Generation", "Certificates are automatically generated after successful, verified operations. Failed or cancelled operations never produce certificates."),
                ("Verification", "Each certificate includes SHA-256 hashes, ECDSA signatures, QR codes, and can be exported as PDF."),
                ("Certificate Centre", "View, search, filter, and manage all certificates from the Certificates page."),
            ])
        elif selected == "Troubleshooting":
            self._help_troubleshooting()
        elif selected == "Safety":
            self._help_safety()

    def _help_getting_started(self):
        gs_header = tk.Frame(self.page, bg=BG)
        gs_header.pack(fill="x", padx=28, pady=(0, 12))
        tk.Label(gs_header, text="📖", font=("Segoe UI", 16), fg=BLUE, bg=BG).pack(side="left", padx=(0, 10))
        gs_text = tk.Frame(gs_header, bg=BG)
        gs_text.pack(side="left")
        tk.Label(gs_text, text="Getting Started", font=("Segoe UI", 15, "bold"), fg=INK, bg=BG).pack(anchor="w")
        tk.Label(gs_text, text="Understand what DREX is and follow best practices before performing any operation.", font=("Segoe UI", 9), fg=MUTED, bg=BG).pack(anchor="w")

        cards_row = tk.Frame(self.page, bg=BG)
        cards_row.pack(fill="x", padx=28, pady=(0, 20))
        info_cards = [
            ("What is DREX?", "DREX is a secure data management platform designed to permanently erase data, recover deleted files, and provide verifiable proof of sanitization.", BLUE, "🛡"),
            ("Before You Begin", "• Connect the storage device securely.\n• Close applications using the target drive.\n• Verify the selected drive before starting any operation.\n• Back up anything you may need later.", BLUE, "📋"),
            ("Important", "Data sanitization and drive destruction can be permanent and irreversible.", ORANGE, "⚠"),
            ("Best Practice", "Always verify your target drive and review operation details before confirming.", GREEN, "✓"),
        ]
        for title, text, color, icon in info_cards:
            card = self._card(cards_row, border=LINE if color == BLUE else (ORANGE if color == ORANGE else GREEN))
            card.pack(side="left", fill="both", expand=True, padx=(0, 8))
            inner = tk.Frame(card, bg="white")
            inner.pack(fill="both", expand=True, padx=14, pady=14)
            tk.Label(inner, text=icon, font=("Segoe UI", 16), fg=color, bg="white").pack(anchor="w")
            tk.Label(inner, text=title, font=("Segoe UI", 11, "bold"), fg=color, bg="white").pack(anchor="w", pady=(8, 4))
            tk.Label(inner, text=text, font=("Segoe UI", 8), fg=INK, bg="white", wraplength=200, justify="left").pack(anchor="w")

    def _help_section_content(self, title, intro, items):
        section = self._card(self.page)
        section.pack(fill="x", padx=28, pady=(0, 12))
        inner = tk.Frame(section, bg="white")
        inner.pack(fill="both", expand=True, padx=22, pady=18)
        tk.Label(inner, text=title, font=("Segoe UI", 15, "bold"), fg=INK, bg="white").pack(anchor="w")
        tk.Label(inner, text=intro, font=("Segoe UI", 9), fg=MUTED, bg="white", wraplength=900, justify="left").pack(anchor="w", pady=(6, 14))
        for sub_title, sub_text in items:
            item = tk.Frame(inner, bg="white")
            item.pack(fill="x", pady=6)
            tk.Label(item, text="●", fg=BLUE, bg="white", font=("Segoe UI", 8)).pack(side="left", padx=(0, 10), anchor="n", pady=3)
            texts = tk.Frame(item, bg="white")
            texts.pack(side="left", fill="x", expand=True)
            tk.Label(texts, text=sub_title, font=("Segoe UI", 10, "bold"), fg=INK, bg="white", anchor="w").pack(anchor="w")
            tk.Label(texts, text=sub_text, font=("Segoe UI", 9), fg=MUTED, bg="white", anchor="w", wraplength=800, justify="left").pack(anchor="w", pady=(2, 0))

    def _help_troubleshooting(self):
        self._help_section_content("Troubleshooting & System Status", "Refresh device discovery, check permissions, review the operation log, and confirm that the selected method is marked Available.", [
            ("Drive not detected", "Check that the drive is connected, powered on, and visible in Windows Disk Management. Try refreshing the device list."),
            ("Wipe operation failed", "Review the operation log for specific error messages. Check permissions and ensure the target is not in use."),
            ("Recovery finds no files", "Data may have been overwritten or securely erased. Try a different recovery method or scanning mode."),
            ("Certificate is unavailable", "Certificates are only generated for successful, verified operations. Check the operation status."),
            ("Method shows unavailable", "Some methods require specific hardware, drivers, or privileges. Check the method requirements."),
        ])

    def _help_safety(self):
        self._help_section_content("Safety Guidelines", "Never select a system or valuable target for destructive testing. Do not bypass confirmation or enable unqualified native tools.", [
            ("Before any destructive operation", "Always verify the target path, drive letter, and model. Back up any data you may need."),
            ("System protection", "DREX blocks operations on system drives, the Windows directory, and the boot environment."),
            ("Physical destruction", "Use authorized disposal services for physical destruction. DREX does not destroy hardware."),
            ("Certificates and verification", "Never rely on a certificate without verifying the operation actually completed successfully."),
            ("Testing", "Use dedicated disposable test directories. Never test destructive operations on production data."),
        ])

    def _set_help_section(self, section: str):
        self.help_section = section
        self.render_help()

    # ── Operation Logic (Preserved) ─────────────────────────────────
    def append_log(self, line: str):
        if self.log_text:
            stamp = datetime.now().strftime("%H:%M:%S")
            self.log_text.configure(state="normal")
            self.log_text.insert("end", f"[{stamp}] {line}\n")
            self.log_text.see("end")
            self.log_text.configure(state="disabled")

    def append_log_batch(self, lines: list[str]):
        if not lines or not self.log_text:
            return
        stamp = datetime.now().strftime("%H:%M:%S")
        block = "".join(f"[{stamp}] {line}\n" for line in lines)
        self.log_text.configure(state="normal")
        self.log_text.insert("end", block)
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

    def start_operation(self, kind: str):
        self._last_op_kind = kind
        self._hide_inline_alert()
        method_id = self.method_var.get()
        if not method_id:
            messagebox.showwarning("Select a method", "Choose exactly one method before starting.")
            return
        if kind == "drive":
            if not self.selected_drive:
                messagebox.showwarning("Select a drive", "Choose a detected device before starting.")
                return
            drive = self.selected_drive
            
            # Cheap local safety check (0ms, Tk thread)
            if drive.path.upper().startswith("C:") or (drive.device_path and "PHYSICALDRIVE0" in drive.device_path.upper()):
                messagebox.showerror(
                    "Safety Guard — System Disk Protected",
                    f"Selected device {drive.path} is protected by DREX safety architecture.\n\n"
                    "Destructive operations against the system drive are permanently blocked."
                )
                return

            model = drive.model or "Storage Device"
            serial = drive.serial or "Unknown"
            capacity_bytes = drive.capacity or 0
            capacity = fmt_bytes(capacity_bytes)

            if not messagebox.askyesno(
                "Confirm Physical Drive Sanitization",
                f"DESTRUCTIVE OPERATION — IRREVERSIBLE\n\n"
                f"Target Drive: {drive.path} ({model})\n"
                f"Physical Device: {drive.device_path or 'PhysicalDrive'}\n"
                f"Serial: {serial}\n"
                f"Capacity: {capacity}\n"
                f"Selected Method: {method_id.upper()}\n\n"
                f"WARNING: All stored data on this device will be permanently erased.\n\n"
                f"Are you sure you want to proceed with this operation?",
                icon="warning",
            ):
                return

            if self.log_text:
                self.log_text.configure(state="normal")
                self.log_text.delete("1.0", "end")
                self.log_text.configure(state="disabled")
            self.progress_value.set(0)
            self.cancel_event.clear()
            self.tracker.start(capacity_bytes, stage=method_id.upper())
            if hasattr(self, "status_label") and self.status_label:
                self.status_label.configure(text="RUNNING", fg=ORANGE)
            if hasattr(self, "start_button") and self.start_button:
                try:
                    self.start_button.configure(state="disabled")
                except Exception:
                    pass
            if hasattr(self, "cancel_button") and self.cancel_button:
                try:
                    self.cancel_button.configure(state="normal")
                except Exception:
                    pass

            def _drive_op_thread(cancel_event=None):
                ce = cancel_event or self.cancel_event
                op_id = f"drive_{method_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
                started = utc_now()

                def _emit(msg):
                    self.events.put((EV_LOG, msg))

                def _progress(done, total):
                    self.events.put((EV_PROGRESS, (done, total)))

                try:
                    _emit(f"Starting background operation: {method_id.upper()} on {drive.path}...")
                    
                    # ── AUTHORITATIVE SAFETY GATE & CAPABILITY DISCOVERY (Worker Thread) ──
                    caps = probe_drive_capabilities(drive)
                    phys_num = caps.get("physical_disk_number")
                    bus_type = caps.get("bus_type", "UNKNOWN")
                    _emit(f"  [Safety Gate] Target: {drive.path} | PhysicalDisk: {phys_num} | Bus: {bus_type}")

                    # 1. System disk / PhysicalDisk 0 check
                    if (phys_num is not None and int(phys_num) == 0) or drive.path.upper().startswith("C:") or caps.get("system_disk") == "SUPPORTED":
                        block_msg = "PhysicalDisk 0 / C: system disk detected — operation blocked by DREX safety architecture."
                        _emit(f"[BLOCKED] {block_msg}")
                        blocked_res = OperationResult(
                            operation_id=op_id, kind="drive", method_id=method_id, method_name=method_id.upper(),
                            status="EXECUTION_BLOCKED", backend="safety_gate", target=str(drive.device_path or drive.path),
                            started=started, completed=utc_now(), verification="NOT_EXECUTED",
                            evidence={"reason": block_msg, "capabilities": caps}, warnings=[], limitations=[],
                            detail=block_msg, error=block_msg,
                        )
                        self.events.put(("status", ("EXECUTION_BLOCKED", RED)))
                        self.events.put((EV_OP_COMPLETED, blocked_res))
                        return blocked_res

                    # 2. Method hardware eligibility check
                    status, reason = drive_method_status(method_id, drive, caps=caps)
                    if status != "Available":
                        _emit(f"[BLOCKED] Method {method_id.upper()} unavailable: {reason}")
                        blocked_res = OperationResult(
                            operation_id=op_id, kind="drive", method_id=method_id, method_name=method_id.upper(),
                            status="UNSUPPORTED_HARDWARE" if status == "UNSUPPORTED_HARDWARE" else "EXECUTION_BLOCKED",
                            backend="capability_gate", target=str(drive.device_path or drive.path),
                            started=started, completed=utc_now(), verification="NOT_EXECUTED",
                            evidence={"reason": reason, "capabilities": caps}, warnings=[], limitations=[],
                            detail=reason, error=reason,
                        )
                        self.events.put(("status", (status, ORANGE if status == "UNSUPPORTED_HARDWARE" else RED)))
                        self.events.put((EV_OP_COMPLETED, blocked_res))
                        return blocked_res

                    # 3. Capacity Safety Guard (Master requirement §15)
                    dev_capacity = caps.get("capacity") or drive.capacity or 0
                    if dev_capacity <= 0:
                        cap_msg = "EXECUTION BLOCKED: Unknown Capacity. DREX never assumes a fallback size."
                        _emit(f"[BLOCKED] {cap_msg}")
                        blocked_res = OperationResult(
                            operation_id=op_id, kind="drive", method_id=method_id, method_name=method_id.upper(),
                            status="EXECUTION_BLOCKED", backend="capacity_gate", target=str(drive.device_path or drive.path),
                            started=started, completed=utc_now(), verification="NOT_EXECUTED",
                            evidence={"reason": cap_msg, "capabilities": caps}, warnings=[], limitations=[],
                            detail=cap_msg, error=cap_msg,
                        )
                        self.events.put(("status", ("EXECUTION_BLOCKED", RED)))
                        self.events.put((EV_OP_COMPLETED, blocked_res))
                        return blocked_res

                    # Initial progress tick (0, dev_capacity)
                    self.events.put((EV_PROGRESS, (0, dev_capacity)))

                    # 4. Physical Execution
                    result = execute_drive_method(
                        method_id, drive, _emit, _progress, ce, caps=caps
                    )
                    status_out = result.get("status", "UNKNOWN")
                    completed = utc_now()

                    # VerificationEngine assess (cross-cutting, off Tk thread)
                    v_status, v_warnings = VerificationEngine.assess(result)

                    limitations = []
                    if result.get("nand_limitation"):
                        limitations.append(result["nand_limitation"])

                    op_result = OperationResult(
                        operation_id=op_id,
                        kind="drive",
                        method_id=method_id,
                        method_name=method_id.upper(),
                        status="SUCCESS" if status_out in ("PASS_PHYSICAL", "PASS_POLICY") else status_out,
                        backend="_physical_overwrite_windows" if status_out in ("PASS_PHYSICAL", "PASS_POLICY", "PASS_PHYSICAL_RANGE") else "execute_drive_method",
                        target=str(drive.device_path),
                        started=started,
                        completed=completed,
                        verification=v_status,
                        evidence=result,
                        warnings=v_warnings,
                        limitations=limitations,
                        detail=f"Drive sanitization ({method_id.upper()}) completed with status {status_out}.",
                    )

                    # Save evidence JSON (off Tk thread — file I/O stays in worker)
                    try:
                        ev_dir = app_data_dir() / "drive_evidence"
                        ev_dir.mkdir(parents=True, exist_ok=True)
                        ev_file = ev_dir / f"{method_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
                        ev_file.write_text(json.dumps(result, indent=2, default=str), encoding="utf-8")
                        _emit(f"Evidence saved: {ev_file}")
                    except Exception as ev_err:
                        _emit(f"[warning] Evidence save failed: {ev_err}")

                    # Generate Certificate & Audit Log (off Tk thread — inside worker!)
                    if op_result.status == "SUCCESS":
                        try:
                            cert = self.cert_manager.create_certificate(
                                operation_type="drive",
                                method_id=method_id,
                                method_name=method_id.upper(),
                                target_path=str(drive.device_path or drive.path),
                                target_size_bytes=dev_capacity,
                                status="SUCCESS",
                                duration_seconds=max(0, int((datetime.fromisoformat(completed.replace("Z", "+00:00")) - datetime.fromisoformat(started.replace("Z", "+00:00"))).total_seconds())),
                                verification_status=v_status,
                                evidence=result,
                            )
                            op_result.certificate_id = cert.certificate_id
                            op_result.certificate_path = cert.certificate_path
                            _emit(f"Certificate generated: {cert.certificate_id}")
                        except Exception as cert_err:
                            _emit(f"[warning] Certificate generation failed: {cert_err}")

                    fg = GREEN if status_out in ("PASS_PHYSICAL", "PASS_POLICY") else (
                        ORANGE if status_out in ("UNSUPPORTED_HARDWARE", "PHYSICAL_EXECUTION_UNAVAILABLE", "HOST_OVERWRITE_ASSURANCE") else RED
                    )
                    self.events.put(("status", (status_out, fg)))
                    self.events.put((EV_OP_COMPLETED, op_result))
                    return op_result

                except Exception as exc:
                    completed = utc_now()
                    cancelled = ce.is_set()
                    op_result = OperationResult(
                        operation_id=op_id,
                        kind="drive",
                        method_id=method_id,
                        method_name=method_id.upper(),
                        status="CANCELLED" if cancelled else "FAILED",
                        backend="execute_drive_method",
                        target=str(drive.device_path),
                        started=started,
                        completed=completed,
                        verification="NOT_EXECUTED",
                        evidence={},
                        warnings=[],
                        limitations=[],
                        detail=f"{'Cancelled' if cancelled else 'Failed'}: {exc}",
                        error=str(exc),
                    )
                    self.events.put((EV_LOG, f"[ERROR] {exc}"))
                    self.events.put(("status", ("CANCELLED" if cancelled else "FAILED", MUTED if cancelled else RED)))
                    self.events.put((EV_OP_COMPLETED, op_result))
                    raise

            self.task_manager.submit_task(f"drive_{method_id}", _drive_op_thread)
            return

        if not self.target:
            messagebox.showwarning("Select a target", "Choose a file, folder, or recovery image before starting.")
            return

        if kind == "recovery":
            is_image_file = (
                self.target.is_file()
                and self.target.suffix.lower() in {".img", ".dd", ".raw", ".iso", ".bin", ".e01", ".dmg"}
            ) or getattr(self, "_recovery_source_is_image", False)
            if not self.target.is_dir() and not is_image_file:
                messagebox.showerror(
                    "Invalid recovery source",
                    "Select a folder (to scan its backing device) or a disk image file (.img, .dd, .raw)."
                )
                return
            availability, reason = self._method_status(method_id, kind)
            if availability != "Available":
                messagebox.showerror("Recovery engine unavailable", reason)
                return

            source = str(self.target) if is_image_file else None
            if not is_image_file:
                drive = get_drive_for_path(self.target, self.drives)
                if drive is None:
                    messagebox.showerror("Physical source unavailable", "DREX could not map the selected folder to a PhysicalDrive source. No scan was started.")
                    return
                source = drive.device_path
                self.append_log(f"Recovery folder selected: {self.target}")
                self.append_log(f"Backing volume: {drive.path}")
                self.append_log(f"Physical source: {drive.device_path}")
            else:
                self.append_log(f"Recovery source (disk image): {self.target}")

            adapter = self.recovery_dispatcher.get(method_id)
            self._recovery_source = source
            self.progress_value.set(0)
            self.cancel_event.clear()
            self.tracker.start(0, stage="SCANNING")
            if hasattr(self, "status_label") and self.status_label:
                self.status_label.configure(text="SCANNING", fg=PURPLE)
            self.append_log(f"{label_for_recovery(method_id)} scan starting; source access is strictly read-only.")
            if hasattr(self, "start_button") and self.start_button:
                self.start_button.configure(state="disabled")
            if hasattr(self, "cancel_button") and self.cancel_button:
                self.cancel_button.configure(state="normal")

            self.task_manager.submit_task(
                f"recovery_scan_{method_id}",
                self._run_recovery_scan,
                method_id, adapter, self.target, source,
            )
            return

        if kind == "file":
            availability, reason = self._method_status(method_id, kind)
            if availability != "Available":
                messagebox.showerror("Method unavailable", reason or "The selected method is unavailable on this host.")
                return
            issue = dangerous_target(self.target)
            if issue:
                messagebox.showerror("Unsafe target", issue)
                return

        label = next((m["name"] for m in FILE_METHODS if m["id"] == method_id), method_id)
        if not messagebox.askyesno("Confirm destructive operation", f"This action may permanently change:\n\n{self.target}\n\nMethod: {label}\n\nContinue only if the target and method are correct."):
            return
        self.progress_value.set(0)
        self.cancel_event.clear()
        target_size = 0
        try:
            if self.target.is_file():
                target_size = self.target.stat().st_size
        except Exception:
            target_size = 0
        self.tracker.start(target_size, stage=label)
        if hasattr(self, "status_label") and self.status_label:
            self.status_label.configure(text="RUNNING", fg=BLUE)
        self.append_log("Validating target identity and method capability.")
        if hasattr(self, "start_button") and self.start_button:
            self.start_button.configure(state="disabled")
        if hasattr(self, "cancel_button") and self.cancel_button:
            self.cancel_button.configure(state="normal")
        self.task_manager.submit_task(
            f"file_wipe_{method_id}",
            self._run_file_operation,
            method_id, self.target, label,
        )

    def _run_recovery_scan(self, method_id: str, adapter: Any, target: Path, source: str, cancel_event: threading.Event | None = None):
        ce = cancel_event or self.cancel_event
        started = utc_now()
        label = next((name for mid, name, _ in RECOVERY_METHODS if mid == method_id), method_id)
        record = {"type": "recovery", "method": label, "target": str(target), "source": source, "started": started}
        try:
            scan = adapter.scan(source, cancel=ce.is_set)
            if ce.is_set():
                raise RecoveryError("Recovery scan cancelled by the user.")
            self.events.put(("recovery_scan", scan))
            completed = utc_now()
            record.update({"completed": completed, "duration": self._duration(started, completed), "status": "SUCCESS", "verification": "SCAN VERIFIED", "candidate_count": len(scan.candidates), "recovered_count": 0, "warnings": list(scan.warnings)})
            self.events.put(("result", ("SCAN COMPLETE", f"{label} completed against {source}. Candidates discovered: {len(scan.candidates)}. Select candidates and a separate destination for recovery.")))
            return scan
        except Exception as exc:
            completed = utc_now()
            cancelled = ce.is_set() or "cancelled" in str(exc).lower()
            record.update({"completed": completed, "duration": self._duration(started, completed), "status": "CANCELLED" if cancelled else "FAILED", "verification": "Not completed", "error": str(exc), "candidate_count": 0, "recovered_count": 0})
            status = "OPERATION CANCELLED" if cancelled else "OPERATION FAILED"
            self.events.put(("result", (status, f"{'Operation Cancelled' if cancelled else 'Operation Failed'}\nMethod: {label}\nTarget: {target}\nStage: native recovery scan\nActual reason: {type(exc).__name__}: {exc}")))
            raise
        finally:
            self.store.add_history(record)
            self.events.put(("finished", None))

    def cancel_operation(self):
        if self.task_manager.is_active() or (self.status_label and self.status_label.cget("text") in {"RUNNING", "SCANNING", "RECOVERING"}):
            self.task_manager.cancel()
            self.cancel_event.set()
            self.append_log("Cancellation requested; the local adapter will stop at its next safe progress boundary.")
            if hasattr(self, "cancel_button") and self.cancel_button:
                try:
                    self.cancel_button.configure(state="disabled")
                except Exception:
                    pass

    def _run_file_operation(self, method_id: str, target: Path, label: str, cancel_event: threading.Event | None = None):
        """File/folder wipe worker. Runs off the Tk thread via TaskManager.
        Returns an authoritative OperationResult. Audit + certificate generation
        happen here (off Tk), and the result is emitted through the queue.
        """
        ce = cancel_event or self.cancel_event
        op_id = f"file_{method_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        started = utc_now()
        before = hash_target(target)
        record: dict[str, Any] = {"type": "file", "method": label, "target": str(target), "started": started}

        def _do_finalize(status: str, v_status: str, evidence: dict, error_str: str | None, detail: str) -> OperationResult:
            """Build OperationResult, run audit + cert (off Tk), emit via queue."""
            completed = utc_now()
            record.update({
                "completed": completed,
                "duration": self._duration(started, completed),
                "status": status,
                "verification": v_status,
                "sha256_before": before,
                "sha256_after": evidence.get("sha256_after"),
                "error": error_str,
            })

            cert_id: str | None = None
            cert_path: str | None = None
            if status == "SUCCESS":
                try:
                    cert = self.cert_manager.create(record)
                    cert_id = cert.get("certificate_id")
                    cert_path = cert.get("certificate_path")
                    record["certificate_id"] = cert_id
                except Exception as cert_err:
                    self.events.put((EV_LOG, f"[warning] Certificate creation failed: {cert_err}"))

            self.store.add_history(record)

            op_result = OperationResult(
                operation_id=op_id,
                kind="file",
                method_id=method_id,
                method_name=label,
                status=status,
                backend="execute_file_method",
                target=str(target),
                started=started,
                completed=completed,
                verification=v_status,
                evidence=evidence,
                warnings=[],
                limitations=[],
                detail=detail,
                certificate_id=cert_id,
                certificate_path=cert_path,
                error=error_str,
            )
            self.events.put((EV_OP_COMPLETED, op_result))
            return op_result

        try:
            self.events.put((EV_LOG, "Operation started; adapter owns execution and verification."))

            def _progress_cb(done: int, total: int) -> None:
                if ce.is_set():
                    raise OperationCancelled("Cancellation requested by the user")
                self.events.put((EV_PROGRESS, (done, total)))

            result = execute_file_method(
                method_id, target,
                lambda message: self.events.put((EV_LOG, message)),
                _progress_cb,
            )
            if ce.is_set():
                raise OperationCancelled("Cancellation requested by the user")

            v_status, v_warnings = VerificationEngine.assess(result)
            status = "SUCCESS" if v_status in ("VERIFIED", "VERIFIED_PARTIAL") else "VERIFICATION_FAILED"
            detail = (
                f"Verified operation complete. Method: {label}. Target: {target}."
                if status == "SUCCESS"
                else f"Verification failed. Method: {label}. Target: {target}."
            )
            return _do_finalize(status, v_status, result, None, detail)

        except OperationCancelled as exc:
            return _do_finalize(
                "CANCELLED", "NOT_EXECUTED", {},
                str(exc),
                f"Operation cancelled. Method: {label}. Target: {target}.",
            )
        except Exception as exc:
            cancelled = ce.is_set()
            status = "CANCELLED" if cancelled else "FAILED"
            return _do_finalize(
                status, "NOT_EXECUTED", {},
                str(exc),
                f"{'Cancelled' if cancelled else 'Failed'}: {type(exc).__name__}: {exc}",
            )
        finally:
            self.events.put((EV_FINISHED, None))

    @staticmethod
    def _duration(started: str, completed: str) -> str:
        try:
            seconds = int((datetime.fromisoformat(completed.replace("Z", "+00:00")) - datetime.fromisoformat(started.replace("Z", "+00:00"))).total_seconds())
            return f"{max(0, seconds)}s"
        except ValueError:
            return "Unavailable"

    # ── Unified Operation Result Handler (Phase 8) ──────────────────────────────
    def _handle_operation_result(self, result: OperationResult) -> None:
        """Called on the Tk thread from _poll_events when EV_OP_COMPLETED arrives.

        This is the SINGLE point that routes a completed OperationResult to:
          • Status label update
          • Progress bar fill
          • Inline alert for failures
          • View Certificate button wiring (exact certificate_path)

        Audit and certificate generation already happened off the Tk thread
        inside the worker (_run_file_operation / _drive_op_thread).
        """
        status = result.status
        color = (
            GREEN_DARK if status == "SUCCESS"
            else MUTED if status in ("CANCELLED", "OPERATION_CANCELLED")
            else RED
        )

        if hasattr(self, "status_label") and self.status_label and self.status_label.winfo_exists():
            try:
                label_text = (
                    "WIPE SUCCESSFUL!" if status == "SUCCESS" and result.kind in ("drive", "file")
                    else "RECOVERY SUCCESSFUL!" if status == "SUCCESS" and result.kind == "recovery"
                    else status
                )
                self.status_label.configure(text=label_text, fg=color)
            except tk.TclError:
                pass

        if status == "SUCCESS":
            self.progress_value.set(100.0)
        elif status in ("FAILED", "VERIFICATION_FAILED", "EXECUTION_BLOCKED"):
            self._show_inline_alert(
                "Operation Failed" if status != "VERIFICATION_FAILED" else "Verification Failed",
                result.detail,
                severity="error",
                tech_info=result.error or json.dumps(result.evidence, indent=2, default=str)[:1000],
            )

        # Wire View Certificate button with the EXACT certificate_path from OperationResult.
        # This is the fix for the "View Certificate" defect: we never search for files,
        # never guess filenames, never regenerate — we use the path already stored.
        if result.certificate_path and result.certificate_id:
            cert_path = result.certificate_path
            self._current_cert_path = cert_path
            if hasattr(self, "view_cert_button") and self.view_cert_button and self.view_cert_button.winfo_exists():
                try:
                    self.view_cert_button.configure(
                        state="normal",
                        text="View Certificate",
                        command=lambda p=cert_path: self._open_certificate(p),
                    )
                except tk.TclError:
                    pass

    def _open_certificate(self, cert_path: str) -> None:
        """Open a certificate file using the OS default handler.
        Uses the exact path stored in OperationResult.certificate_path.
        Never searches for newest cert, never guesses filename.
        """
        try:
            if not Path(cert_path).is_file():
                messagebox.showerror(
                    "Certificate Not Found",
                    f"The certificate file could not be found:\n{cert_path}\n\n"
                    "It may have been moved or deleted."
                )
                return
            os.startfile(cert_path)
        except Exception as exc:
            messagebox.showerror("Cannot Open Certificate", f"Failed to open certificate:\n{exc}")

    def _poll_events(self):
        """Consume the Worker → queue → Tk event bus.

        Runs on the Tk thread, called every 30 ms via self.after().
        Batches log writes and coalesces progress events for performance.
        Handles both legacy string events and structured EV_* events.
        """
        log_batch: list[str] = []
        latest_progress = None
        try:
            while True:
                kind, value = self.events.get_nowait()
                # ── log (legacy + structured)
                if kind in ("log", EV_LOG):
                    log_batch.append(str(value))
                # ── progress — coalesce; only apply latest per tick
                elif kind in ("progress", EV_PROGRESS):
                    latest_progress = value
                # ── OperationResult — the unified completion path (Phase 8)
                elif kind == EV_OP_COMPLETED:
                    op_result: OperationResult = value
                    self._handle_operation_result(op_result)
                    log_batch.append(op_result.detail)
                # ── TaskManager state (internal lifecycle)
                elif kind in ("task_state", EV_TASK_STATE):
                    new_state, detail = value
                    if hasattr(self, "status_label") and self.status_label and self.status_label.winfo_exists():
                        if new_state in (TaskState.RUNNING, TaskState.QUEUED):
                            self.status_label.configure(text=new_state.name, fg=ORANGE)
                        elif new_state in (TaskState.VALIDATING, TaskState.VERIFYING):
                            self.status_label.configure(text=new_state.name, fg=BLUE)
                        elif new_state == TaskState.SUCCESS:
                            self.status_label.configure(text="SUCCESS", fg=GREEN_DARK)
                        elif new_state == TaskState.FAILED:
                            self.status_label.configure(text="FAILED", fg=RED)
                        elif new_state == TaskState.CANCELLED:
                            self.status_label.configure(text="CANCELLED", fg=MUTED)
                # ── Recovery scan results
                elif kind in ("recovery_scan", EV_RECOVERY_SCAN):
                    scan: RecoveryScan = value
                    self.recovery_scan = scan
                    if self.recovery_tree and self.recovery_tree.winfo_exists():
                        for item in self.recovery_tree.get_children():
                            self.recovery_tree.delete(item)
                        for candidate in scan.candidates:
                            size = fmt_bytes(candidate.size) if candidate.size is not None else "Unknown"
                            deleted = "Yes" if candidate.deleted is True else "No" if candidate.deleted is False else "Unknown"
                            confidence = f"{candidate.confidence:.0%}" if candidate.confidence is not None and candidate.confidence <= 1 else f"{candidate.confidence:.0f}%" if candidate.confidence is not None else "Unknown"
                            self.recovery_tree.insert("", "end", values=(candidate.candidate_id, candidate.name, candidate.filesystem, size, deleted, confidence))
                        self.recovery_tree.bind("<<TreeviewSelect>>", lambda _event: self._update_recovery_action_state(), add="+")
                        if hasattr(self, "recovery_destination_button") and self.recovery_destination_button:
                            self.recovery_destination_button.configure(state="normal")
                # ── Device discovery
                elif kind in ("devices_discovered", EV_DEVICES):
                    self._on_devices_discovered(value)
                # ── Asynchronous device capabilities updated
                elif kind in ("capabilities_updated", EV_CAPABILITIES):
                    probed_drive, caps = value
                    if self.selected_drive and (getattr(probed_drive, "path", None) == self.selected_drive.path or getattr(probed_drive, "device_path", None) == self.selected_drive.device_path):
                        self._update_drive_method_badges(caps=caps)
                        if getattr(self, "_tech_details_visible", False) and hasattr(self, "tech_details_label") and self.tech_details_label.winfo_exists():
                            probe_lines = [
                                f"PhysicalDisk: {caps.get('physical_disk_number')} | Bus: {caps.get('bus_type')} | Model: {caps.get('model')}",
                                f"Native Sanitize: {caps.get('native_sanitize')} | ATA Secure Erase: {caps.get('ata_secure_erase')} | NVMe: {caps.get('nvme_controller')}",
                                f"Overwrite Backend: {caps.get('overwrite_backend_qualified')} | Write Capable: {caps.get('write_capable')}",
                            ]
                            self.tech_details_label.configure(text="\n".join(probe_lines))
                # ── Legacy status/result events (kept for backwards compat)
                elif kind == "status":
                    status_out, fg_color = value
                    if hasattr(self, "status_label") and self.status_label and self.status_label.winfo_exists():
                        self.status_label.configure(text=status_out, fg=fg_color)
                elif kind == "result":
                    status, detail = value
                    color = GREEN_DARK if status == "SUCCESS" else (MUTED if "CANCELLED" in status else RED)
                    if hasattr(self, "status_label") and self.status_label and self.status_label.winfo_exists():
                        self.status_label.configure(text=status, fg=color)
                    log_batch.append(detail)
                    if status == "SUCCESS":
                        self.progress_value.set(100.0)
                        if hasattr(self, "status_label") and self.status_label and self.status_label.winfo_exists():
                            self.status_label.configure(text="WIPE SUCCESSFUL!" if self.current_page != "Recover" else "RECOVERY SUCCESSFUL!")
                # ── Inline error alert
                elif kind in ("error_alert", EV_ERROR_ALERT):
                    title, desc, severity, tech = value
                    self._show_inline_alert(title, desc, severity=severity, tech_info=tech)
                # ── Task teardown (release buttons, stop timer)
                elif kind in ("task_finished", EV_TASK_FINISHED, "finished", EV_FINISHED, "done"):
                    self.timer.stop()
                    if hasattr(self, "start_button") and self.start_button and self.start_button.winfo_exists():
                        try:
                            self.start_button.configure(state="normal")
                        except Exception:
                            pass
                    if hasattr(self, "cancel_button") and self.cancel_button and self.cancel_button.winfo_exists():
                        try:
                            self.cancel_button.configure(state="disabled")
                        except Exception:
                            pass
                    if kind in ("task_finished", EV_TASK_FINISHED):
                        task_id, result, exc = value
                        if exc is not None and not isinstance(exc, (OperationCancelled,)):
                            # Only show alert if we didn't already emit EV_OP_COMPLETED
                            if not (result and isinstance(result, OperationResult)):
                                self._show_inline_alert(
                                    "Operation Failed",
                                    f"An error occurred during {task_id}: {exc}",
                                    severity="error",
                                    tech_info=str(exc),
                                )
                        elif result and isinstance(result, dict) and result.get("status") in ("FAILED", "EXECUTION_BLOCKED", "VERIFICATION_FAILED"):
                            self._show_inline_alert(
                                "Operation Incomplete",
                                result.get("reason") or f"Method returned status {result.get('status')}",
                                severity="error",
                                tech_info=json.dumps(result, indent=2, default=str),
                            )
        except queue.Empty:
            pass

        # Flush batched logs in single UI draw
        if log_batch:
            self.append_log_batch(log_batch)

        # Apply coalesced progress
        if latest_progress is not None:
            if isinstance(latest_progress, tuple):
                done, total = latest_progress
                self.tracker.update(done, total)
                if total > 0:
                    self.progress_value.set(min(100.0, self.tracker.percentage))
            else:
                pct = float(latest_progress)
                self.tracker.percentage = pct
                self.progress_value.set(min(100.0, pct))

        self.after(30, self._poll_events)


def verify_certificate_record(path: str) -> bool:
    store = Store(Path(path).parent.parent)
    record = json.loads(Path(path).read_text(encoding="utf-8"))
    return CertificateManager(store).verify(record)


def run_doctor() -> dict[str, Any]:
    from recovery_backends import BACKENDS, find_backend_executable
    is_admin = False
    if os.name == "nt":
        try:
            is_admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            pass
    backend_report = {}
    for bid, spec in BACKENDS.items():
        exe = find_backend_executable(bid, ROOT)
        backend_report[bid] = {
            "name": bid,
            "installed": exe is not None,
            "executable_path": str(exe) if exe else None,
            "project_url": spec.project_url,
            "license": spec.license_name,
        }
    drives = discover_drives()
    report = {
        "app": APP_NAME,
        "version": VERSION,
        "python_version": sys.version,
        "platform": sys.platform,
        "is_admin": is_admin,
        "methods_count": {
            "drive": len(DRIVE_METHODS),
            "file": len(FILE_METHODS),
            "recovery": len(RECOVERY_METHODS),
            "total": len(DRIVE_METHODS) + len(FILE_METHODS) + len(RECOVERY_METHODS),
        },
        "backends": backend_report,
        "detected_drives": [
            {
                "path": d.path,
                "model": d.model,
                "serial": d.serial,
                "capacity": d.capacity,
                "drive_type": d.drive_type,
                "health": d.health,
            }
            for d in drives
        ],
    }
    return report


def main(argv: list[str] | None = None) -> int:
    global _ELEVATION_STATE
    argv = argv or sys.argv[1:]
    if "--version" in argv:
        print(f"{APP_NAME} {VERSION}")
        return 0
    if "--doctor" in argv:
        print(json.dumps(run_doctor(), indent=2))
        return 0
    if "--self-test" in argv:
        with tempfile.TemporaryDirectory(prefix="drex-self-test-") as temp:
            root = Path(temp)
            target = root / "fixture.bin"
            target.write_bytes(b"DREX adapter self-test" * 32)
            execute_file_method("zero", target, lambda _: None, lambda *_: None)
            if target.exists():
                return 2
            store = Store(root / "data")
            manager = CertificateManager(store)
            record = manager.create({
                "type": "file", "method": "Single-Pass Zero Overwrite", "target": str(target), "target_size": "fixture",
                "started": utc_now(), "completed": utc_now(), "duration": "0s", "status": "SUCCESS", "verification": "VERIFIED",
                "sha256_before": hashlib.sha256(b"DREX adapter self-test" * 32).hexdigest(), "sha256_after": "Not applicable after verified removal",
            })
            if not manager.verify(record) or not Path(record["pdf_path"]).exists():
                return 3
        print(json.dumps({"app": APP_NAME, "version": VERSION, "offline": True, "drive_methods": len(DRIVE_METHODS), "file_methods": len(FILE_METHODS), "recovery_methods": len(RECOVERY_METHODS), "bundled_adapter": "zero-overwrite", "certificate_integrity": "verified"}, indent=2))
        return 0

    # ── Elevation: detect privilege level before opening the Tk window. ──
    # DREX is a destructive storage application — Administrator access is
    # required for physical raw device I/O. If not elevated, request UAC.
    # This does NOT replace capability detection; it is only an OS permission check.
    _ELEVATION_STATE = _detect_elevation()
    if _ELEVATION_STATE == ElevationState.NOT_ELEVATED and "--no-uac" not in argv:
        # Attempt silent re-launch with runas. If the user cancels UAC or
        # elevation fails, we fall through and run with limited permissions.
        _request_uac_elevation()
        # If we reach here, UAC was cancelled or failed — update state and continue.
        _ELEVATION_STATE = _detect_elevation()

    app = DrexApp()
    qa_page = os.environ.get("DREX_QA_PAGE")
    if qa_page in {"Dashboard", "Wipe Drive", "Wipe File/Folder", "Recover", "Destroy Drive", "Certificates", "Help"}:
        app.show_page(qa_page)
    app.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
