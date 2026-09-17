"""Backend adapters for official external recovery tools.

Each adapter wraps a single upstream tool using its verified CLI interface.
Command construction and output parsing are derived directly from the
upstream man-pages / source code; nothing is invented.

Upstream references:
  - TSK:       https://github.com/sleuthkit/sleuthkit   (fls.1, icat.1, tsk_recover.1, fsstat.1, mmls.1)
  - PhotoRec:  https://github.com/cgsecurity/testdisk   (phmain.c display_help)
  - ddrescue:  https://savannah.gnu.org/git/?group=ddrescue (info ddrescue)
  - TestDisk:  https://github.com/cgsecurity/testdisk   (testdisk.c — interactive only)
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from recovery_adapter import RecoveryCandidate, RecoveryError, RecoveryScan


# ─── TSK: fls ────────────────────────────────────────────────────────
# Upstream: fls [-adDFlpruvV] [-m mnt] [-z zone] [-f fstype] [-s seconds]
#           [-i imgtype] [-o imgoffset] [-b dev_sector_size] image [images] [inode]
#
# Output format (per line): TYPE inode_number file_name
#   d/d  2:  .
#   r/r  * 14:  deleted_file.txt
#   d/d  20:  subdir
# The '*' marks deleted entries.

def build_fls_command(fls_exe: Path, image: str, *, deleted_only: bool = False,
                      recursive: bool = True, long_format: bool = True,
                      full_path: bool = True, fs_offset: int | None = None) -> list[str]:
    """Build an fls command line using verified upstream flags."""
    cmd = [str(fls_exe)]
    if deleted_only:
        cmd.append("-d")
    if recursive:
        cmd.append("-r")
    if long_format:
        cmd.append("-l")
    if full_path:
        cmd.append("-p")
    if fs_offset is not None:
        cmd.extend(["-o", str(fs_offset)])
    cmd.append(image)
    return cmd


def parse_fls_output(stdout: str, module: str = "fls") -> list[RecoveryCandidate]:
    """Parse fls output lines into RecoveryCandidates.

    fls long-format (-l) output:
        file_type inode file_name mod_time acc_time chg_time cre_time size uid gid

    fls short-format output:
        TYPE inode:  file_name

    Deleted entries are marked with '*' before the inode number.
    """
    candidates: list[RecoveryCandidate] = []
    seen_ids: set[str] = set()

    # Regex for short fls output: r/r  * 14:	deleted_file.txt
    # or long format: r/r  * 14-128-4:	deleted_file.txt	2024-01-01	...	1234
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue

        # Detect whether the entry is deleted (asterisk marker)
        deleted = "*" in line.split(":")[0] if ":" in line else False

        # Extract inode number - the number before the colon
        # Patterns: "14:" or "14-128-4:" with optional leading whitespace and *
        inode_match = re.search(r'(\d+(?:-\d+(?:-\d+)?)?):\s+', line)
        if not inode_match:
            continue

        inode_str = inode_match.group(1)

        if inode_str in seen_ids:
            continue
        seen_ids.add(inode_str)

        # Extract filename - everything after "inode:  "
        name_start = inode_match.end()
        rest = line[name_start:]

        # In long format, fields are tab-separated: name \t times \t size ...
        fields = rest.split("\t")
        name = fields[0].strip() if fields else "Unknown"

        # Extract size if in long format (last numeric-looking field)
        size = None
        if len(fields) >= 2:
            for field in reversed(fields):
                field = field.strip()
                if field.isdigit():
                    size = int(field)
                    break

        # Determine type from prefix (r/r = regular, d/d = directory, etc.)
        file_type = None
        type_match = re.match(r'^([rdlcbpwv])/([rdlcbpwv])', line)
        if type_match:
            type_char = type_match.group(1)
            type_map = {"r": "regular", "d": "directory", "l": "symlink",
                        "c": "character", "b": "block", "p": "pipe", "v": "virtual"}
            file_type = type_map.get(type_char, type_char)

        candidates.append(RecoveryCandidate(
            candidate_id=inode_str,
            name=Path(name).name if name else "Unknown",
            filesystem="Unknown",  # fls doesn't report this per-file
            size=size,
            deleted=deleted,
            confidence=None,       # fls does not provide confidence
            raw={"inode": inode_str, "line": line},
            original_path=name,
            file_type=file_type,
            source_offset=None,
            source_device=None,
            source_partition=None,
            recoverable=deleted,   # Only deleted entries are recoverable in the TSK sense
            backend="tsk-fls",
            is_directory=(file_type == "directory"),
            relative_path=name,
        ))

    return candidates


# ─── TSK: icat ───────────────────────────────────────────────────────
# Upstream: icat [-hrsvV] [-f fstype] [-i imgtype] [-o imgoffset]
#           [-b dev_sector_size] image [images] inode
#
# icat copies the file content to stdout. Redirect to a file to recover.

def build_icat_command(icat_exe: Path, image: str, inode: str, *,
                       recover_deleted: bool = True,
                       fs_offset: int | None = None) -> list[str]:
    """Build an icat command line using verified upstream flags."""
    cmd = [str(icat_exe)]
    if recover_deleted:
        cmd.append("-r")
    if fs_offset is not None:
        cmd.extend(["-o", str(fs_offset)])
    cmd.append(image)
    cmd.append(inode)
    return cmd


# ─── TSK: tsk_recover ────────────────────────────────────────────────
# Upstream: tsk_recover [-vVae] [-f fstype] [-i imgtype] [-b dev_sector_size]
#           [-o sector_offset] [-d dir_inum] image [images] output_dir
#
# By default recovers only unallocated (deleted) files.
# -e recovers all (allocated + unallocated).

def build_tsk_recover_command(tsk_recover_exe: Path, image: str, output_dir: str, *,
                              all_files: bool = False,
                              fs_offset: int | None = None) -> list[str]:
    """Build a tsk_recover command line using verified upstream flags."""
    cmd = [str(tsk_recover_exe)]
    if all_files:
        cmd.append("-e")
    if fs_offset is not None:
        cmd.extend(["-o", str(fs_offset)])
    cmd.append(image)
    cmd.append(output_dir)
    return cmd


# ─── TSK: fsstat ─────────────────────────────────────────────────────
# Upstream: fsstat [-f fstype] [-i imgtype] [-o imgoffset]
#           [-b dev_sector_size] [-tvV] image [images]

def build_fsstat_command(fsstat_exe: Path, image: str, *,
                         fs_offset: int | None = None) -> list[str]:
    """Build an fsstat command line using verified upstream flags."""
    cmd = [str(fsstat_exe)]
    if fs_offset is not None:
        cmd.extend(["-o", str(fs_offset)])
    cmd.append(image)
    return cmd


def parse_fsstat_output(stdout: str) -> dict[str, Any]:
    """Parse fsstat output into a structured dict.

    fsstat output is free-form text with sections like:
        FILE SYSTEM INFORMATION
        FILE SYSTEM TYPE: NTFS
        ...
    """
    result: dict[str, Any] = {"raw": stdout}
    for line in stdout.splitlines():
        line = line.strip()
        if line.startswith("FILE SYSTEM TYPE:"):
            result["filesystem_type"] = line.split(":", 1)[1].strip()
        elif line.startswith("Volume Name:"):
            result["volume_name"] = line.split(":", 1)[1].strip()
        elif line.startswith("Volume Serial Number:"):
            result["serial"] = line.split(":", 1)[1].strip()
        elif line.startswith("Cluster Size:"):
            val = line.split(":", 1)[1].strip()
            try:
                result["cluster_size"] = int(val)
            except ValueError:
                result["cluster_size_raw"] = val
    return result


# ─── TSK: mmls ───────────────────────────────────────────────────────
# Upstream: mmls [-t mmtype] [-o offset] [-i imgtype] [-b dev_sector_size]
#           [-BrvV] [-aAmM] image [images]
#
# Output example:
#   DOS Partition Table
#   Offset Sector: 0
#   Units are in 512-byte sectors
#
#        Slot      Start        End          Length       Description
#   000:  Meta      0000000000   0000000000   0000000001   Primary Table (#0)
#   001:  -------   0000000000   0000002047   0000002048   Unallocated
#   002:  000:000   0000002048   0001026047   0001024000   NTFS / exFAT (0x07)

def build_mmls_command(mmls_exe: Path, image: str, *,
                       show_bytes: bool = True) -> list[str]:
    """Build an mmls command line using verified upstream flags."""
    cmd = [str(mmls_exe)]
    if show_bytes:
        cmd.append("-B")
    cmd.append(image)
    return cmd


def parse_mmls_output(stdout: str) -> list[dict[str, Any]]:
    """Parse mmls output into a list of partition dicts."""
    partitions: list[dict[str, Any]] = []
    for line in stdout.splitlines():
        line = line.strip()
        # Match lines like: 002:  000:000   0000002048   0001026047   0001024000   NTFS / exFAT (0x07)
        match = re.match(
            r'^(\d+):\s+(\S+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(.+)$', line
        )
        if match:
            partitions.append({
                "index": int(match.group(1)),
                "slot": match.group(2),
                "start": int(match.group(3)),
                "end": int(match.group(4)),
                "length": int(match.group(5)),
                "description": match.group(6).strip(),
            })
    return partitions


# ─── PhotoRec ────────────────────────────────────────────────────────
# Upstream CLI (from phmain.c display_help):
#   photorec [/log] [/logjson log.jsonl] [/debug] [/d recup_dir] [file.dd|file.e01|device]
#   photorec /version
#
# Non-interactive batch mode uses /cmd:
#   photorec /cmd <device> <commands...>
#
# Key limitations (from upstream source and documentation):
#   - PhotoRec does NOT recover original filenames; files are named f0001234.ext
#   - PhotoRec is a file CARVER — it works on unallocated space by default
#   - PhotoRec output directory must exist
#   - /d specifies the recovery output directory prefix

def build_photorec_command(photorec_exe: Path, image: str, output_dir: str, *,
                           log_json: str | None = None,
                           free_space_only: bool = True) -> list[str]:
    """Build a PhotoRec command line for non-interactive batch recovery.

    Uses /cmd for non-interactive mode and /d for output directory.
    The command string after /cmd <device> follows PhotoRec's internal
    command language: 'search' to start scanning.
    """
    cmd = [str(photorec_exe)]
    if log_json:
        cmd.extend(["/logjson", log_json])
    cmd.extend(["/d", output_dir])
    cmd.extend(["/cmd", image])
    # In batch mode, "search" starts the carving process
    cmd.append("search")
    return cmd


def build_fidentify_command(fidentify_exe: Path, target: str, *,
                            check_extension: bool = False,
                            file_format: str | None = None) -> list[str]:
    """Build an fidentify command line using verified PhotoRec fidentify syntax."""
    cmd = [str(fidentify_exe)]
    if check_extension:
        cmd.append("--check")
    if file_format:
        cmd.append(f"+{file_format}")
    cmd.append(target)
    return cmd


def parse_fidentify_output(stdout: str) -> list[dict[str, str]]:
    """Parse fidentify output lines (e.g. 'path/to/file.jpg: jpg')."""
    results: list[dict[str, str]] = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line or ":" not in line:
            continue
        path_part, format_part = line.rsplit(":", 1)
        format_str = format_part.strip()
        if format_str and not format_str.startswith("unknown"):
            results.append({"path": path_part.strip(), "format": format_str})
    return results


# ─── ddrescue ────────────────────────────────────────────────────────
# Upstream: ddrescue [options] infile outfile [mapfile]
#
# Key verified flags from upstream documentation:
#   -f, --force           overwrite output device or partition
#   -n, --no-scrape       skip scraping phase (faster, less data)
#   -r N, --retry-passes=N   retry bad areas N times
#   -v, --verbose         increase verbosity
#   -d, --idirect         use direct I/O for input
#   -S, --sparse          use sparse writes for output file
#
# ddrescue creates a rescue image and a mapfile tracking sector status.
# The mapfile is essential for resuming interrupted rescues.
#
# Key limitation: ddrescue does NOT recover individual files.
# It creates a sector-by-sector copy of a damaged device/image.

def build_ddrescue_command(ddrescue_exe: Path, infile: str, outfile: str,
                           mapfile: str, *, force: bool = False,
                           no_scrape: bool = False, retry_passes: int = 0,
                           direct_io: bool = False,
                           verbose: bool = True) -> list[str]:
    """Build a ddrescue command line using verified upstream flags."""
    cmd = [str(ddrescue_exe)]
    if force:
        cmd.append("-f")
    if no_scrape:
        cmd.append("-n")
    if retry_passes > 0:
        cmd.extend(["-r", str(retry_passes)])
    if direct_io:
        cmd.append("-d")
    if verbose:
        cmd.append("-v")
    cmd.append(infile)
    cmd.append(outfile)
    cmd.append(mapfile)
    return cmd


def parse_ddrescue_mapfile(mapfile: Path | str) -> dict[str, Any]:
    """Parse a ddrescue mapfile (Path, file path str, or raw text) to determine rescue progress."""
    result: dict[str, Any] = {"rescued_bytes": 0, "bad_bytes": 0,
                               "non_tried_bytes": 0, "total_bytes": 0,
                               "regions": []}
    if isinstance(mapfile, Path) or (isinstance(mapfile, str) and "\n" not in mapfile and Path(mapfile).is_file()):
        p = Path(mapfile)
        if not p.is_file():
            return result
        lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
    elif isinstance(mapfile, str):
        lines = mapfile.splitlines()
    else:
        return result
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) == 2:
            # Status header line: current_pos current_status
            continue
        if len(parts) >= 3:
            try:
                pos = int(parts[0], 0)
                size = int(parts[1], 0)
                status = parts[2]
                result["regions"].append({"pos": pos, "size": size, "status": status})
                result["total_bytes"] += size
                if status == "+":
                    result["rescued_bytes"] += size
                elif status == "-":
                    result["bad_bytes"] += size
                elif status == "?":
                    result["non_tried_bytes"] += size
            except (ValueError, IndexError):
                continue

    return result


# ─── Capability matrix (upstream source of truth) ────────────────────
# These document what each tool can and CANNOT do, per upstream.

BACKEND_CAPABILITIES = {
    "testdisk": {
        "can_recover_partitions": True,
        "can_recover_files": False,  # TestDisk is interactive-only for file ops
        "can_recover_boot_sectors": True,
        "has_batch_mode": False,     # TestDisk is fundamentally interactive (ncurses)
        "non_interactive_cli": False,
        "notes": "TestDisk is an interactive ncurses/Win32 application. It cannot be "
                 "driven non-interactively for recovery. DREX can detect its presence "
                 "but cannot automate it.",
    },
    "photorec": {
        "can_recover_files": True,
        "can_carve_unallocated": True,
        "recovers_original_filenames": False,  # PhotoRec CANNOT recover original filenames
        "recovers_directory_structure": False,  # Files go to flat recup_dir.N folders
        "has_batch_mode": True,
        "non_interactive_cli": True,  # via /cmd
        "supported_formats": "480+ file extensions (about 300 file families)",
        "notes": "PhotoRec is a file carver. It recovers file content based on "
                 "signatures/headers, NOT filesystem metadata. Original filenames "
                 "and directory structure are lost.",
    },
    "tsk_fls": {
        "can_list_files": True,
        "can_list_deleted": True,
        "can_list_recursive": True,
        "non_interactive_cli": True,
        "output_format": "text lines: TYPE inode: filename",
        "notes": "fls lists file names from filesystem metadata. It can show deleted "
                 "entries. Use with icat to actually recover file content.",
    },
    "tsk_icat": {
        "can_recover_single_file": True,
        "recovers_original_filename": False,  # icat outputs to stdout, caller must name
        "can_recover_deleted": True,  # -r flag
        "non_interactive_cli": True,
        "output_format": "raw file content to stdout",
        "notes": "icat extracts a single file by inode to stdout. The caller must "
                 "redirect to a named file. Only works if data blocks are not "
                 "overwritten.",
    },
    "tsk_recover": {
        "can_batch_recover": True,
        "recovers_original_filenames": True,
        "recovers_directory_structure": True,
        "non_interactive_cli": True,
        "default_behavior": "recovers unallocated (deleted) files only",
        "notes": "tsk_recover exports files from an image to a local directory. "
                 "By default it only exports deleted files. Use -e for all files.",
    },
    "ddrescue": {
        "can_recover_files": False,   # ddrescue does NOT recover individual files
        "can_image_damaged_media": True,
        "can_resume": True,           # via mapfile
        "non_interactive_cli": True,
        "notes": "ddrescue creates a sector-by-sector copy of a damaged device. "
                 "It does NOT recover individual files — it creates a disk image "
                 "that can then be processed by other tools (fls, photorec, etc.).",
    },
    "autopsy": {
        "can_recover_files": True,
        "has_batch_mode": False,      # Autopsy is a GUI forensic platform
        "non_interactive_cli": False,
        "notes": "Autopsy is a GUI-based digital forensics platform. It bundles TSK "
                 "and provides a case-based workflow. DREX can detect its installation "
                 "but cannot automate it non-interactively.",
    },
}


@dataclass(frozen=True)
class ProcessResult:
    command: tuple[str, ...]
    exit_code: int
    stdout: str
    stderr: str
    duration_seconds: float
    timed_out: bool = False
    cancelled: bool = False

    @property
    def success(self) -> bool:
        return self.exit_code == 0 and not self.timed_out and not self.cancelled


@dataclass(frozen=True)
class BinaryProcessResult:
    command: tuple[str, ...]
    exit_code: int
    stdout_bytes: bytes
    stderr_bytes: bytes
    duration_seconds: float
    timed_out: bool = False
    cancelled: bool = False

    @property
    def success(self) -> bool:
        return self.exit_code == 0 and not self.timed_out and not self.cancelled


class CentralProcessRunner:
    """Centralized process execution with safe argument arrays, timeout, and cancellation."""

    @staticmethod
    def run(
        command: list[str],
        *,
        timeout: int = 86400,
        cancel_check: Callable[[], bool] | None = None,
        cwd: str | Path | None = None,
        env: dict[str, str] | None = None,
    ) -> ProcessResult:
        if not command:
            raise ValueError("Command array must not be empty.")
        
        start_time = time.monotonic()
        try:
            proc = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
                cwd=str(cwd) if cwd else None,
                env=env,
            )
        except OSError as exc:
            return ProcessResult(
                command=tuple(command),
                exit_code=-1,
                stdout="",
                stderr=str(exc),
                duration_seconds=time.monotonic() - start_time,
            )

        timed_out = False
        cancelled = False

        while proc.poll() is None:
            if cancel_check and cancel_check():
                cancelled = True
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
                break

            if (time.monotonic() - start_time) >= timeout:
                timed_out = True
                proc.kill()
                proc.wait()
                break

            time.sleep(0.05)

        stdout, stderr = proc.communicate()
        duration = time.monotonic() - start_time

        return ProcessResult(
            command=tuple(command),
            exit_code=proc.returncode if proc.returncode is not None else -1,
            stdout=stdout or "",
            stderr=stderr or "",
            duration_seconds=duration,
            timed_out=timed_out,
            cancelled=cancelled,
        )

    @staticmethod
    def binary_run(
        command: list[str],
        *,
        timeout: int = 86400,
        cancel_check: Callable[[], bool] | None = None,
        cwd: str | Path | None = None,
        env: dict[str, str] | None = None,
    ) -> BinaryProcessResult:
        """Execute a process preserving stdout and stderr byte-for-byte without decoding."""
        if not command:
            raise ValueError("Command array must not be empty.")

        start_time = time.monotonic()
        try:
            proc = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=False,
                cwd=str(cwd) if cwd else None,
                env=env,
            )
        except OSError as exc:
            return BinaryProcessResult(
                command=tuple(command),
                exit_code=-1,
                stdout_bytes=b"",
                stderr_bytes=str(exc).encode("utf-8", errors="replace"),
                duration_seconds=time.monotonic() - start_time,
            )

        timed_out = False
        cancelled = False

        while proc.poll() is None:
            if cancel_check and cancel_check():
                cancelled = True
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
                break

            if (time.monotonic() - start_time) >= timeout:
                timed_out = True
                proc.kill()
                proc.wait()
                break

            time.sleep(0.05)

        stdout_bytes, stderr_bytes = proc.communicate()
        duration = time.monotonic() - start_time

        return BinaryProcessResult(
            command=tuple(command),
            exit_code=proc.returncode if proc.returncode is not None else -1,
            stdout_bytes=stdout_bytes or b"",
            stderr_bytes=stderr_bytes or b"",
            duration_seconds=duration,
            timed_out=timed_out,
            cancelled=cancelled,
        )


# ─── GNU ddrescue Adapter (External Tool Invocation Only) ───────────────────
# Upstream: ddrescue [options] infile outfile [mapfile]
# Reference: GNU ddrescue manual / public CLI interface (GPL external tool)

def build_ddrescue_command(
    ddrescue_exe: Path,
    source: str | Path,
    destination: str | Path,
    mapfile: str | Path,
    *,
    sector_size: int | None = None,
    retry_passes: int | None = None,
    direct_access: bool = False,
    direct_io: bool = False,
    no_trim: bool = False,
    no_scrape: bool = False,
    reverse: bool = False,
    verbose: bool = True,
    force: bool = False,
) -> list[str]:
    """Build a validated GNU ddrescue command line array using verified CLI flags."""
    cmd = [str(ddrescue_exe)]
    if verbose:
        cmd.append("-v")
    if force:
        cmd.append("-f")
    if no_scrape:
        cmd.append("-n")
    if no_trim:
        cmd.append("-N")
    if retry_passes is not None:
        cmd.extend(["-r", str(retry_passes)])
    if direct_access or direct_io:
        cmd.append("-d")
    if sector_size is not None and sector_size != 512:
        cmd.extend(["-b", str(sector_size)])
    if reverse:
        cmd.append("-R")
    cmd.extend([str(source), str(destination), str(mapfile)])
    return cmd


def parse_ddrescue_mapfile(content_or_path: str | Path) -> dict[str, Any]:
    """Parse ddrescue mapfile content or file path and return standard summary statistics dict."""
    if isinstance(content_or_path, Path) or (isinstance(content_or_path, str) and "\n" not in content_or_path and not content_or_path.startswith("0x") and not content_or_path.startswith("#")):
        p = Path(content_or_path)
        if not p.is_file():
            return {
                "rescued_bytes": 0,
                "bad_bytes": 0,
                "non_tried_bytes": 0,
                "total_bytes": 0,
                "regions": [],
            }
    from damaged_media import DdrescueMapfile
    try:
        mf = DdrescueMapfile.parse_mapfile(content_or_path)
        stats = mf.summary_stats()
        stats["regions"] = [{"pos": b.pos, "size": b.size, "status": b.status.value} for b in mf.blocks]
        return stats
    except Exception:
        return {
            "rescued_bytes": 0,
            "bad_bytes": 0,
            "non_tried_bytes": 0,
            "total_bytes": 0,
            "regions": [],
        }


def parse_ddrescue_output(stdout: str) -> dict[str, Any]:
    """Parse GNU ddrescue progress and summary text output."""
    res: dict[str, Any] = {
        "rescued_str": "",
        "rescued_bytes": 0,
        "errsize_str": "",
        "errsize_bytes": 0,
        "bad_areas": 0,
        "current_pass": 1,
        "pct_rescued": 0.0,
    }
    for line in stdout.splitlines():
        line = line.strip()
        # Pattern: (not pct) rescued: 1234 B
        rescued_match = re.search(r"(?<!pct\s)rescued:\s*([\d\.]+\s*[kMGTP]?B|\d+)", line, re.IGNORECASE)
        if rescued_match:
            res["rescued_str"] = rescued_match.group(1).strip()
        errsize_match = re.search(r"errsize:\s*([\d\.]+\s*[kMGTP]?B|\d+)", line, re.IGNORECASE)
        if errsize_match:
            res["errsize_str"] = errsize_match.group(1).strip()
        bad_match = re.search(r"bad areas:\s*(\d+)", line, re.IGNORECASE)
        if bad_match:
            res["bad_areas"] = int(bad_match.group(1))
        pct_match = re.search(r"pct rescued:\s*([\d\.]+)%", line, re.IGNORECASE)
        if pct_match:
            res["pct_rescued"] = float(pct_match.group(1))
        pass_match = re.search(r"current_pass:\s*(\d+)|pass\s*(\d+)", line, re.IGNORECASE)
        if pass_match:
            val = pass_match.group(1) or pass_match.group(2)
            res["current_pass"] = int(val)

    return res


@dataclass
class DdrescueAcquisitionResult:
    """Result from a controlled external GNU ddrescue execution."""
    success: bool
    source_path: str
    output_image_path: str
    mapfile_path: str
    rescued_bytes: int
    bad_bytes: int
    image_sha256: str
    mapfile_sha256: str
    duration_seconds: float
    command: list[str]
    stdout: str
    stderr: str
    error_message: str = ""
    is_simulation: bool = False



# --- BleachBit -------------------------------------------------------
def build_bleachbit_command(bleachbit_py: Path, target: str, *, wipe_free_space: bool = False, shred: bool = False) -> list[str]:
    """Build a BleachBit command line."""
    import sys
    cmd = [sys.executable, str(bleachbit_py)]
    if wipe_free_space:
        cmd.append("--wipe-free-space")
    if shred:
        cmd.append("--shred")
    cmd.append(target)
    return cmd

# --- Eraser ----------------------------------------------------------
def build_eraser_command(eraser_exe: Path, target: str, *, method: str = "Gutmann") -> list[str]:
    """Build an Eraser command line."""
    # Eraser.exe erase -method Gutmann -file <target>
    return [str(eraser_exe), "erase", "-method", method, "-file", target]

# --- DriveWipe -------------------------------------------------------
def build_drivewipe_command(drivewipe_cli: Path, target: str, *, method_id: str = "M01", confirm: bool = False) -> list[str]:
    """Build a DriveWipe CLI command line."""
    cmd = [str(drivewipe_cli), "wipe", "--target", target, "--method", method_id]
    if confirm:
        cmd.append("--confirm-destructive")
    return cmd

# --- nvme-cli --------------------------------------------------------
def build_nvme_cli_command(nvme_exe: Path, target: str, *, action: str = "format", ses: int = 1) -> list[str]:
    """Build an nvme-cli command line for secure erase or format."""
    cmd = [str(nvme_exe), action, target]
    if action == "format":
        cmd.extend(["-s", str(ses)])
    elif action == "sanitize":
        cmd.extend(["-a", str(ses)])
    return cmd
