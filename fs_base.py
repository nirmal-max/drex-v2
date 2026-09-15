"""
DREX-V2 Forensic Filesystem Recovery - Base Types & Abstractions
Module: fs_base.py
Phase: 3 / 12

Defines core read-only source abstractions, orthogonal truth states,
candidate models, partition records, and base interfaces for Phase 3.
"""

from __future__ import annotations

import abc
import hashlib
import os
import struct
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Generator, List, Optional, Tuple, Union


class SourceSafetyState(str, Enum):
    """Safety and write-blocker verification states for data sources."""
    READ_ONLY_HANDLE_CONFIRMED = "READ_ONLY_HANDLE_CONFIRMED"
    WRITE_PROTECTION_CONFIRMED = "WRITE_PROTECTION_CONFIRMED"
    WRITE_PROTECTION_UNKNOWN = "WRITE_PROTECTION_UNKNOWN"
    MOUNTED = "MOUNTED"
    UNMOUNTED = "UNMOUNTED"
    UNKNOWN = "UNKNOWN"


class PathState(str, Enum):
    """Reconstructed directory path confidence states."""
    ORIGINAL_PATH_CONFIRMED = "ORIGINAL_PATH_CONFIRMED"
    ORIGINAL_PARENT_CONFIRMED = "ORIGINAL_PARENT_CONFIRMED"
    PATH_PARTIAL = "PATH_PARTIAL"
    PATH_UNKNOWN = "PATH_UNKNOWN"
    ORPHANED = "ORPHANED"
    SYNTHETIC_PARENT = "SYNTHETIC_PARENT"


class ExtentState(str, Enum):
    """Extent resolution states for forensic candidates."""
    RESIDENT_METADATA = "RESIDENT_METADATA"
    VERIFIED_EXTENTS = "VERIFIED_EXTENTS"
    HYPOTHETICAL_EXTENTS = "HYPOTHETICAL_EXTENTS"
    FRAGMENTED_EXTENTS = "FRAGMENTED_EXTENTS"
    SPARSE_EXTENTS = "SPARSE_EXTENTS"
    CORRUPTED_EXTENTS = "CORRUPTED_EXTENTS"


class FilesystemKind(str, Enum):
    """Supported and recognized filesystem types."""
    NTFS = "NTFS"
    FAT12 = "FAT12"
    FAT16 = "FAT16"
    FAT32 = "FAT32"
    EXFAT = "EXFAT"
    EXT2 = "EXT2"
    EXT3 = "EXT3"
    EXT4 = "EXT4"
    HFS_PLUS = "HFS_PLUS"
    APFS = "APFS"
    ISO9660 = "ISO9660"
    AMBIGUOUS = "AMBIGUOUS"
    UNKNOWN = "UNKNOWN"


class PartitionType(str, Enum):
    """Partition table and structure classifications."""
    MBR_PRIMARY = "MBR_PRIMARY"
    MBR_LOGICAL = "MBR_LOGICAL"
    GPT = "GPT"
    PROTECTIVE_MBR = "PROTECTIVE_MBR"
    RAW_IMAGE = "RAW_IMAGE"
    UNKNOWN = "UNKNOWN"


class PartitionValidationOutcome(str, Enum):
    """Partition table integrity assessment outcomes."""
    VALID = "VALID"
    VALID_WITH_WARNINGS = "VALID_WITH_WARNINGS"
    PARTIAL = "PARTIAL"
    CORRUPTED = "CORRUPTED"
    UNKNOWN = "UNKNOWN"


@dataclass
class PartitionRecord:
    """Represents a discovered partition on storage media."""
    index: int
    partition_type: PartitionType
    start_lba: int
    end_lba: int
    start_offset: int
    size_bytes: int
    sector_size: int = 512
    type_code: Optional[int] = None
    type_guid: Optional[str] = None
    unique_guid: Optional[str] = None
    name: Optional[str] = None
    flags: int = 0
    is_bootable: bool = False
    validation: PartitionValidationOutcome = PartitionValidationOutcome.VALID
    warnings: List[str] = field(default_factory=list)


@dataclass
class ExtentRun:
    """Represents a contiguous run of bytes in a candidate file."""
    logical_offset: int
    physical_offset: int
    length_bytes: int
    is_sparse: bool = False
    is_hypothetical: bool = False
    cluster_index: Optional[int] = None
    cluster_count: Optional[int] = None


@dataclass
class FsTimestamps:
    """Forensic MACB timestamps."""
    created: Optional[str] = None
    modified: Optional[str] = None
    accessed: Optional[str] = None
    mft_changed: Optional[str] = None
    deleted: Optional[str] = None


class MetadataSource(str, Enum):
    """Provenance origin of recovered filesystem metadata."""
    NTFS_MFT = "NTFS_MFT"
    FAT_DIRECTORY_ENTRY = "FAT_DIRECTORY_ENTRY"
    EXFAT_DIRECTORY_ENTRY = "EXFAT_DIRECTORY_ENTRY"
    EXT_INODE = "EXT_INODE"
    CARVED = "CARVED"
    INFERRED = "INFERRED"
    UNKNOWN = "UNKNOWN"


@dataclass
class FsCandidateRecord:
    """Forensic candidate metadata discovered during filesystem scanning."""
    candidate_id: str
    filesystem: FilesystemKind
    filename: str
    original_path: Optional[str] = None
    reconstructed_path: Optional[str] = None
    path_state: PathState = PathState.PATH_UNKNOWN
    declared_size: int = 0
    recovered_size: int = 0
    is_directory: bool = False
    is_deleted: bool = False
    is_resident: bool = False
    extent_state: ExtentState = ExtentState.VERIFIED_EXTENTS
    extents: List[ExtentRun] = field(default_factory=list)
    resident_data: Optional[bytes] = None
    timestamps: FsTimestamps = field(default_factory=FsTimestamps)
    parent_id: Optional[str] = None
    source_record_id: Optional[Union[int, str]] = None
    evidence_vector: Dict[str, Any] = field(default_factory=dict)
    limitations: List[str] = field(default_factory=list)
    sha256: Optional[str] = None
    metadata_source: MetadataSource = MetadataSource.UNKNOWN
    is_metadata_inferred: bool = False
    fs_offset: Optional[int] = None


class ReadOnlySource(abc.ABC):
    """Abstract base class representing a strictly read-only data source."""

    @abc.abstractmethod
    def read(self, offset: int, size: int) -> bytes:
        """Read bytes at offset. Must not modify source under any circumstances."""
        raise NotImplementedError

    @abc.abstractmethod
    def get_size(self) -> int:
        """Return total size in bytes."""
        raise NotImplementedError

    @abc.abstractmethod
    def get_sector_size(self) -> int:
        """Return sector size in bytes (default 512)."""
        raise NotImplementedError

    @abc.abstractmethod
    def get_safety_state(self) -> SourceSafetyState:
        """Return verified source safety and write protection state."""
        raise NotImplementedError

    @abc.abstractmethod
    def get_source_identifier(self) -> str:
        """Return unique source path, URI, or device name."""
        raise NotImplementedError

    def compute_sha256(self, chunk_size: int = 4 * 1024 * 1024) -> str:
        """Compute full SHA-256 digest of source."""
        hasher = hashlib.sha256()
        total_size = self.get_size()
        offset = 0
        while offset < total_size:
            bytes_to_read = min(chunk_size, total_size - offset)
            data = self.read(offset, bytes_to_read)
            if not data:
                break
            hasher.update(data)
            offset += len(data)
        return hasher.hexdigest()

    def close(self) -> None:
        """Release underlying handles if necessary."""
        pass

    def __enter__(self) -> "ReadOnlySource":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()


class DiskImageSource(ReadOnlySource):
    """Read-only data source for raw disk image files (.raw, .dd, .img, .bin)."""

    def __init__(self, file_path: Union[str, Path], sector_size: int = 512):
        self.path = Path(file_path).resolve()
        if not self.path.exists():
            raise FileNotFoundError(f"Disk image not found: {self.path}")
        self._file = open(self.path, "rb")
        self._file.seek(0, os.SEEK_END)
        self._size = self._file.tell()
        self._file.seek(0)
        self._sector_size = sector_size
        self._safety_state = SourceSafetyState.READ_ONLY_HANDLE_CONFIRMED

    def read(self, offset: int, size: int) -> bytes:
        if offset < 0 or size < 0:
            raise ValueError("Offset and size must be non-negative")
        if offset >= self._size:
            return b""
        actual_size = min(size, self._size - offset)
        self._file.seek(offset)
        return self._file.read(actual_size)

    def get_size(self) -> int:
        return self._size

    def get_sector_size(self) -> int:
        return self._sector_size

    def get_safety_state(self) -> SourceSafetyState:
        return self._safety_state

    def get_source_identifier(self) -> str:
        return str(self.path)

    def close(self) -> None:
        if not self._file.closed:
            self._file.close()


class FileSource(DiskImageSource):
    """Alias for single container or filesystem image files."""
    pass


class PartitionSource(ReadOnlySource):
    """A bounded slice / window over a parent ReadOnlySource."""

    def __init__(self, parent_source: ReadOnlySource, start_offset: int, size_bytes: int, sector_size: Optional[int] = None):
        if start_offset < 0 or size_bytes < 0:
            raise ValueError("Partition offset and size must be non-negative")
        parent_size = parent_source.get_size()
        if start_offset + size_bytes > parent_size:
            raise ValueError(f"Partition bounds [{start_offset}, {start_offset + size_bytes}] exceed parent size {parent_size}")
        self.parent = parent_source
        self.start_offset = start_offset
        self.size_bytes = size_bytes
        self.sector_size = sector_size or parent_source.get_sector_size()

    def read(self, offset: int, size: int) -> bytes:
        if offset < 0 or size < 0:
            raise ValueError("Offset and size must be non-negative")
        if offset >= self.size_bytes:
            return b""
        actual_size = min(size, self.size_bytes - offset)
        return self.parent.read(self.start_offset + offset, actual_size)

    def get_size(self) -> int:
        return self.size_bytes

    def get_sector_size(self) -> int:
        return self.sector_size

    def get_safety_state(self) -> SourceSafetyState:
        return self.parent.get_safety_state()

    def get_source_identifier(self) -> str:
        return f"{self.parent.get_source_identifier()}:partition@{self.start_offset}+{self.size_bytes}"

    def close(self) -> None:
        pass


class SyntheticFixtureSource(ReadOnlySource):
    """In-memory or bytearray fixture source used for deterministic testing."""

    def __init__(self, data: Union[bytes, bytearray], sector_size: int = 512, identifier: str = "synthetic://fixture"):
        self._data = bytes(data)
        self._size = len(self._data)
        self._sector_size = sector_size
        self._identifier = identifier
        self._safety_state = SourceSafetyState.READ_ONLY_HANDLE_CONFIRMED

    def read(self, offset: int, size: int) -> bytes:
        if offset < 0 or size < 0:
            raise ValueError("Offset and size must be non-negative")
        if offset >= self._size:
            return b""
        return self._data[offset: offset + size]

    def get_size(self) -> int:
        return self._size

    def get_sector_size(self) -> int:
        return self._sector_size

    def get_safety_state(self) -> SourceSafetyState:
        return self._safety_state

    def get_source_identifier(self) -> str:
        return self._identifier


class PhysicalDeviceSource(ReadOnlySource):
    """Read-only handle to a physical block device (e.g. \\\\.\\PhysicalDriveN or /dev/sdX)."""

    def __init__(self, device_path: str, sector_size: int = 512, estimated_size: Optional[int] = None):
        self.device_path = device_path
        self._sector_size = sector_size
        self._estimated_size = estimated_size or 0
        self._safety_state = SourceSafetyState.READ_ONLY_HANDLE_CONFIRMED
        # On Windows or Linux, open with read-only semantics
        try:
            self._handle = open(device_path, "rb")
            if not self._estimated_size:
                try:
                    self._handle.seek(0, os.SEEK_END)
                    self._estimated_size = self._handle.tell()
                    self._handle.seek(0)
                except Exception:
                    # Some physical devices don't support seek(0, SEEK_END)
                    self._estimated_size = 1024 * 1024 * 1024 * 1024  # default 1TB upper bound
        except Exception as err:
            raise PermissionError(f"Failed to open physical device {device_path} read-only: {err}")

    def read(self, offset: int, size: int) -> bytes:
        if offset < 0 or size < 0:
            raise ValueError("Offset and size must be non-negative")
        self._handle.seek(offset)
        return self._handle.read(size)

    def get_size(self) -> int:
        return self._estimated_size

    def get_sector_size(self) -> int:
        return self._sector_size

    def get_safety_state(self) -> SourceSafetyState:
        return self._safety_state

    def get_source_identifier(self) -> str:
        return self.device_path

    def close(self) -> None:
        if hasattr(self, "_handle") and not self._handle.closed:
            self._handle.close()
