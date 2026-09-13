"""
DREX-V2 Native FAT12 / FAT16 / FAT32 Parser & Forensic Recovery Engine
Module: fs_fat.py
Phase: 3 / 12

Parses FAT12/16/32 BPBs, FAT tables, 32-byte directory entries, LFN Unicode chaining,
and deleted entries (0xE5) with explicit hypothetical zeroed-chain truth modeling.
"""

from __future__ import annotations

import datetime
import struct
from typing import Any, Dict, List, Optional, Set, Tuple

from fs_base import (
    ExtentRun,
    ExtentState,
    FilesystemKind,
    FsCandidateRecord,
    FsTimestamps,
    PathState,
    ReadOnlySource,
)


class FatParser:
    """Forensic parser for FAT12, FAT16, and FAT32 filesystems."""

    ATTR_READ_ONLY = 0x01
    ATTR_HIDDEN = 0x02
    ATTR_SYSTEM = 0x04
    ATTR_VOLUME_ID = 0x08
    ATTR_DIRECTORY = 0x10
    ATTR_ARCHIVE = 0x20
    ATTR_LONG_NAME = 0x0F

    DELETED_MARKER = 0xE5
    END_DIR_MARKER = 0x00

    def __init__(self, source: ReadOnlySource, partition_offset: int = 0):
        self.source = source
        self.partition_offset = partition_offset
        self.bytes_per_sector = 512
        self.sectors_per_cluster = 8
        self.cluster_size = 4096
        self.reserved_sectors = 32
        self.num_fats = 2
        self.sectors_per_fat = 0
        self.root_dir_entries = 0
        self.root_dir_sectors = 0
        self.root_cluster = 2
        self.fat_offset = 0
        self.data_start_offset = 0
        self.total_clusters = 0
        self.fat_kind = FilesystemKind.FAT32
        self.is_initialized = False
        self._initialize()

    def _initialize(self) -> None:
        """Parse BPB and establish FAT geometry."""
        sector0 = self.source.read(self.partition_offset, 512)
        if len(sector0) < 512 or sector0[510:512] != b"\x55\xaa":
            return

        try:
            self.bytes_per_sector, self.sectors_per_cluster, self.reserved_sectors, self.num_fats, self.root_dir_entries = struct.unpack(
                "<HBHBH", sector0[11:19]
            )
            total_secs_16, _, secs_per_fat_16 = struct.unpack("<HsH", sector0[19:24])
            total_secs_32 = struct.unpack("<I", sector0[32:36])[0]
        except Exception:
            return

        if self.bytes_per_sector == 0 or self.sectors_per_cluster == 0 or self.num_fats == 0:
            return

        self.cluster_size = self.bytes_per_sector * self.sectors_per_cluster
        self.sectors_per_fat = secs_per_fat_16

        total_sectors = total_secs_16 if total_secs_16 != 0 else total_secs_32

        if self.sectors_per_fat == 0 and len(sector0) >= 40:
            # FAT32 BPB
            self.sectors_per_fat = struct.unpack("<I", sector0[36:40])[0]
            self.root_cluster = struct.unpack("<I", sector0[44:48])[0]

        self.root_dir_sectors = ((self.root_dir_entries * 32) + (self.bytes_per_sector - 1)) // self.bytes_per_sector
        self.fat_offset = self.partition_offset + (self.reserved_sectors * self.bytes_per_sector)

        data_start_sec = self.reserved_sectors + (self.num_fats * self.sectors_per_fat) + self.root_dir_sectors
        self.data_start_offset = self.partition_offset + (data_start_sec * self.bytes_per_sector)

        data_sectors = total_sectors - data_start_sec if total_sectors >= data_start_sec else 0
        self.total_clusters = data_sectors // self.sectors_per_cluster if self.sectors_per_cluster > 0 else 0

        if self.total_clusters < 4085:
            self.fat_kind = FilesystemKind.FAT12
        elif self.total_clusters < 65525:
            self.fat_kind = FilesystemKind.FAT16
        else:
            self.fat_kind = FilesystemKind.FAT32

        self.is_initialized = True

    def cluster_to_byte_offset(self, cluster: int) -> int:
        """Convert a FAT cluster number (>= 2) to absolute byte offset."""
        if cluster < 2:
            return self.data_start_offset
        return self.data_start_offset + ((cluster - 2) * self.cluster_size)

    def read_fat_entry(self, cluster: int) -> int:
        """Read the next cluster pointer from the primary FAT table."""
        if self.fat_kind == FilesystemKind.FAT32:
            entry_offset = self.fat_offset + (cluster * 4)
            data = self.source.read(entry_offset, 4)
            if len(data) < 4:
                return 0x0FFFFFFF
            return struct.unpack("<I", data)[0] & 0x0FFFFFFF
        elif self.fat_kind == FilesystemKind.FAT16:
            entry_offset = self.fat_offset + (cluster * 2)
            data = self.source.read(entry_offset, 2)
            if len(data) < 2:
                return 0xFFFF
            return struct.unpack("<H", data)[0]
        else:  # FAT12
            entry_offset = self.fat_offset + ((cluster * 3) // 2)
            data = self.source.read(entry_offset, 2)
            if len(data) < 2:
                return 0xFFF
            val = struct.unpack("<H", data)[0]
            if cluster & 1:
                return val >> 4
            else:
                return val & 0x0FFF

    def is_eof_cluster(self, val: int) -> bool:
        """Check if cluster value represents End of Cluster Chain."""
        if self.fat_kind == FilesystemKind.FAT32:
            return val >= 0x0FFFFFF8
        elif self.fat_kind == FilesystemKind.FAT16:
            return val >= 0xFFF8
        else:
            return val >= 0xFF8

    @staticmethod
    def compute_lfn_checksum(short_name_11bytes: bytes) -> int:
        """
        Compute 8-bit checksum over 11-byte short filename according to FAT LFN specification.
        Adapted from CyberForensics (commit c1d2e3f) / FAT specification.
        See docs/PROVEN_CODE_PROVENANCE.md PROV-007.
        """
        chk = 0
        for b in short_name_11bytes:
            chk = (((chk & 1) << 7) | (chk >> 1)) + b
            chk &= 0xFF
        return chk

    def scan_all_entries(self, max_depth: int = 32) -> List[FsCandidateRecord]:
        """Traverse directory hierarchies and discover all allocated and deleted entries."""
        if not self.is_initialized:
            return []

        candidates: List[FsCandidateRecord] = []
        visited_clusters: Set[int] = set()

        if self.fat_kind == FilesystemKind.FAT32:
            self._scan_directory_cluster(self.root_cluster, "/", candidates, visited_clusters, depth=0, max_depth=max_depth)
        else:
            # FAT12 / FAT16 root directory is fixed size at root_dir_offset
            root_offset = self.partition_offset + (self.reserved_sectors + (self.num_fats * self.sectors_per_fat)) * self.bytes_per_sector
            root_bytes = self.source.read(root_offset, self.root_dir_entries * 32)
            self._parse_directory_buffer(root_bytes, "/", candidates, visited_clusters, depth=0, max_depth=max_depth)

        return candidates

    def _scan_directory_cluster(
        self,
        start_cluster: int,
        parent_path: str,
        candidates: List[FsCandidateRecord],
        visited_clusters: Set[int],
        depth: int,
        max_depth: int,
    ) -> None:
        """Read directory cluster chain and parse entries."""
        if depth > max_depth or start_cluster < 2 or start_cluster in visited_clusters:
            return

        curr_clus = start_cluster
        dir_bytes = bytearray()

        while curr_clus >= 2 and curr_clus not in visited_clusters:
            visited_clusters.add(curr_clus)
            clus_offset = self.cluster_to_byte_offset(curr_clus)
            clus_data = self.source.read(clus_offset, self.cluster_size)
            if not clus_data:
                break
            dir_bytes.extend(clus_data)

            next_clus = self.read_fat_entry(curr_clus)
            if self.is_eof_cluster(next_clus) or next_clus < 2:
                break
            curr_clus = next_clus

        self._parse_directory_buffer(bytes(dir_bytes), parent_path, candidates, visited_clusters, depth, max_depth)

    def _parse_directory_buffer(
        self,
        dir_bytes: bytes,
        parent_path: str,
        candidates: List[FsCandidateRecord],
        visited_clusters: Set[int],
        depth: int,
        max_depth: int,
    ) -> None:
        """Parse 32-byte directory entries with LFN Unicode reassembly."""
        lfn_parts: Dict[int, str] = {}
        lfn_checksums: Set[int] = set()
        offset = 0

        while offset + 32 <= len(dir_bytes):
            entry = dir_bytes[offset: offset + 32]
            offset += 32

            b0 = entry[0]
            if b0 == self.END_DIR_MARKER:
                # End of directory entries
                break

            attr = entry[11]

            # Long File Name (LFN) entry
            if attr == self.ATTR_LONG_NAME:
                seq = b0 & 0x1F
                chk = entry[13]
                lfn_checksums.add(chk)
                name_chars = bytearray()
                name_chars.extend(entry[1:11])
                name_chars.extend(entry[14:26])
                name_chars.extend(entry[28:32])
                try:
                    lfn_text = name_chars.decode("utf-16-le", "replace").split("\x00")[0]
                    lfn_parts[seq] = lfn_text
                except Exception:
                    pass
                continue

            # Skip volume label
            if (attr & self.ATTR_VOLUME_ID) and not (attr & self.ATTR_DIRECTORY):
                lfn_parts.clear()
                lfn_checksums.clear()
                continue

            # Short filename assembly
            is_deleted = (b0 == self.DELETED_MARKER)
            raw_name = bytearray(entry[0:11])
            if is_deleted:
                raw_name[0] = ord("_")

            s_name = raw_name[0:8].decode("latin1", "replace").rstrip()
            s_ext = raw_name[8:11].decode("latin1", "replace").rstrip()
            short_name = f"{s_name}.{s_ext}" if s_ext else s_name

            # Use LFN if available and checksum is valid (for deleted entries, byte 0 is overwritten with 0xE5)
            assembled_name = short_name
            if lfn_parts:
                actual_chk = self.compute_lfn_checksum(bytes(entry[0:11]))
                if is_deleted or (not lfn_checksums or all(c == actual_chk for c in lfn_checksums)):
                    assembled_name = "".join(lfn_parts[k] for k in sorted(lfn_parts.keys()))
                lfn_parts.clear()
                lfn_checksums.clear()

            # Skip '.' and '..'
            if assembled_name in (".", ".."):
                continue

            # Starting cluster & file size
            clus_hi = struct.unpack("<H", entry[20:22])[0]
            clus_lo = struct.unpack("<H", entry[26:28])[0]
            start_clus = (clus_hi << 16) | clus_lo
            file_size = struct.unpack("<I", entry[28:32])[0]

            is_dir = bool(attr & self.ATTR_DIRECTORY)
            timestamps = self._parse_dos_timestamps(entry[14:18], entry[22:26])

            # Resolve Extents & Deletion Semantics
            extents, extent_state, limitations = self._resolve_extents(start_clus, file_size, is_deleted)

            cand_id = f"fat_{start_clus}_{len(candidates)}"
            rec_path = f"{parent_path.rstrip('/')}/{assembled_name}"

            cand = FsCandidateRecord(
                candidate_id=cand_id,
                filesystem=self.fat_kind,
                filename=assembled_name,
                original_path=rec_path,
                reconstructed_path=rec_path,
                path_state=PathState.ORIGINAL_PATH_CONFIRMED if not is_deleted else PathState.ORIGINAL_PARENT_CONFIRMED,
                declared_size=file_size if not is_dir else 0,
                recovered_size=sum(e.length_bytes for e in extents),
                is_directory=is_dir,
                is_deleted=is_deleted,
                is_resident=False,
                extent_state=extent_state,
                extents=extents,
                timestamps=timestamps,
                parent_id=parent_path,
                source_record_id=start_clus,
                limitations=limitations,
            )
            candidates.append(cand)

            # Recurse into subdirectories if valid
            if is_dir and start_clus >= 2 and start_clus not in visited_clusters:
                self._scan_directory_cluster(start_clus, rec_path, candidates, visited_clusters, depth + 1, max_depth)

    def _resolve_extents(
        self, start_cluster: int, file_size: int, is_deleted: bool
    ) -> Tuple[List[ExtentRun], ExtentState, List[str]]:
        """Resolve cluster extents distinguishing valid FAT chains from zeroed-chain hypotheses."""
        if start_cluster < 2:
            return [], ExtentState.VERIFIED_EXTENTS, []

        extents: List[ExtentRun] = []
        limitations: List[str] = []

        # Check FAT table at start_cluster
        fat_val = self.read_fat_entry(start_cluster)

        if is_deleted and (fat_val == 0 or fat_val > self.total_clusters + 2):
            # Zeroed or destroyed FAT chain -> HYPOTHETICAL CONTIGUOUS EXTENTS
            needed_clusters = max(1, (file_size + self.cluster_size - 1) // self.cluster_size) if file_size > 0 else 1
            phys_offset = self.cluster_to_byte_offset(start_cluster)
            length_bytes = needed_clusters * self.cluster_size

            extents.append(
                ExtentRun(
                    logical_offset=0,
                    physical_offset=phys_offset,
                    length_bytes=length_bytes,
                    is_sparse=False,
                    is_hypothetical=True,
                    cluster_index=start_cluster,
                    cluster_count=needed_clusters,
                )
            )
            limitations.append("FAT_CHAIN_ZEROED_HYPOTHESIS")
            return extents, ExtentState.HYPOTHETICAL_EXTENTS, limitations

        # Valid / Surviving FAT Chain
        curr_clus = start_cluster
        visited = set()
        run_start_clus = curr_clus
        run_length_clus = 0
        logical_offset = 0

        while curr_clus >= 2 and curr_clus not in visited:
            visited.add(curr_clus)
            if run_length_clus == 0:
                run_start_clus = curr_clus
                run_length_clus = 1
            else:
                if curr_clus == run_start_clus + run_length_clus:
                    run_length_clus += 1
                else:
                    # Emit previous contiguous run
                    run_bytes = run_length_clus * self.cluster_size
                    extents.append(
                        ExtentRun(
                            logical_offset=logical_offset,
                            physical_offset=self.cluster_to_byte_offset(run_start_clus),
                            length_bytes=run_bytes,
                            is_sparse=False,
                            cluster_index=run_start_clus,
                            cluster_count=run_length_clus,
                        )
                    )
                    logical_offset += run_bytes
                    run_start_clus = curr_clus
                    run_length_clus = 1

            next_clus = self.read_fat_entry(curr_clus)
            if self.is_eof_cluster(next_clus) or next_clus < 2:
                break
            curr_clus = next_clus

        if run_length_clus > 0:
            run_bytes = run_length_clus * self.cluster_size
            extents.append(
                ExtentRun(
                    logical_offset=logical_offset,
                    physical_offset=self.cluster_to_byte_offset(run_start_clus),
                    length_bytes=run_bytes,
                    is_sparse=False,
                    cluster_index=run_start_clus,
                    cluster_count=run_length_clus,
                )
            )

        extent_state = ExtentState.FRAGMENTED_EXTENTS if len(extents) > 1 else ExtentState.VERIFIED_EXTENTS
        return extents, extent_state, limitations

    def read_candidate_bytes(self, candidate: FsCandidateRecord, max_bytes: Optional[int] = None) -> bytes:
        """Read full binary content of a candidate file."""
        target_size = candidate.declared_size
        if max_bytes:
            target_size = min(target_size, max_bytes)

        out_buffer = bytearray()
        bytes_left = target_size

        for ext in candidate.extents:
            if bytes_left <= 0:
                break
            chunk_len = min(bytes_left, ext.length_bytes)
            data = self.source.read(ext.physical_offset, chunk_len)
            out_buffer.extend(data)
            bytes_left -= chunk_len

        return bytes(out_buffer)

    @classmethod
    def _parse_dos_timestamps(cls, create_bytes: bytes, write_bytes: bytes) -> FsTimestamps:
        """Parse 16-bit DOS date/time integers."""
        def dos_to_iso(time_int: int, date_int: int) -> Optional[str]:
            if date_int == 0:
                return None
            try:
                year = ((date_int >> 9) & 0x7F) + 1980
                month = (date_int >> 5) & 0x0F
                day = date_int & 0x1F
                hour = (time_int >> 11) & 0x1F
                minute = (time_int >> 5) & 0x3F
                second = min(59, (time_int & 0x1F) * 2)
                dt = datetime.datetime(year, month, day, hour, minute, second, tzinfo=datetime.timezone.utc)
                return dt.isoformat()
            except Exception:
                return None

        c_time, c_date = struct.unpack("<HH", create_bytes) if len(create_bytes) >= 4 else (0, 0)
        w_time, w_date = struct.unpack("<HH", write_bytes) if len(write_bytes) >= 4 else (0, 0)

        return FsTimestamps(
            created=dos_to_iso(c_time, c_date),
            modified=dos_to_iso(w_time, w_date),
            accessed=dos_to_iso(0, w_date),
        )
