"""
DREX-V2 Native exFAT Parser & Forensic Recovery Engine
Module: fs_exfat.py
Phase: 3 / 12

Parses exFAT VBR, Entry Sets (Primary File Entry, Stream Extension Entry with NoFatChain,
and File Name Entries), deleted entry sets (0x05/0x40/0x41), and stream extents.
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


class ExfatParser:
    """Forensic parser for exFAT volumes and Entry Sets."""

    ENTRY_PRIMARY_FILE_ALLOCATED = 0x85
    ENTRY_PRIMARY_FILE_DELETED = 0x05
    ENTRY_STREAM_EXT_ALLOCATED = 0xC0
    ENTRY_STREAM_EXT_DELETED = 0x40
    ENTRY_FILE_NAME_ALLOCATED = 0xC1
    ENTRY_FILE_NAME_DELETED = 0x41

    def __init__(self, source: ReadOnlySource, partition_offset: int = 0):
        self.source = source
        self.partition_offset = partition_offset
        self.bytes_per_sector = 512
        self.sectors_per_cluster = 8
        self.cluster_size = 4096
        self.fat_offset = 0
        self.fat_length_sectors = 0
        self.cluster_heap_offset = 0
        self.cluster_count = 0
        self.root_cluster = 2
        self.is_initialized = False
        self._initialize()

    def _initialize(self) -> None:
        """Parse exFAT Volume Boot Record (VBR) and geometry."""
        vbr = self.source.read(self.partition_offset, 512)
        if len(vbr) < 512 or vbr[3:11] != b"EXFAT   " or vbr[510:512] != b"\x55\xaa":
            return

        try:
            fat_offset_sec = struct.unpack("<I", vbr[80:84])[0]
            fat_len_sec = struct.unpack("<I", vbr[84:88])[0]
            cluster_heap_sec = struct.unpack("<I", vbr[88:92])[0]
            cluster_count = struct.unpack("<I", vbr[92:96])[0]
            root_clus = struct.unpack("<I", vbr[96:100])[0]
            sec_shift = vbr[108]
            clus_shift = vbr[109]
        except Exception:
            return

        if not (9 <= sec_shift <= 12 and 0 <= clus_shift <= 12):
            return

        self.bytes_per_sector = 1 << sec_shift
        self.sectors_per_cluster = 1 << clus_shift
        self.cluster_size = self.bytes_per_sector * self.sectors_per_cluster
        self.fat_offset = self.partition_offset + (fat_offset_sec * self.bytes_per_sector)
        self.fat_length_sectors = fat_len_sec
        self.cluster_heap_offset = self.partition_offset + (cluster_heap_sec * self.bytes_per_sector)
        self.cluster_count = cluster_count
        self.root_cluster = root_clus
        self.is_initialized = True

    def cluster_to_byte_offset(self, cluster: int) -> int:
        """Convert an exFAT cluster number (>= 2) to absolute byte offset in Cluster Heap."""
        if cluster < 2:
            return self.cluster_heap_offset
        return self.cluster_heap_offset + ((cluster - 2) * self.cluster_size)

    def read_fat_entry(self, cluster: int) -> int:
        """Read next cluster pointer from exFAT Allocation Table."""
        entry_offset = self.fat_offset + (cluster * 4)
        data = self.source.read(entry_offset, 4)
        if len(data) < 4:
            return 0xFFFFFFFF
        return struct.unpack("<I", data)[0]

    def scan_all_entries(self, max_depth: int = 32) -> List[FsCandidateRecord]:
        """Traverse directory cluster chains and discover exFAT Entry Sets."""
        if not self.is_initialized:
            return []

        candidates: List[FsCandidateRecord] = []
        visited_clusters: Set[int] = set()
        self._scan_directory_cluster(self.root_cluster, "/", candidates, visited_clusters, depth=0, max_depth=max_depth)
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
        """Read directory cluster chain and assemble entry sets."""
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

            # In exFAT, root directory may or may not have a FAT chain
            next_clus = self.read_fat_entry(curr_clus)
            if next_clus >= 0xFFFFFFF8 or next_clus < 2:
                break
            curr_clus = next_clus

        self._parse_entry_sets(bytes(dir_bytes), parent_path, candidates, visited_clusters, depth, max_depth)

    def _parse_entry_sets(
        self,
        dir_bytes: bytes,
        parent_path: str,
        candidates: List[FsCandidateRecord],
        visited_clusters: Set[int],
        depth: int,
        max_depth: int,
    ) -> None:
        """Parse contiguous 32-byte directory entry sets."""
        offset = 0
        total_len = len(dir_bytes)

        while offset + 32 <= total_len:
            entry_type = dir_bytes[offset]
            if entry_type == 0x00:
                # End of directory
                break

            # Check for Primary Directory Entry (0x85 Allocated or 0x05 Deleted)
            if entry_type in (self.ENTRY_PRIMARY_FILE_ALLOCATED, self.ENTRY_PRIMARY_FILE_DELETED):
                primary_entry = dir_bytes[offset: offset + 32]
                is_deleted = (entry_type == self.ENTRY_PRIMARY_FILE_DELETED)
                sec_count = primary_entry[1]
                file_attr = struct.unpack("<H", primary_entry[4:6])[0]
                is_dir = bool(file_attr & 0x10)

                # Expect at least 1 stream extension + 1 filename entry
                if sec_count < 2 or offset + ((1 + sec_count) * 32) > total_len:
                    offset += 32
                    continue

                # Stream Extension Entry (Offset + 32)
                stream_entry = dir_bytes[offset + 32: offset + 64]
                stream_type = stream_entry[0]

                if stream_type not in (self.ENTRY_STREAM_EXT_ALLOCATED, self.ENTRY_STREAM_EXT_DELETED):
                    offset += 32
                    continue

                gen_sec_flags = stream_entry[1]
                no_fat_chain = bool(gen_sec_flags & 0x02)
                name_len = stream_entry[3]
                first_clus = struct.unpack("<I", stream_entry[20:24])[0]
                data_len = struct.unpack("<Q", stream_entry[24:32])[0]

                # Assemble File Name Entries
                fn_parts = []
                for fn_idx in range(sec_count - 1):
                    fn_offset = offset + 64 + (fn_idx * 32)
                    fn_entry = dir_bytes[fn_offset: fn_offset + 32]
                    fn_type = fn_entry[0]
                    if fn_type in (self.ENTRY_FILE_NAME_ALLOCATED, self.ENTRY_FILE_NAME_DELETED):
                        chars_raw = fn_entry[2:32]
                        try:
                            fn_parts.append(chars_raw.decode("utf-16-le", "replace"))
                        except Exception:
                            pass

                filename = "".join(fn_parts)[:name_len].rstrip("\x00") if fn_parts else f"exfat_file_{first_clus}"

                # Timestamps
                timestamps = self._parse_exfat_timestamps(primary_entry[8:12], primary_entry[12:16], primary_entry[16:20])

                # Resolve Extents
                extents, extent_state, limitations = self._resolve_extents(first_clus, data_len, no_fat_chain, is_deleted)

                rec_path = f"{parent_path.rstrip('/')}/{filename}"
                cand = FsCandidateRecord(
                    candidate_id=f"exfat_{first_clus}_{len(candidates)}",
                    filesystem=FilesystemKind.EXFAT,
                    filename=filename,
                    original_path=rec_path,
                    reconstructed_path=rec_path,
                    path_state=PathState.ORIGINAL_PATH_CONFIRMED if not is_deleted else PathState.ORIGINAL_PARENT_CONFIRMED,
                    declared_size=data_len if not is_dir else 0,
                    recovered_size=sum(e.length_bytes for e in extents),
                    is_directory=is_dir,
                    is_deleted=is_deleted,
                    is_resident=False,
                    extent_state=extent_state,
                    extents=extents,
                    timestamps=timestamps,
                    parent_id=parent_path,
                    source_record_id=first_clus,
                    limitations=limitations,
                )
                candidates.append(cand)

                if is_dir and first_clus >= 2 and first_clus not in visited_clusters:
                    self._scan_directory_cluster(first_clus, rec_path, candidates, visited_clusters, depth + 1, max_depth)

                offset += (1 + sec_count) * 32
            else:
                offset += 32

    def _resolve_extents(
        self, first_cluster: int, data_length: int, no_fat_chain: bool, is_deleted: bool
    ) -> Tuple[List[ExtentRun], ExtentState, List[str]]:
        """Resolve exFAT cluster extents using NoFatChain flag or FAT table."""
        if first_cluster < 2 or data_length == 0:
            return [], ExtentState.VERIFIED_EXTENTS, []

        extents: List[ExtentRun] = []
        limitations: List[str] = []

        needed_clusters = max(1, (data_length + self.cluster_size - 1) // self.cluster_size)

        if no_fat_chain:
            # Deterministic contiguous stream
            phys_offset = self.cluster_to_byte_offset(first_cluster)
            length_bytes = needed_clusters * self.cluster_size
            extents.append(
                ExtentRun(
                    logical_offset=0,
                    physical_offset=phys_offset,
                    length_bytes=length_bytes,
                    is_sparse=False,
                    cluster_index=first_cluster,
                    cluster_count=needed_clusters,
                )
            )
            return extents, ExtentState.VERIFIED_EXTENTS, limitations

        # Traversal via FAT Table
        curr_clus = first_cluster
        visited = set()
        run_start_clus = curr_clus
        run_len_clus = 0
        logical_offset = 0

        while curr_clus >= 2 and curr_clus not in visited:
            visited.add(curr_clus)
            if run_len_clus == 0:
                run_start_clus = curr_clus
                run_len_clus = 1
            else:
                if curr_clus == run_start_clus + run_len_clus:
                    run_len_clus += 1
                else:
                    run_bytes = run_len_clus * self.cluster_size
                    extents.append(
                        ExtentRun(
                            logical_offset=logical_offset,
                            physical_offset=self.cluster_to_byte_offset(run_start_clus),
                            length_bytes=run_bytes,
                            is_sparse=False,
                            cluster_index=run_start_clus,
                            cluster_count=run_len_clus,
                        )
                    )
                    logical_offset += run_bytes
                    run_start_clus = curr_clus
                    run_len_clus = 1

            next_clus = self.read_fat_entry(curr_clus)
            if next_clus >= 0xFFFFFFF8 or next_clus < 2:
                break
            curr_clus = next_clus

        if run_len_clus > 0:
            run_bytes = run_len_clus * self.cluster_size
            extents.append(
                ExtentRun(
                    logical_offset=logical_offset,
                    physical_offset=self.cluster_to_byte_offset(run_start_clus),
                    length_bytes=run_bytes,
                    is_sparse=False,
                    cluster_index=run_start_clus,
                    cluster_count=run_len_clus,
                )
            )

        extent_state = ExtentState.FRAGMENTED_EXTENTS if len(extents) > 1 else ExtentState.VERIFIED_EXTENTS
        return extents, extent_state, limitations

    def read_candidate_bytes(self, candidate: FsCandidateRecord, max_bytes: Optional[int] = None) -> bytes:
        """Extract full binary stream of candidate file."""
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
    def _parse_exfat_timestamps(cls, create_bytes: bytes, modify_bytes: bytes, access_bytes: bytes) -> FsTimestamps:
        """Parse 32-bit exFAT DOS date/time integer fields."""
        def exfat_dos_to_iso(val_bytes: bytes) -> Optional[str]:
            if len(val_bytes) < 4:
                return None
            dt_int = struct.unpack("<I", val_bytes)[0]
            if dt_int == 0:
                return None
            try:
                time_part = dt_int & 0xFFFF
                date_part = (dt_int >> 16) & 0xFFFF
                year = ((date_part >> 9) & 0x7F) + 1980
                month = (date_part >> 5) & 0x0F
                day = date_part & 0x1F
                hour = (time_part >> 11) & 0x1F
                minute = (time_part >> 5) & 0x3F
                second = min(59, (time_part & 0x1F) * 2)
                dt = datetime.datetime(year, month, day, hour, minute, second, tzinfo=datetime.timezone.utc)
                return dt.isoformat()
            except Exception:
                return None

        return FsTimestamps(
            created=exfat_dos_to_iso(create_bytes),
            modified=exfat_dos_to_iso(modify_bytes),
            accessed=exfat_dos_to_iso(access_bytes),
        )
