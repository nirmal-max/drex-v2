"""
DREX-V2 Native NTFS Parser & Forensic Recovery Engine
Module: fs_ntfs.py
Phase: 3 / 12

Parses NTFS boot sector, MFT records with USA fixup, attributes ($STANDARD_INFORMATION,
$FILE_NAME, $DATA resident/non-resident data runs), and deleted records (flags 0x00/0x02).
"""

from __future__ import annotations

import datetime
import struct
from typing import Any, Dict, List, Optional, Tuple, Union

from fs_base import (
    ExtentRun,
    ExtentState,
    FilesystemKind,
    FsCandidateRecord,
    FsTimestamps,
    PathState,
    ReadOnlySource,
)


class NtfsParser:
    """Forensic parser for NTFS volumes and MFT structures."""

    FILE_MAGIC = b"FILE"
    BAAD_MAGIC = b"BAAD"
    ATTR_STANDARD_INFORMATION = 0x10
    ATTR_ATTRIBUTE_LIST = 0x20
    ATTR_FILE_NAME = 0x30
    ATTR_DATA = 0x80

    def __init__(self, source: ReadOnlySource, partition_offset: int = 0):
        self.source = source
        self.partition_offset = partition_offset
        self.bytes_per_sector = 512
        self.sectors_per_cluster = 8
        self.cluster_size = 4096
        self.mft_cluster_lcn = 0
        self.mft_offset = 0
        self.mft_record_size = 1024
        self.is_initialized = False
        self._initialize()

    def _initialize(self) -> None:
        """Parse NTFS Boot Sector (BPB) and establish geometry."""
        boot = self.source.read(self.partition_offset, 512)
        if len(boot) < 512 or boot[3:11] != b"NTFS    ":
            return

        self.bytes_per_sector, self.sectors_per_cluster = struct.unpack("<HB", boot[11:14])
        if self.bytes_per_sector == 0 or self.sectors_per_cluster == 0:
            return

        self.cluster_size = self.bytes_per_sector * self.sectors_per_cluster
        self.mft_cluster_lcn = struct.unpack("<Q", boot[48:56])[0]
        self.mft_offset = self.partition_offset + (self.mft_cluster_lcn * self.cluster_size)

        # MFT record size
        mft_rec_byte = struct.unpack("<b", boot[64:65])[0]
        if mft_rec_byte < 0:
            self.mft_record_size = 1 << abs(mft_rec_byte)  # e.g., -10 -> 1024 bytes
        else:
            self.mft_record_size = mft_rec_byte * self.cluster_size

        self.is_initialized = True

    def scan_records(self, max_records: int = 100000) -> List[FsCandidateRecord]:
        """Scan MFT records and discover both allocated and deleted candidates."""
        if not self.is_initialized:
            return []

        candidates: List[FsCandidateRecord] = []
        record_idx = 0

        while record_idx < max_records:
            record_offset = self.mft_offset + (record_idx * self.mft_record_size)
            if record_offset + self.mft_record_size > self.source.get_size():
                break

            record_bytes = self.source.read(record_offset, self.mft_record_size)
            if len(record_bytes) < self.mft_record_size:
                break

            # Stop scanning if consecutive records are completely zeroed
            if record_bytes == b"\x00" * len(record_bytes):
                # Peak ahead: check 4 records
                next_check = self.source.read(record_offset, min(4096, self.source.get_size() - record_offset))
                if next_check == b"\x00" * len(next_check):
                    break
                record_idx += 1
                continue

            cand = self.parse_record(record_bytes, record_idx)
            if cand:
                candidates.append(cand)

            record_idx += 1

        return candidates

    def parse_record(self, raw_record: bytes, record_index: int) -> Optional[FsCandidateRecord]:
        """Parse a single MFT record applying USA fixups and extracting attributes."""
        if len(raw_record) < 48:
            return None

        magic = raw_record[0:4]
        if magic not in (self.FILE_MAGIC, self.BAAD_MAGIC):
            return None

        is_baad = (magic == self.BAAD_MAGIC)

        # Apply USA (Update Sequence Array) fixup
        fixed_record, fixup_valid = self._apply_usa_fixup(raw_record)

        usa_offset, usa_count, lsn, seq_num, link_count, first_attr_offset, flags, real_size, alloc_size = struct.unpack(
            "<HHQHHHHII", fixed_record[4:32]
        )
        base_mft_ref = struct.unpack("<Q", fixed_record[32:40])[0]

        # Bit 0 = In-Use, Bit 1 = Directory
        is_in_use = bool(flags & 0x01)
        is_directory = bool(flags & 0x02)
        is_deleted = not is_in_use

        # Extract attributes
        attrs = self._parse_attributes(fixed_record, first_attr_offset)

        filename = f"MFT_{record_index}"
        parent_ref = None
        declared_size = 0
        resident_data: Optional[bytes] = None
        extents: List[ExtentRun] = []
        extent_state = ExtentState.VERIFIED_EXTENTS
        timestamps = FsTimestamps()

        # 1. $STANDARD_INFORMATION (0x10)
        if self.ATTR_STANDARD_INFORMATION in attrs:
            std_attr = attrs[self.ATTR_STANDARD_INFORMATION][0]
            if std_attr.get("is_resident") and len(std_attr.get("data", b"")) >= 32:
                timestamps = self._parse_windows_timestamps(std_attr["data"])

        # 2. $FILE_NAME (0x30)
        if self.ATTR_FILE_NAME in attrs:
            fn_attr = attrs[self.ATTR_FILE_NAME][0]
            if fn_attr.get("is_resident") and len(fn_attr.get("data", b"")) >= 66:
                fn_data = fn_attr["data"]
                parent_mft = struct.unpack("<Q", fn_data[0:8])[0] & 0x0000FFFFFFFFFFFF
                parent_ref = str(parent_mft)
                fn_len = fn_data[64]
                try:
                    name_raw = fn_data[66: 66 + (fn_len * 2)]
                    filename = name_raw.decode("utf-16-le", "replace")
                except Exception:
                    pass
                if not timestamps.created:
                    timestamps = self._parse_windows_timestamps(fn_data[8:40])

        # 3. $DATA (0x80)
        if self.ATTR_DATA in attrs and not is_directory:
            data_attr = attrs[self.ATTR_DATA][0]
            if data_attr.get("is_resident"):
                resident_data = data_attr.get("data", b"")
                declared_size = len(resident_data)
                extent_state = ExtentState.RESIDENT_METADATA
            else:
                declared_size = data_attr.get("real_size", 0)
                extents = data_attr.get("extents", [])
                if any(e.is_sparse for e in extents):
                    extent_state = ExtentState.SPARSE_EXTENTS
                elif len(extents) > 1:
                    extent_state = ExtentState.FRAGMENTED_EXTENTS
                else:
                    extent_state = ExtentState.VERIFIED_EXTENTS

        warnings: List[str] = []
        if is_baad:
            warnings.append("MFT_BAAD_SIGNATURE")
        if not fixup_valid:
            warnings.append("MFT_USA_FIXUP_MISMATCH")

        return FsCandidateRecord(
            candidate_id=f"ntfs_mft_{record_index}",
            filesystem=FilesystemKind.NTFS,
            filename=filename,
            original_path=filename,
            reconstructed_path=filename,
            path_state=PathState.ORIGINAL_PATH_CONFIRMED if is_in_use else PathState.PATH_UNKNOWN,
            declared_size=declared_size,
            recovered_size=declared_size if resident_data else sum(e.length_bytes for e in extents),
            is_directory=is_directory,
            is_deleted=is_deleted,
            is_resident=(resident_data is not None),
            extent_state=extent_state,
            extents=extents,
            resident_data=resident_data,
            timestamps=timestamps,
            parent_id=parent_ref,
            source_record_id=record_index,
            limitations=warnings,
        )

    def read_candidate_bytes(self, candidate: FsCandidateRecord, max_bytes: Optional[int] = None) -> bytes:
        """Extract full binary content of a candidate file."""
        if candidate.is_resident and candidate.resident_data is not None:
            return candidate.resident_data[:max_bytes] if max_bytes else candidate.resident_data

        target_size = candidate.declared_size
        if max_bytes:
            target_size = min(target_size, max_bytes)

        out_buffer = bytearray()
        bytes_left = target_size

        for ext in candidate.extents:
            if bytes_left <= 0:
                break
            chunk_len = min(bytes_left, ext.length_bytes)
            if ext.is_sparse:
                out_buffer.extend(b"\x00" * chunk_len)
            else:
                data = self.source.read(ext.physical_offset, chunk_len)
                out_buffer.extend(data)
            bytes_left -= chunk_len

        return bytes(out_buffer)

    def _apply_usa_fixup(self, raw: bytes) -> Tuple[bytes, bool]:
        """Apply Update Sequence Array (USA) fixup to raw MFT record."""
        if len(raw) < 48:
            return raw, False

        usa_offset, usa_count = struct.unpack("<HH", raw[4:8])
        if usa_offset + (usa_count * 2) > len(raw) or usa_count < 1:
            return raw, False

        usa_num = raw[usa_offset: usa_offset + 2]
        usa_array = raw[usa_offset + 2: usa_offset + (usa_count * 2)]

        sector_size = self.bytes_per_sector
        num_sectors = len(raw) // sector_size
        if (usa_count - 1) < num_sectors:
            return raw, False

        buf = bytearray(raw)
        is_valid = True

        for i in range(num_sectors):
            sec_end = ((i + 1) * sector_size) - 2
            curr_sig = bytes(buf[sec_end: sec_end + 2])
            if curr_sig != usa_num:
                is_valid = False

            # Replace with original 2 bytes from USA
            orig_bytes = usa_array[i * 2: (i * 2) + 2]
            buf[sec_end: sec_end + 2] = orig_bytes

        return bytes(buf), is_valid

    def _parse_attributes(self, record_bytes: bytes, first_attr_offset: int) -> Dict[int, List[dict]]:
        """Parse MFT attribute chain."""
        attrs: Dict[int, List[dict]] = {}
        offset = first_attr_offset

        while offset + 8 <= len(record_bytes):
            attr_type = struct.unpack("<I", record_bytes[offset: offset + 4])[0]
            if attr_type == 0xFFFFFFFF or attr_type == 0:
                break

            attr_len = struct.unpack("<I", record_bytes[offset + 4: offset + 8])[0]
            if attr_len < 8 or offset + attr_len > len(record_bytes):
                break

            attr_slice = record_bytes[offset: offset + attr_len]
            non_resident = attr_slice[8] != 0
            name_len = attr_slice[9]
            name_offset = struct.unpack("<H", attr_slice[10:12])[0]
            flags = struct.unpack("<H", attr_slice[12:14])[0]

            attr_dict: Dict[str, Any] = {
                "type": attr_type,
                "is_resident": not non_resident,
                "flags": flags,
            }

            if not non_resident:
                val_len, val_offset = struct.unpack("<IH", attr_slice[16:22])
                if val_offset + val_len <= len(attr_slice):
                    attr_dict["data"] = attr_slice[val_offset: val_offset + val_len]
            else:
                start_vcn, last_vcn, run_offset = struct.unpack("<QQH", attr_slice[16:34])
                alloc_size, real_size, init_size = struct.unpack("<QQQ", attr_slice[40:64])
                attr_dict["real_size"] = real_size
                attr_dict["alloc_size"] = alloc_size

                # Decode data runs
                runs_slice = attr_slice[run_offset:]
                extents = self.decode_data_runs(runs_slice)
                attr_dict["extents"] = extents

            attrs.setdefault(attr_type, []).append(attr_dict)
            offset += attr_len

        return attrs

    def decode_data_runs(self, run_bytes: bytes) -> List[ExtentRun]:
        """Decode nibble-encoded NTFS data runs into ExtentRun records."""
        extents: List[ExtentRun] = []
        offset = 0
        current_lcn = 0
        logical_offset = 0

        while offset < len(run_bytes):
            header = run_bytes[offset]
            if header == 0:
                break
            offset += 1

            len_size = header & 0x0F
            offset_size = (header >> 4) & 0x0F

            if len_size == 0 or offset + len_size + offset_size > len(run_bytes):
                break

            # Read run length in clusters
            run_len_bytes = run_bytes[offset: offset + len_size]
            run_clusters = int.from_bytes(run_len_bytes, byteorder="little", signed=False)
            offset += len_size

            # Read relative LCN offset (signed two's complement)
            if offset_size > 0:
                rel_offset_bytes = run_bytes[offset: offset + offset_size]
                rel_lcn = int.from_bytes(rel_offset_bytes, byteorder="little", signed=True)
                offset += offset_size
                current_lcn += rel_lcn
                is_sparse = False
                phys_offset = self.partition_offset + (current_lcn * self.cluster_size)
            else:
                is_sparse = True
                phys_offset = 0

            length_bytes = run_clusters * self.cluster_size
            extents.append(
                ExtentRun(
                    logical_offset=logical_offset,
                    physical_offset=phys_offset,
                    length_bytes=length_bytes,
                    is_sparse=is_sparse,
                    cluster_index=current_lcn,
                    cluster_count=run_clusters,
                )
            )
            logical_offset += length_bytes

        return extents

    @classmethod
    def _parse_windows_timestamps(cls, raw: bytes) -> FsTimestamps:
        """Parse 64-bit Windows FILETIME timestamps (100-nanosecond intervals since Jan 1, 1601)."""
        if len(raw) < 32:
            return FsTimestamps()

        def filetime_to_iso(ft: int) -> Optional[str]:
            if ft == 0 or ft > 0x7FFFFFFFFFFFFFFF:
                return None
            try:
                # Windows epoch to Unix epoch offset is 11644473600 seconds
                us = (ft - 116444736000000000) // 10
                dt = datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc) + datetime.timedelta(microseconds=us)
                return dt.isoformat()
            except Exception:
                return None

        c_ft, m_ft, mft_ft, a_ft = struct.unpack("<QQQQ", raw[0:32])
        return FsTimestamps(
            created=filetime_to_iso(c_ft),
            modified=filetime_to_iso(m_ft),
            mft_changed=filetime_to_iso(mft_ft),
            accessed=filetime_to_iso(a_ft),
        )
