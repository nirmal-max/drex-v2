"""
DREX-V2 Forensic Partition Table Parser
Module: fs_partition.py
Phase: 3 / 12

Parses MBR, EBR extended chains, and GPT (Primary + Backup) with CRC32 verification,
cycle detection, bounds checking, and protective fallback.
"""

from __future__ import annotations

import struct
import uuid
import zlib
from typing import List, Optional, Tuple

from fs_base import (
    PartitionRecord,
    PartitionType,
    PartitionValidationOutcome,
    ReadOnlySource,
)


class PartitionTableParser:
    """Forensic partition table parser for MBR, EBR, and GPT."""

    GPT_SIGNATURE = b"EFI PART"
    MBR_BOOT_SIGNATURE = b"\x55\xaa"
    MAX_EBR_DEPTH = 32
    MAX_PARTITIONS = 128

    @classmethod
    def parse(cls, source: ReadOnlySource) -> List[PartitionRecord]:
        """Discover and validate all partitions on the source media."""
        sector_size = source.get_sector_size() or 512
        source_size = source.get_size()
        total_sectors = source_size // sector_size if sector_size > 0 else 0

        if source_size < sector_size:
            return cls._raw_fallback(source, "Source smaller than one sector")

        # 1. Check for GPT at LBA 1
        gpt_records = cls._parse_gpt(source, sector_size, total_sectors)
        if gpt_records:
            return gpt_records

        # 2. Check for MBR at LBA 0
        mbr_records = cls._parse_mbr(source, sector_size, total_sectors)
        if mbr_records:
            return mbr_records

        # 3. Fallback to Raw Image
        return cls._raw_fallback(source, "No valid partition table detected; treated as raw volume")

    @classmethod
    def _raw_fallback(cls, source: ReadOnlySource, reason: str) -> List[PartitionRecord]:
        """Emit a single PartitionRecord representing the entire raw volume."""
        source_size = source.get_size()
        sector_size = source.get_sector_size() or 512
        total_sectors = source_size // sector_size if sector_size > 0 else 0
        return [
            PartitionRecord(
                index=0,
                partition_type=PartitionType.RAW_IMAGE,
                start_lba=0,
                end_lba=max(0, total_sectors - 1),
                start_offset=0,
                size_bytes=source_size,
                sector_size=sector_size,
                name="RAW_VOLUME",
                warnings=[reason] if reason else [],
            )
        ]

    @classmethod
    def _parse_mbr(cls, source: ReadOnlySource, sector_size: int, total_sectors: int) -> List[PartitionRecord]:
        """Parse MBR and EBR extended partition chains."""
        sector0 = source.read(0, 512)
        if len(sector0) < 512 or sector0[510:512] != cls.MBR_BOOT_SIGNATURE:
            return []

        partitions: List[PartitionRecord] = []
        extended_ebr_lba: Optional[int] = None
        has_protective_mbr = False

        # Parse 4 standard MBR entries (offset 446 to 510, 16 bytes each)
        for i in range(4):
            entry_offset = 446 + (i * 16)
            entry = sector0[entry_offset: entry_offset + 16]
            status, _, _, _, type_code, _, _, _, lba_start, sector_count = struct.unpack("<BBBBBBBBII", entry)

            if type_code == 0x00 or sector_count == 0:
                continue

            if type_code == 0xEE:
                has_protective_mbr = True
                continue

            is_bootable = (status == 0x80)
            end_lba = lba_start + sector_count - 1
            start_byte = lba_start * sector_size
            size_bytes = sector_count * sector_size

            # Check for extended partition types (0x05, 0x0F)
            if type_code in (0x05, 0x0F):
                extended_ebr_lba = lba_start
                continue

            # Bounds validation
            warnings: List[str] = []
            val_outcome = PartitionValidationOutcome.VALID
            if total_sectors > 0 and (lba_start >= total_sectors or end_lba >= total_sectors):
                val_outcome = PartitionValidationOutcome.PARTIAL
                warnings.append(f"Partition {i} extends beyond source size (LBA {end_lba} >= {total_sectors})")

            partitions.append(
                PartitionRecord(
                    index=len(partitions),
                    partition_type=PartitionType.MBR_PRIMARY,
                    start_lba=lba_start,
                    end_lba=end_lba,
                    start_offset=start_byte,
                    size_bytes=size_bytes,
                    sector_size=sector_size,
                    type_code=type_code,
                    is_bootable=is_bootable,
                    validation=val_outcome,
                    warnings=warnings,
                )
            )

        if has_protective_mbr and not partitions:
            # Indicates GPT is likely present
            return []

        # Parse EBR if extended partition was found
        if extended_ebr_lba is not None:
            cls._parse_ebr_chain(source, sector_size, total_sectors, extended_ebr_lba, partitions)

        return partitions

    @classmethod
    def _parse_ebr_chain(
        cls,
        source: ReadOnlySource,
        sector_size: int,
        total_sectors: int,
        extended_root_lba: int,
        partitions: List[PartitionRecord],
    ) -> None:
        """Traverse EBR (Extended Boot Record) linked list with cycle detection."""
        current_ebr_lba = extended_root_lba
        visited_lbas = set()
        depth = 0

        while current_ebr_lba and depth < cls.MAX_EBR_DEPTH:
            if current_ebr_lba in visited_lbas:
                break
            visited_lbas.add(current_ebr_lba)
            depth += 1

            ebr_offset = current_ebr_lba * sector_size
            ebr_sector = source.read(ebr_offset, 512)
            if len(ebr_sector) < 512 or ebr_sector[510:512] != cls.MBR_BOOT_SIGNATURE:
                break

            # First entry: Logical partition relative to current EBR
            entry1 = ebr_sector[446:462]
            _, _, _, _, type_code1, _, _, _, rel_start1, count1 = struct.unpack("<BBBBBBBBII", entry1)

            if type_code1 != 0 and count1 > 0:
                abs_start_lba = current_ebr_lba + rel_start1
                end_lba = abs_start_lba + count1 - 1
                warnings: List[str] = []
                val_outcome = PartitionValidationOutcome.VALID
                if total_sectors > 0 and (abs_start_lba >= total_sectors or end_lba >= total_sectors):
                    val_outcome = PartitionValidationOutcome.PARTIAL
                    warnings.append(f"EBR partition extends beyond source bounds (LBA {end_lba} >= {total_sectors})")

                partitions.append(
                    PartitionRecord(
                        index=len(partitions),
                        partition_type=PartitionType.MBR_LOGICAL,
                        start_lba=abs_start_lba,
                        end_lba=end_lba,
                        start_offset=abs_start_lba * sector_size,
                        size_bytes=count1 * sector_size,
                        sector_size=sector_size,
                        type_code=type_code1,
                        validation=val_outcome,
                        warnings=warnings,
                    )
                )

            # Second entry: Pointer to next EBR relative to extended root LBA
            entry2 = ebr_sector[462:478]
            _, _, _, _, type_code2, _, _, _, rel_start2, count2 = struct.unpack("<BBBBBBBBII", entry2)
            if type_code2 != 0 and rel_start2 > 0:
                current_ebr_lba = extended_root_lba + rel_start2
            else:
                break

    @classmethod
    def _parse_gpt(cls, source: ReadOnlySource, sector_size: int, total_sectors: int) -> List[PartitionRecord]:
        """Parse Primary or Backup GPT with CRC32 verification."""
        # 1. Try Primary GPT at LBA 1
        primary_lba1_offset = 1 * sector_size
        header_bytes = source.read(primary_lba1_offset, sector_size)
        is_primary_valid, primary_info = cls._validate_gpt_header(header_bytes, sector_size, total_sectors)

        using_backup = False
        if is_primary_valid and primary_info:
            gpt_info = primary_info
        else:
            # 2. Try Backup GPT at last LBA
            backup_lba = total_sectors - 1 if total_sectors > 1 else 0
            if backup_lba > 1:
                backup_bytes = source.read(backup_lba * sector_size, sector_size)
                is_backup_valid, backup_info = cls._validate_gpt_header(backup_bytes, sector_size, total_sectors)
                if is_backup_valid and backup_info:
                    gpt_info = backup_info
                    using_backup = True
                else:
                    return []
            else:
                return []

        # Read Partition Entry Array
        entries_lba = gpt_info["entries_lba"]
        num_entries = min(gpt_info["num_entries"], cls.MAX_PARTITIONS)
        entry_size = gpt_info["entry_size"]
        entries_crc = gpt_info["entries_crc"]

        array_size = num_entries * entry_size
        entries_data = source.read(entries_lba * sector_size, array_size)
        if len(entries_data) < array_size:
            return []

        # Verify Partition Array CRC32
        actual_entries_crc = zlib.crc32(entries_data) & 0xFFFFFFFF
        array_crc_valid = (actual_entries_crc == entries_crc)

        partitions: List[PartitionRecord] = []
        for i in range(num_entries):
            offset = i * entry_size
            entry_slice = entries_data[offset: offset + entry_size]
            if len(entry_slice) < 128:
                continue

            type_guid_bytes = entry_slice[0:16]
            unique_guid_bytes = entry_slice[16:32]
            start_lba, end_lba, flags = struct.unpack("<QQQ", entry_slice[32:56])
            name_bytes = entry_slice[56:128]

            if type_guid_bytes == b"\x00" * 16 or start_lba == 0 or end_lba < start_lba:
                continue

            try:
                name = name_bytes.decode("utf-16-le").rstrip("\x00")
            except Exception:
                name = "GPT_PARTITION"

            type_guid_str = str(uuid.UUID(bytes_le=type_guid_bytes))
            unique_guid_str = str(uuid.UUID(bytes_le=unique_guid_bytes))
            size_bytes = (end_lba - start_lba + 1) * sector_size

            warnings: List[str] = []
            val_outcome = PartitionValidationOutcome.VALID
            if using_backup:
                warnings.append("BACKUP_GPT_RECOVERED (Primary GPT was corrupted or invalid)")
            if not array_crc_valid:
                val_outcome = PartitionValidationOutcome.PARTIAL
                warnings.append("Partition array CRC32 checksum mismatch")
            if total_sectors > 0 and end_lba >= total_sectors:
                val_outcome = PartitionValidationOutcome.PARTIAL
                warnings.append(f"GPT partition extends beyond source bounds (LBA {end_lba} >= {total_sectors})")

            partitions.append(
                PartitionRecord(
                    index=len(partitions),
                    partition_type=PartitionType.GPT,
                    start_lba=start_lba,
                    end_lba=end_lba,
                    start_offset=start_lba * sector_size,
                    size_bytes=size_bytes,
                    sector_size=sector_size,
                    type_guid=type_guid_str,
                    unique_guid=unique_guid_str,
                    name=name,
                    flags=flags,
                    validation=val_outcome,
                    warnings=warnings,
                )
            )

        return partitions

    @classmethod
    def _validate_gpt_header(
        cls, header_bytes: bytes, sector_size: int, total_sectors: int
    ) -> Tuple[bool, Optional[dict]]:
        """Validate GPT header signature, bounds, and CRC32."""
        if len(header_bytes) < 92 or header_bytes[0:8] != cls.GPT_SIGNATURE:
            return False, None

        revision, header_size, header_crc, _, current_lba, backup_lba, first_usable, last_usable = struct.unpack(
            "<IIIIQQQQ", header_bytes[8:56]
        )
        guid_bytes = header_bytes[56:72]
        entries_lba, num_entries, entry_size, entries_crc = struct.unpack("<QIII", header_bytes[72:92])

        if header_size < 92 or header_size > sector_size or entry_size < 128:
            return False, None

        # Verify Header CRC32 (with CRC field at bytes 16:20 zeroed)
        header_for_crc = header_bytes[0:16] + b"\x00\x00\x00\x00" + header_bytes[20:header_size]
        computed_crc = zlib.crc32(header_for_crc) & 0xFFFFFFFF
        if computed_crc != header_crc:
            return False, None

        return True, {
            "current_lba": current_lba,
            "backup_lba": backup_lba,
            "first_usable": first_usable,
            "last_usable": last_usable,
            "entries_lba": entries_lba,
            "num_entries": num_entries,
            "entry_size": entry_size,
            "entries_crc": entries_crc,
        }
