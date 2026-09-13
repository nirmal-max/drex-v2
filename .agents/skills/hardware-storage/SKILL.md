---
name: hardware-storage
description: Storage controller detection, ATA/NVMe pass-through, and physical drive geometry.
---

# Hardware Storage Skill

## When to Use
Use when probing physical drive capabilities, identifying ATA/NVMe controller interfaces, or querying device serials and SMART health.

## Key APIs
- Windows CIM / WMI (`Win32_DiskDrive`, `Win32_LogicalDiskToPartition`).
- Win32 DeviceIoControl (`IOCTL_STORAGE_QUERY_PROPERTY`, `IOCTL_STORAGE_PROTOCOL_COMMAND`).
- Bridge detection: Explicitly detect USB-to-SATA/NVMe bridges that filter SCSI/ATA commands.
