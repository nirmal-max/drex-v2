"""
DREX-V2 Native Sanitization Hardware & Controller Qualification Tests
====================================================================
Validates ATA Secure Erase, NVMe Format/Sanitize, USB bridge containment,
command construction, safety gates, and truthful evidence models without
touching physical hardware destructively.
"""

import ctypes
import pytest
from hardware_storage import (
    NativeHardwareEngine,
    HardwareDeviceCapabilities,
    HardwareExecutionStatus,
    AtaSecurityState,
    NvmeSanitizeAction,
    StorageBusType,
    ATA_CMD_SEC_SET_PASS,
    ATA_CMD_SEC_ERASE_UNIT,
    ATA_CMD_SEC_DISABLE_PASS,
    NVME_ADMIN_FORMAT_NVM,
    NVME_ADMIN_SANITIZE,
)


class TestNativeHardwareCommandConstruction:
    """Test low-level ATA and NVMe binary command structures."""

    def test_ata_password_block_normal_erase(self):
        pwd_block = NativeHardwareEngine.build_ata_password_block(enhanced=False, password=b"SecretKey123")
        assert len(pwd_block) == 512
        assert pwd_block[0] == 0x00  # Normal erase
        assert pwd_block[1] == 0x00  # User password identifier
        assert pwd_block[2:14] == b"SecretKey123"
        assert all(b == 0 for b in pwd_block[14:])

    def test_ata_password_block_enhanced_erase(self):
        pwd_block = NativeHardwareEngine.build_ata_password_block(enhanced=True, password=b"EnhancedKey")
        assert len(pwd_block) == 512
        assert pwd_block[0] == 0x02  # Enhanced erase bit
        assert pwd_block[1] == 0x00
        assert pwd_block[2:13] == b"EnhancedKey"

    def test_ata_passthrough_command_structure(self):
        pwd_block = NativeHardwareEngine.build_ata_password_block(enhanced=False)
        header, payload = NativeHardwareEngine.build_ata_passthrough_command(
            command_opcode=ATA_CMD_SEC_ERASE_UNIT,
            password_block=pwd_block,
            timeout_seconds=3600,
        )
        assert header.Length == ctypes.sizeof(header)
        assert header.TimeOutValue == 3600
        assert header.CurrentTaskFile[6] == ATA_CMD_SEC_ERASE_UNIT
        assert header.CurrentTaskFile[1] == 1  # Sector count
        assert len(payload) == ctypes.sizeof(header) + 512
        assert payload[ctypes.sizeof(header):] == pwd_block

    def test_nvme_admin_format_command_ses_modes(self):
        # SES=1: User Data Erase
        cmd_user = NativeHardwareEngine.build_nvme_admin_format_command(ses=1, nsid=0xFFFFFFFF, timeout_seconds=600)
        assert cmd_user.Version == 1
        assert cmd_user.ProtocolType == 3  # NVMe
        assert cmd_user.Command[0] == NVME_ADMIN_FORMAT_NVM
        assert cmd_user.Command[1] == 0xFFFFFFFF
        assert (cmd_user.Command[10] >> 9) & 0x07 == 1  # SES=1

        # SES=2: Cryptographic Erase
        cmd_crypto = NativeHardwareEngine.build_nvme_admin_format_command(ses=2, nsid=1, timeout_seconds=300)
        assert (cmd_crypto.Command[10] >> 9) & 0x07 == 2  # SES=2
        assert cmd_crypto.Command[1] == 1  # Namespace 1

    def test_nvme_admin_sanitize_actions(self):
        # Block Erase
        cmd_blk = NativeHardwareEngine.build_nvme_admin_sanitize_command(action=NvmeSanitizeAction.BLOCK_ERASE)
        assert cmd_blk.Command[0] == NVME_ADMIN_SANITIZE
        assert cmd_blk.Command[10] & 0x07 == int(NvmeSanitizeAction.BLOCK_ERASE)

        # Crypto Erase
        cmd_cry = NativeHardwareEngine.build_nvme_admin_sanitize_command(action=NvmeSanitizeAction.CRYPTO_ERASE)
        assert cmd_cry.Command[10] & 0x07 == int(NvmeSanitizeAction.CRYPTO_ERASE)

        # Overwrite with pattern 0x5A5A5A5A
        cmd_ow = NativeHardwareEngine.build_nvme_admin_sanitize_command(
            action=NvmeSanitizeAction.OVERWRITE,
            overwrite_pattern=0x5A5A5A5A,
        )
        assert cmd_ow.Command[10] & 0x07 == int(NvmeSanitizeAction.OVERWRITE)
        assert cmd_ow.Command[11] == 0x5A5A5A5A


class TestNativeHardwareSafetyGates:
    """Validate that safety gates reliably block hazardous operations."""

    def test_boot_and_system_disk_protection(self):
        # Target: C: or PhysicalDrive0
        caps = NativeHardwareEngine.probe_device_capabilities(
            r"\\.\PhysicalDrive0",
            simulated_descriptor={"disk_number": 0, "bus_type": "NVME", "system_disk": True},
        )
        assert caps.is_system_or_boot is True

        res = NativeHardwareEngine.execute_native_sanitization(
            method_id="nvme",
            caps=caps,
            confirm_destructive=True,
        )
        assert res.status == HardwareExecutionStatus.BOOT_DISK_PROTECTED
        assert res.is_physical_hardware_executed is False
        assert "protected system/boot drive" in res.error_message

    def test_usb_bridge_containment(self):
        # Target: USB flash or USB-SATA bridge
        caps = NativeHardwareEngine.probe_device_capabilities(
            r"\\.\PhysicalDrive1",
            simulated_descriptor={"disk_number": 1, "bus_type": "USB", "removable": True},
        )
        assert caps.is_usb_bridge is True

        res = NativeHardwareEngine.execute_native_sanitization(
            method_id="ata",
            caps=caps,
            confirm_destructive=True,
        )
        assert res.status == HardwareExecutionStatus.USB_BRIDGE_BLOCKED
        assert "not exposed over USB" in res.error_message
        assert res.evidence_payload["recommended_interface"] == "Direct SATA / M.2 PCIe NVMe"

    def test_frozen_ata_security_refusal(self):
        # SATA SSD with FROZEN state
        caps = NativeHardwareEngine.probe_device_capabilities(
            r"\\.\PhysicalDrive2",
            simulated_descriptor={
                "disk_number": 2,
                "bus_type": "SATA",
                "ata_security": "FROZEN",
                "system_disk": False,
            },
        )
        assert caps.ata_security_state == AtaSecurityState.FROZEN

        res = NativeHardwareEngine.execute_native_sanitization(
            method_id="ata",
            caps=caps,
            confirm_destructive=True,
        )
        assert res.status == HardwareExecutionStatus.DEVICE_FROZEN
        assert "FROZEN" in res.error_message

    def test_locked_ata_security_refusal(self):
        # SATA HDD with LOCKED state
        caps = NativeHardwareEngine.probe_device_capabilities(
            r"\\.\PhysicalDrive2",
            simulated_descriptor={
                "disk_number": 2,
                "bus_type": "SATA",
                "ata_security": "LOCKED",
                "system_disk": False,
            },
        )
        res = NativeHardwareEngine.execute_native_sanitization(
            method_id="ata",
            caps=caps,
            confirm_destructive=True,
        )
        assert res.status == HardwareExecutionStatus.DEVICE_LOCKED

    def test_unconfirmed_operation_refusal(self):
        # Valid SATA SSD with unconfirmed execution
        caps = NativeHardwareEngine.probe_device_capabilities(
            r"\\.\PhysicalDrive2",
            simulated_descriptor={
                "disk_number": 2,
                "bus_type": "SATA",
                "ata_security": "DISABLED",
                "system_disk": False,
            },
        )
        res = NativeHardwareEngine.execute_native_sanitization(
            method_id="ata",
            caps=caps,
            confirm_destructive=False,  # Unconfirmed
        )
        assert res.status == HardwareExecutionStatus.COMMAND_FAILED
        assert "confirmation required" in res.error_message


class TestTruthfulHardwareEvidenceModel:
    """Verify that offline/simulation tests NEVER claim physical hardware qualification."""

    def test_simulation_never_claims_physical_hardware_qualification(self):
        caps = NativeHardwareEngine.probe_device_capabilities(
            r"\\.\PhysicalDrive2",
            simulated_descriptor={
                "disk_number": 2,
                "bus_type": "NVME",
                "nvme_format": True,
                "system_disk": False,
            },
        )
        res = NativeHardwareEngine.execute_native_sanitization(
            method_id="nvme",
            caps=caps,
            confirm_destructive=True,
            allow_simulation=True,
        )
        assert res.status == HardwareExecutionStatus.SIMULATION_QUALIFIED
        assert res.is_physical_hardware_executed is False
        assert res.evidence_payload["execution_mode"] == "SOFTWARE_SIMULATION_QUALIFIED"
        assert res.evidence_payload["physical_qualification_state"] == "PENDING_PHYSICAL_HARDWARE"
        # Must NEVER contain REAL_HARDWARE_VERIFIED or PHYSICAL_HARDWARE_QUALIFIED
        assert res.evidence_payload.get("physical_qualification_state") != "PHYSICAL_HARDWARE_QUALIFIED"

    def test_storage_bus_enumeration_mapping(self):
        assert StorageBusType.SATA == 0x0B
        assert StorageBusType.NVME == 0x11
        assert StorageBusType.USB == 0x07
        assert StorageBusType.SCSI == 0x01
