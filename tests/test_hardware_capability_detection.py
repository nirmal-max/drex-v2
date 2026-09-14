"""Unit and Integration Tests for Hardware Capability Detection (Phase 7)."""

import pytest
from hardware_storage import (
    DriveWipeHardwareBackend,
    HardwareDeviceCapabilities,
    AtaSecurityState,
    NvmeSanitizeAction,
    StorageBusType,
)


def test_ata_security_state_detection():
    """Verify ATA security state detection and parsing."""
    caps_frozen = DriveWipeHardwareBackend.identify(
        r"\\.\PhysicalDrive2",
        simulated_descriptor={"disk_number": 2, "bus_type": "SATA", "ata_security": "FROZEN", "ata_enhanced": True},
    )
    assert caps_frozen.ata_supported is True
    assert caps_frozen.ata_security_state == AtaSecurityState.FROZEN
    assert caps_frozen.ata_enhanced_supported is True

    caps_disabled = DriveWipeHardwareBackend.identify(
        r"\\.\PhysicalDrive3",
        simulated_descriptor={"disk_number": 3, "bus_type": "SATA", "ata_security": "DISABLED"},
    )
    assert caps_disabled.ata_security_state == AtaSecurityState.DISABLED

    caps_locked = DriveWipeHardwareBackend.identify(
        r"\\.\PhysicalDrive4",
        simulated_descriptor={"disk_number": 4, "bus_type": "SATA", "ata_security": "LOCKED"},
    )
    assert caps_locked.ata_security_state == AtaSecurityState.LOCKED


def test_nvme_capability_detection():
    """Verify NVMe admin command capability parsing."""
    caps_nvme = DriveWipeHardwareBackend.identify(
        r"\\.\PhysicalDrive1",
        simulated_descriptor={
            "disk_number": 1,
            "bus_type": "NVME",
            "nvme_format": True,
            "nvme_sanitize": True,
            "nvme_crypto": True,
            "nvme_block": True,
            "nvme_overwrite": True,
        },
    )
    assert caps_nvme.nvme_supported is True
    assert caps_nvme.nvme_format_supported is True
    assert caps_nvme.nvme_crypto_erase_supported is True
    assert caps_nvme.nvme_block_erase_supported is True
    assert caps_nvme.nvme_overwrite_supported is True


def test_usb_bridge_containment():
    """Verify USB bridge isolates native firmware commands."""
    caps_usb = DriveWipeHardwareBackend.identify(
        r"\\.\PhysicalDrive4",
        simulated_descriptor={
            "disk_number": 4,
            "bus_type": "USB",
            "is_usb_bridge": True,
            "removable": True,
        },
    )
    assert caps_usb.is_usb_bridge is True
    assert caps_usb.ata_supported is False
    assert caps_usb.nvme_supported is False
