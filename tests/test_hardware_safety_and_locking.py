"""Unit and Integration Tests for Hardware Safety State Machine and Locking (Phase 7)."""

import pytest
from hardware_storage import (
    DeviceIntelligenceEngine,
    DeviceSafetyStateMachine,
    DriveWipeHardwareBackend,
    HardwareExecutionStatus,
    TransportBus,
)


def test_safety_gate_blocks_system_and_boot_disks():
    """Verify system drive PhysicalDrive0 is unconditionally blocked."""
    snap = DeviceIntelligenceEngine.create_snapshot(
        r"\\.\PhysicalDrive0",
        simulated_descriptor={"disk_number": 0, "system_disk": True, "boot_disk": True},
    )
    is_safe, status, reason, blocking = DeviceSafetyStateMachine.evaluate_safety(snap, "M04", confirmation=True)
    assert is_safe is False
    assert status == HardwareExecutionStatus.BOOT_DISK_PROTECTED
    assert "SYSTEM_DISK_BLOCKED" in blocking
    assert "BOOT_DISK_BLOCKED" in blocking


def test_safety_gate_blocks_ata_frozen_and_locked():
    """Verify ATA FROZEN and LOCKED drives fail closed."""
    caps_frozen = DriveWipeHardwareBackend.identify(
        r"\\.\PhysicalDrive2",
        simulated_descriptor={"disk_number": 2, "bus_type": "SATA", "ata_security": "FROZEN"},
    )
    is_safe, status, reason, blocking = DeviceSafetyStateMachine.evaluate_safety(
        caps_frozen.raw_identity_snapshot,
        method_id="M04",
        confirmation=True,
        ata_evidence=caps_frozen.raw_ata_evidence,
    )
    assert is_safe is False
    assert status == HardwareExecutionStatus.DEVICE_FROZEN
    assert "FROZEN" in blocking

    caps_locked = DriveWipeHardwareBackend.identify(
        r"\\.\PhysicalDrive3",
        simulated_descriptor={"disk_number": 3, "bus_type": "SATA", "ata_security": "LOCKED"},
    )
    is_safe, status, reason, blocking = DeviceSafetyStateMachine.evaluate_safety(
        caps_locked.raw_identity_snapshot,
        method_id="M04",
        confirmation=True,
        ata_evidence=caps_locked.raw_ata_evidence,
    )
    assert is_safe is False
    assert status == HardwareExecutionStatus.DEVICE_LOCKED
    assert "LOCKED" in blocking


def test_safety_gate_blocks_usb_bridge_pass_through():
    """Verify USB bridge blocks native ATA/NVMe pass-through."""
    caps_usb = DriveWipeHardwareBackend.identify(
        r"\\.\PhysicalDrive5",
        simulated_descriptor={"disk_number": 5, "bus_type": "USB", "is_usb_bridge": True},
    )
    is_safe, status, reason, blocking = DeviceSafetyStateMachine.evaluate_safety(
        caps_usb.raw_identity_snapshot,
        method_id="M05",
        confirmation=True,
    )
    assert is_safe is False
    assert status == HardwareExecutionStatus.USB_BRIDGE_BLOCKED
    assert "USB_BRIDGE_LIMITATION" in blocking


def test_safety_gate_blocks_write_protected_media():
    """Verify write-protected media fails closed."""
    snap_wp = DeviceIntelligenceEngine.create_snapshot(
        r"\\.\PhysicalDrive6",
        simulated_descriptor={"disk_number": 6, "bus_type": "USB", "write_protected": True},
    )
    is_safe, status, reason, blocking = DeviceSafetyStateMachine.evaluate_safety(
        snap_wp,
        method_id="M07",
        confirmation=True,
    )
    assert is_safe is False
    assert status == HardwareExecutionStatus.WRITE_PROTECTED
    assert "WRITE_PROTECTED" in blocking
