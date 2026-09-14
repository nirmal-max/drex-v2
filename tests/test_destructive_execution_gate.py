"""Unit and Integration Tests for Destructive Execution Gates & Tripwire (Phase 7)."""

import os
import pytest
from hardware_storage import (
    DriveWipeHardwareBackend,
    HardwareExecutionStatus,
    DestructiveHardwareTripwire,
)


def test_destructive_hardware_tripwire_blocks_unauthorized_physical_io():
    """Verify DestructiveHardwareTripwire throws RuntimeError on unauthorized physical path."""
    with pytest.raises(RuntimeError) as exc_info:
        DestructiveHardwareTripwire.assert_safe_execution(r"\\.\PhysicalDrive1", "M04_ATA_SECURE_ERASE")
    assert "SAFETY TRIPWIRE TRIGGERED" in str(exc_info.value)


def test_destructive_gate_refuses_without_confirmation(monkeypatch):
    """Verify destructive execution fails closed without explicit operator confirmation."""
    monkeypatch.delenv("DREX_CONFIRM_DESTRUCTIVE", raising=False)
    monkeypatch.delenv("DREX_PHYSICAL_TEST_AUTHORIZED", raising=False)

    res = DriveWipeHardwareBackend.execute(
        device_path=r"\\.\PhysicalDrive5",
        method_id="M04",
        options={"confirm_destructive": False, "simulated_descriptor": {"disk_number": 5, "bus_type": "SATA"}},
        allow_simulation=True,
    )
    assert res.status == HardwareExecutionStatus.COMMAND_FAILED
    assert "confirmation required" in res.error_message


def test_destructive_gate_refuses_system_drive():
    """Verify system drive PhysicalDrive0 is refused."""
    res = DriveWipeHardwareBackend.execute(
        device_path=r"\\.\PhysicalDrive0",
        method_id="M05",
        options={"confirm_destructive": True, "simulated_descriptor": {"disk_number": 0, "system_disk": True, "bus_type": "NVME"}},
        allow_simulation=True,
    )
    assert res.status == HardwareExecutionStatus.BOOT_DISK_PROTECTED
    assert res.is_physical_hardware_executed is False


def test_destructive_gate_refuses_usb_pass_through():
    """Verify USB bridge triggers USB_BRIDGE_BLOCKED."""
    res = DriveWipeHardwareBackend.execute(
        device_path=r"\\.\PhysicalDrive3",
        method_id="M04",
        options={"confirm_destructive": True, "simulated_descriptor": {"disk_number": 3, "bus_type": "USB", "is_usb_bridge": True}},
        allow_simulation=True,
    )
    assert res.status == HardwareExecutionStatus.USB_BRIDGE_BLOCKED
    assert res.is_physical_hardware_executed is False


def test_simulation_mode_never_claims_physical_execution():
    """Verify simulation mode strictly reports physical_execution = NOT_EXECUTED."""
    res = DriveWipeHardwareBackend.execute(
        device_path=r"\\.\PhysicalDrive2",
        method_id="M04",
        options={"confirm_destructive": True, "simulated_descriptor": {"disk_number": 2, "bus_type": "SATA", "ata_security": "DISABLED"}},
        allow_simulation=True,
    )
    assert res.status == HardwareExecutionStatus.SIMULATION_QUALIFIED
    assert res.is_physical_hardware_executed is False
    assert res.hardware_qualification == "NOT_ESTABLISHED"
    assert res.execution == "SIMULATED"
