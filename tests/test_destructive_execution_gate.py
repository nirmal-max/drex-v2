"""Unit and Integration Tests for Destructive Execution Gates & Tripwire (Phase 7)."""

import os
import pytest
from hardware_storage import (
    DriveWipeHardwareBackend,
    HardwareExecutionStatus,
    DestructiveHardwareTripwire,
    DeviceIntelligenceEngine,
    PreExecutionRevalidator,
)


def test_destructive_hardware_tripwire_blocks_unauthorized_physical_io():
    """Verify DestructiveHardwareTripwire throws RuntimeError on unauthorized physical path."""
    with pytest.raises(RuntimeError) as exc_info:
        DestructiveHardwareTripwire.assert_safe_execution(r"\\.\PhysicalDrive1", "M04_ATA_SECURE_ERASE")
    assert "SAFETY TRIPWIRE TRIGGERED" in str(exc_info.value)


def test_tripwire_env_var_alone_is_denied(monkeypatch):
    """Verify DREX_PHYSICAL_TEST_AUTHORIZED=YES alone without matching device path is denied."""
    monkeypatch.setenv("DREX_PHYSICAL_TEST_AUTHORIZED", "YES")
    monkeypatch.delenv("DREX_PHYSICAL_TEST_DEVICE", raising=False)

    with pytest.raises(RuntimeError) as exc_info:
        DestructiveHardwareTripwire.assert_safe_execution(r"\\.\PhysicalDrive2", "M04_ATA_SECURE_ERASE")
    assert "SAFETY TRIPWIRE TRIGGERED" in str(exc_info.value)


def test_tripwire_auth_without_matching_device_is_denied(monkeypatch):
    """Verify authorization on PhysicalDrive8 denies execution against PhysicalDrive2."""
    monkeypatch.setenv("DREX_PHYSICAL_TEST_AUTHORIZED", "YES")
    monkeypatch.setenv("DREX_PHYSICAL_TEST_DEVICE", r"\\.\PhysicalDrive8")

    with pytest.raises(RuntimeError) as exc_info:
        DestructiveHardwareTripwire.assert_safe_execution(r"\\.\PhysicalDrive2", "M04_ATA_SECURE_ERASE")
    assert "SAFETY TRIPWIRE TRIGGERED" in str(exc_info.value)


def test_tripwire_matching_device_without_auth_flag_is_denied(monkeypatch):
    """Verify device path specified in DREX_PHYSICAL_TEST_DEVICE without YES flag is denied."""
    monkeypatch.setenv("DREX_PHYSICAL_TEST_DEVICE", r"\\.\PhysicalDrive8")
    monkeypatch.delenv("DREX_PHYSICAL_TEST_AUTHORIZED", raising=False)

    with pytest.raises(RuntimeError) as exc_info:
        DestructiveHardwareTripwire.assert_safe_execution(r"\\.\PhysicalDrive8", "M04_ATA_SECURE_ERASE")
    assert "SAFETY TRIPWIRE TRIGGERED" in str(exc_info.value)


def test_tripwire_system_drive_physicaldrive0_always_denied(monkeypatch):
    """Verify PhysicalDrive0 is unconditionally blocked even if env vars try to target it."""
    monkeypatch.setenv("DREX_PHYSICAL_TEST_AUTHORIZED", "YES")
    monkeypatch.setenv("DREX_PHYSICAL_TEST_DEVICE", r"\\.\PhysicalDrive0")

    with pytest.raises(RuntimeError) as exc_info:
        DestructiveHardwareTripwire.assert_safe_execution(r"\\.\PhysicalDrive0", "M04_ATA_SECURE_ERASE")
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


def test_destructive_gate_refuses_boot_disk_flag():
    """Verify boot disk flag refuses destructive execution."""
    res = DriveWipeHardwareBackend.execute(
        device_path=r"\\.\PhysicalDrive2",
        method_id="M04",
        options={"confirm_destructive": True, "simulated_descriptor": {"disk_number": 2, "boot_disk": True, "bus_type": "SATA"}},
        allow_simulation=True,
    )
    assert res.status == HardwareExecutionStatus.BOOT_DISK_PROTECTED
    assert res.is_physical_hardware_executed is False


def test_destructive_gate_refuses_identity_drift():
    """Verify identity drift during pre-execution revalidation causes fail-closed refusal."""
    snap1 = DeviceIntelligenceEngine.create_snapshot(
        r"\\.\PhysicalDrive2",
        simulated_descriptor={"disk_number": 2, "serial_number": "ORIG-SN-001", "capacity_bytes": 10**11, "bus_type": "SATA"},
    )
    is_valid, err, _ = PreExecutionRevalidator.revalidate(
        discovery_snapshot=snap1,
        target_device_path=r"\\.\PhysicalDrive2",
        simulated_descriptor={"disk_number": 2, "serial_number": "DRIFTED-SN-999", "capacity_bytes": 10**11, "bus_type": "SATA"},
    )
    assert is_valid is False
    assert "IDENTITY_CHANGED" in err


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


def test_destructive_gate_refuses_unknown_unsupported_capability():
    """Verify device with unknown capability fails closed."""
    res = DriveWipeHardwareBackend.execute(
        device_path=r"\\.\PhysicalDrive6",
        method_id="M04",
        options={"confirm_destructive": True, "simulated_descriptor": {"disk_number": 6, "bus_type": "UNKNOWN"}},
        allow_simulation=False,
    )
    assert res.status in (HardwareExecutionStatus.UNSUPPORTED_HARDWARE, HardwareExecutionStatus.COMMAND_FAILED)


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
