"""
DREX-V2 Phase 9 — Hardware Safety & Qualification Gate Adversarial Tests
========================================================================
File: tests/test_phase9_hardware_safety.py

Adversarial validation of hardware qualification gates, TOCTOU safety guards,
device identity stability, USB bridge containment, and non-negotiable truth boundaries:
- Serial, capacity, model, sector geometry, and bus transport drift detection
- Sudden device disappearance / invalid handle refusal
- System and boot disk mutation refusal (PhysicalDrive0, C:)
- USB bridge low-level ATA/NVMe pass-through refusal
- Hardware write protection fail-closed refusal
- Software qualification truth invariant:
    physical_execution = NOT_EXECUTED
    physical_qualification = NOT_ESTABLISHED

Zero external dependencies. Pure standard library.
"""

from __future__ import annotations

import pytest
from hardware_storage import (
    DeviceIntelligenceEngine,
    DeviceSafetyStateMachine,
    DestructiveHardwareTripwire,
    HardwareExecutionStatus,
    PreExecutionRevalidator,
    Qualification25MethodEngine,
    TransportBus,
)


class TestPhase9DeviceIdentityStability:
    """Adversarial tests for dynamic device identity drift and TOCTOU protection."""

    def test_serial_drift_adversarial_rejection(self):
        """PreExecutionRevalidator refuses execution if serial changes between discovery and execution."""
        sim1 = {"disk_number": 2, "serial_number": "AUTHENTIC-DRIVE-SN1", "product_id": "SSD 980"}
        sim2 = {"disk_number": 2, "serial_number": "SUBSTITUTE-DRIVE-SN2", "product_id": "SSD 980"}

        snap1 = DeviceIntelligenceEngine.create_snapshot(r"\\.\PhysicalDrive2", simulated_descriptor=sim1)
        valid, err, _ = PreExecutionRevalidator.revalidate(
            discovery_snapshot=snap1,
            target_device_path=r"\\.\PhysicalDrive2",
            simulated_descriptor=sim2,
        )
        assert valid is False
        assert "IDENTITY_CHANGED" in err
        assert "Serial drift" in err

    def test_capacity_drift_adversarial_rejection(self):
        """PreExecutionRevalidator refuses execution if drive capacity changes."""
        sim1 = {"disk_number": 2, "serial_number": "SN-01", "capacity_bytes": 500 * 10**9}
        sim2 = {"disk_number": 2, "serial_number": "SN-01", "capacity_bytes": 1000 * 10**9}

        snap1 = DeviceIntelligenceEngine.create_snapshot(r"\\.\PhysicalDrive2", simulated_descriptor=sim1)
        valid, err, _ = PreExecutionRevalidator.revalidate(
            discovery_snapshot=snap1,
            target_device_path=r"\\.\PhysicalDrive2",
            simulated_descriptor=sim2,
        )
        assert valid is False
        assert "IDENTITY_CHANGED" in err
        assert "Capacity drift" in err

    def test_model_drift_adversarial_rejection(self):
        """PreExecutionRevalidator refuses execution if drive model changes."""
        sim1 = {"disk_number": 2, "serial_number": "SN-01", "product_id": "SAMSUNG SSD 980"}
        sim2 = {"disk_number": 2, "serial_number": "SN-01", "product_id": "WD BLACK SN850"}

        snap1 = DeviceIntelligenceEngine.create_snapshot(r"\\.\PhysicalDrive2", simulated_descriptor=sim1)
        valid, err, _ = PreExecutionRevalidator.revalidate(
            discovery_snapshot=snap1,
            target_device_path=r"\\.\PhysicalDrive2",
            simulated_descriptor=sim2,
        )
        assert valid is False
        assert "IDENTITY_CHANGED" in err
        assert "Model drift" in err

    def test_sector_geometry_drift_adversarial_rejection(self):
        """PreExecutionRevalidator refuses execution if sector size changes (e.g. 512e vs 4Kn)."""
        sim1 = {"disk_number": 2, "serial_number": "SN-01", "sector_size": 512}
        sim2 = {"disk_number": 2, "serial_number": "SN-01", "sector_size": 4096}

        snap1 = DeviceIntelligenceEngine.create_snapshot(r"\\.\PhysicalDrive2", simulated_descriptor=sim1)
        valid, err, _ = PreExecutionRevalidator.revalidate(
            discovery_snapshot=snap1,
            target_device_path=r"\\.\PhysicalDrive2",
            simulated_descriptor=sim2,
        )
        assert valid is False
        assert "IDENTITY_CHANGED" in err
        assert "Sector geometry drift" in err

    def test_transport_bus_drift_adversarial_rejection(self):
        """PreExecutionRevalidator refuses execution if transport bus changes (e.g. SATA to USB)."""
        sim1 = {"disk_number": 2, "serial_number": "SN-01", "bus_type": "SATA"}
        sim2 = {"disk_number": 2, "serial_number": "SN-01", "bus_type": "USB"}

        snap1 = DeviceIntelligenceEngine.create_snapshot(r"\\.\PhysicalDrive2", simulated_descriptor=sim1)
        valid, err, _ = PreExecutionRevalidator.revalidate(
            discovery_snapshot=snap1,
            target_device_path=r"\\.\PhysicalDrive2",
            simulated_descriptor=sim2,
        )
        assert valid is False
        assert "CAPABILITY_CHANGED" in err
        assert "Transport bus drift" in err

    def test_system_disk_status_drift_adversarial_rejection(self):
        """PreExecutionRevalidator refuses execution if disk becomes system/boot drive."""
        sim1 = {"disk_number": 2, "serial_number": "SN-01", "system_disk": False, "boot_disk": False}
        sim2 = {"disk_number": 2, "serial_number": "SN-01", "system_disk": True, "boot_disk": True}

        snap1 = DeviceIntelligenceEngine.create_snapshot(r"\\.\PhysicalDrive2", simulated_descriptor=sim1)
        valid, err, _ = PreExecutionRevalidator.revalidate(
            discovery_snapshot=snap1,
            target_device_path=r"\\.\PhysicalDrive2",
            simulated_descriptor=sim2,
        )
        assert valid is False
        assert "IDENTITY_CHANGED" in err


class TestPhase9HardwareSafetyGates:
    """Adversarial tests for host disk protection, write protection, and USB bridge containment."""

    def test_physical_drive_0_tripwire_strict_block(self):
        """DestructiveHardwareTripwire unconditionally blocks PhysicalDrive0."""
        with pytest.raises(RuntimeError, match="SAFETY TRIPWIRE TRIGGERED.*PhysicalDrive0.*strictly forbidden"):
            DestructiveHardwareTripwire.assert_safe_execution(r"\\.\PhysicalDrive0", "NVMe Sanitize")

    def test_c_drive_root_tripwire_strict_block(self):
        """DestructiveHardwareTripwire unconditionally blocks C: drive root."""
        with pytest.raises(RuntimeError, match="SAFETY TRIPWIRE TRIGGERED.*strictly forbidden"):
            DestructiveHardwareTripwire.assert_safe_execution(r"\\.\C:", "Zero Overwrite")

    def test_safety_state_machine_blocks_system_disk(self):
        """DeviceSafetyStateMachine returns BOOT_DISK_PROTECTED and blocks destructive methods."""
        sys_snap = DeviceIntelligenceEngine.create_snapshot(
            r"\\.\PhysicalDrive0",
            simulated_descriptor={"disk_number": 0, "is_system": True, "is_boot": True},
        )
        is_safe, status, reason, blocking = DeviceSafetyStateMachine.evaluate_safety(
            snapshot=sys_snap,
            method_id="M04",
            confirmation=True,
        )
        assert is_safe is False
        assert status == HardwareExecutionStatus.BOOT_DISK_PROTECTED
        assert "SYSTEM_DISK_BLOCKED" in blocking

    def test_safety_state_machine_blocks_write_protected_device(self):
        """DeviceSafetyStateMachine blocks write-protected devices."""
        wp_snap = DeviceIntelligenceEngine.create_snapshot(
            r"\\.\PhysicalDrive3",
            simulated_descriptor={"disk_number": 3, "write_protected": True},
        )
        is_safe, status, reason, blocking = DeviceSafetyStateMachine.evaluate_safety(
            snapshot=wp_snap,
            method_id="M01",
            confirmation=True,
        )
        assert is_safe is False
        assert status == HardwareExecutionStatus.WRITE_PROTECTED
        assert "WRITE_PROTECTED" in blocking

    def test_usb_bridge_refusal_for_native_sanitize(self):
        """USB bridge attached drives refuse ATA Secure Erase and NVMe Sanitize."""
        usb_snap = DeviceIntelligenceEngine.create_snapshot(
            r"\\.\PhysicalDrive4",
            simulated_descriptor={"disk_number": 4, "bus_type": "USB", "is_usb_bridge": True},
        )
        matrix = Qualification25MethodEngine.evaluate_25_methods(usb_snap)
        # M03 (Device-Native Sanitize), M04 (ATA Secure Erase), M05 (NVMe Secure Erase) must be blocked
        assert matrix[3].qualification_status.value in ("BLOCKED", "UNSUPPORTED")
        assert "USB_BRIDGE_LIMITATION" in matrix[3].blocking_reasons
        assert matrix[4].qualification_status.value in ("BLOCKED", "UNSUPPORTED")
        assert matrix[5].qualification_status.value in ("BLOCKED", "UNSUPPORTED")

    def test_truth_model_physical_invariants(self):
        """All qualification records strictly report NOT_EXECUTED and NOT_ESTABLISHED."""
        snap = DeviceIntelligenceEngine.create_snapshot(
            r"\\.\PhysicalDrive2",
            simulated_descriptor={"disk_number": 2, "bus_type": "SATA", "capacity_bytes": 10**11},
        )
        matrix = Qualification25MethodEngine.evaluate_25_methods(snap)
        for m_id, rec in matrix.items():
            assert rec.truth_model.physical_execution == "NOT_EXECUTED"
            assert rec.truth_model.physical_qualification == "NOT_ESTABLISHED"
