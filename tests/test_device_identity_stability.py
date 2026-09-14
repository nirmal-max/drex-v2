"""Unit and Integration Tests for Device Identity Stability and TOCTOU Guard (Phase 7)."""

import pytest
from hardware_storage import (
    DeviceIntelligenceEngine,
    PreExecutionRevalidator,
)


def test_identical_snapshot_revalidation_accepted():
    """Verify that identical pre-execution snapshot passes revalidation."""
    sim = {
        "disk_number": 2,
        "serial_number": "SN-SAMSUNG-980-001",
        "product_id": "SSD 980 PRO",
        "capacity_bytes": 1000204886016,
        "sector_size": 512,
        "bus_type": "NVME",
    }
    snap_discovery = DeviceIntelligenceEngine.create_snapshot(r"\\.\PhysicalDrive2", simulated_descriptor=sim)

    is_valid, err, current = PreExecutionRevalidator.revalidate(
        discovery_snapshot=snap_discovery,
        target_device_path=r"\\.\PhysicalDrive2",
        simulated_descriptor=sim,
    )
    assert is_valid is True
    assert err is None


def test_serial_drift_rejection():
    """Verify that serial number change triggers IDENTITY_CHANGED refusal."""
    sim1 = {"disk_number": 2, "serial_number": "ORIGINAL-SN-001", "product_id": "SSD 980"}
    sim2 = {"disk_number": 2, "serial_number": "SUBSTITUTED-SN-999", "product_id": "SSD 980"}

    snap_discovery = DeviceIntelligenceEngine.create_snapshot(r"\\.\PhysicalDrive2", simulated_descriptor=sim1)

    is_valid, err, current = PreExecutionRevalidator.revalidate(
        discovery_snapshot=snap_discovery,
        target_device_path=r"\\.\PhysicalDrive2",
        simulated_descriptor=sim2,
    )
    assert is_valid is False
    assert "IDENTITY_CHANGED" in err
    assert "Serial drift" in err


def test_capacity_drift_rejection():
    """Verify that capacity change triggers IDENTITY_CHANGED refusal."""
    sim1 = {"disk_number": 2, "serial_number": "SN-001", "capacity_bytes": 500000000000}
    sim2 = {"disk_number": 2, "serial_number": "SN-001", "capacity_bytes": 1000000000000}

    snap_discovery = DeviceIntelligenceEngine.create_snapshot(r"\\.\PhysicalDrive2", simulated_descriptor=sim1)

    is_valid, err, current = PreExecutionRevalidator.revalidate(
        discovery_snapshot=snap_discovery,
        target_device_path=r"\\.\PhysicalDrive2",
        simulated_descriptor=sim2,
    )
    assert is_valid is False
    assert "IDENTITY_CHANGED" in err
    assert "Capacity drift" in err


def test_bus_drift_rejection():
    """Verify that transport bus change triggers CAPABILITY_CHANGED refusal."""
    sim1 = {"disk_number": 2, "serial_number": "SN-001", "bus_type": "NVME"}
    sim2 = {"disk_number": 2, "serial_number": "SN-001", "bus_type": "USB"}

    snap_discovery = DeviceIntelligenceEngine.create_snapshot(r"\\.\PhysicalDrive2", simulated_descriptor=sim1)

    is_valid, err, current = PreExecutionRevalidator.revalidate(
        discovery_snapshot=snap_discovery,
        target_device_path=r"\\.\PhysicalDrive2",
        simulated_descriptor=sim2,
    )
    assert is_valid is False
    assert "CAPABILITY_CHANGED" in err
