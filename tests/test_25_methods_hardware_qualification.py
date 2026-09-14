"""Unit and Integration Tests for 25-Method Hardware Qualification Matrix (Phase 7)."""

import pytest
from hardware_storage import (
    DeviceIntelligenceEngine,
    Qualification25MethodEngine,
    MethodApplicability,
    QualificationStatus,
    MediaType,
    TransportBus,
)


def test_25_methods_matrix_completeness():
    """Verify evaluate_25_methods() returns exact 25 canonical method IDs M01-M25."""
    sim = {
        "disk_number": 1,
        "vendor_id": "WD",
        "product_id": "Black SN850X",
        "bus_type": "NVME",
        "capacity_bytes": 1000000000000,
        "is_ssd": True,
    }
    snap = DeviceIntelligenceEngine.create_snapshot(r"\\.\PhysicalDrive1", simulated_descriptor=sim)
    matrix = Qualification25MethodEngine.evaluate_25_methods(snap)

    assert len(matrix) == 25
    for m_id in range(1, 26):
        assert m_id in matrix
        rec = matrix[m_id]
        assert rec.method_id == m_id
        assert rec.canonical_name
        assert rec.category
        assert rec.truth_model.physical_execution == "NOT_EXECUTED"
        assert rec.truth_model.physical_qualification == "NOT_ESTABLISHED"


def test_nvme_fixture_qualification():
    """Verify NVMe fixture qualifies Method 05 (NVMe Secure Erase)."""
    sim = {"disk_number": 1, "bus_type": "NVME", "is_ssd": True}
    snap = DeviceIntelligenceEngine.create_snapshot(r"\\.\PhysicalDrive1", simulated_descriptor=sim)
    matrix = Qualification25MethodEngine.evaluate_25_methods(snap)

    m05 = matrix[5]
    assert m05.qualification_status == QualificationStatus.AVAILABLE
    assert "NVME_ADMIN_COMMAND_SUPPORT" in m05.detected_capabilities

    # M04 (ATA Secure Erase) must be NOT_APPLICABLE on NVMe
    m04 = matrix[4]
    assert m04.qualification_status == QualificationStatus.UNSUPPORTED
    assert m04.applicability == MethodApplicability.NOT_APPLICABLE


def test_usb_flash_fixture_qualification():
    """Verify USB flash fixture blocks M03, M04, M05 with USB_BRIDGE_LIMITATION while allowing M01, M07, M17-M25."""
    sim = {"disk_number": 3, "bus_type": "USB", "is_usb_bridge": True, "removable": True}
    snap = DeviceIntelligenceEngine.create_snapshot(r"\\.\PhysicalDrive3", simulated_descriptor=sim)
    matrix = Qualification25MethodEngine.evaluate_25_methods(snap)

    # Hardware methods blocked on USB
    assert matrix[3].qualification_status == QualificationStatus.BLOCKED
    assert "USB_BRIDGE_LIMITATION" in matrix[3].blocking_reasons
    assert matrix[4].qualification_status == QualificationStatus.BLOCKED
    assert "USB_BRIDGE_LIMITATION" in matrix[4].blocking_reasons
    assert matrix[5].qualification_status == QualificationStatus.BLOCKED
    assert "USB_BRIDGE_LIMITATION" in matrix[5].blocking_reasons

    # Policy & Overwrite methods available on USB
    assert matrix[1].qualification_status == QualificationStatus.AVAILABLE
    assert matrix[7].qualification_status == QualificationStatus.AVAILABLE

    # Recovery methods (M17-M25) available on USB
    for r_id in range(17, 26):
        assert matrix[r_id].qualification_status == QualificationStatus.AVAILABLE
        assert matrix[r_id].applicability == MethodApplicability.APPLICABLE


def test_system_disk_blocks_destructive_allows_recovery():
    """Verify system disk blocks M01-M16 but permits read-only recovery M17-M25."""
    sim = {"disk_number": 0, "system_disk": True, "boot_disk": True, "bus_type": "NVME"}
    snap = DeviceIntelligenceEngine.create_snapshot(r"\\.\PhysicalDrive0", simulated_descriptor=sim)
    matrix = Qualification25MethodEngine.evaluate_25_methods(snap)

    # Destructive methods 1-16 blocked
    for d_id in range(1, 17):
        assert matrix[d_id].qualification_status == QualificationStatus.BLOCKED
        assert "SYSTEM_DISK_BLOCKED" in matrix[d_id].blocking_reasons

    # Recovery methods 17-25 remain available
    for r_id in range(17, 26):
        assert matrix[r_id].qualification_status == QualificationStatus.AVAILABLE
