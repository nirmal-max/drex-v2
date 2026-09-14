"""Unit and Integration Tests for DREX-V2 Device Intelligence Discovery (Phase 7)."""

import pytest
from hardware_storage import (
    DeviceIntelligenceEngine,
    DeviceIdentitySnapshot,
    HardwareFact,
    PropertySource,
    TransportBus,
    UnderlyingInterface,
    MediaType,
)


def test_synthetic_device_discovery_parsing():
    """Verify synthetic descriptor parsing and HardwareFact provenance tracking."""
    sim = {
        "disk_number": 2,
        "vendor_id": "Samsung",
        "product_id": "SSD 980 PRO 1TB",
        "serial_number": "S5GXNF0R123456",
        "firmware_revision": "5B2QGXA7",
        "capacity_bytes": 1000204886016,
        "sector_size": 512,
        "physical_sector_size": 512,
        "bus_type": "NVME",
        "is_ssd": True,
        "removable": False,
        "write_protected": False,
    }

    snap = DeviceIntelligenceEngine.create_snapshot(r"\\.\PhysicalDrive2", simulated_descriptor=sim)

    assert snap.physical_drive_index.value == 2
    assert snap.vendor_id.value == "Samsung"
    assert snap.product_id_model.value == "SSD 980 PRO 1TB"
    assert snap.serial_number.value == "S5GXNF0R123456"
    assert snap.capacity_bytes.value == 1000204886016
    assert snap.transport_bus.value == TransportBus.NVME
    assert snap.underlying_interface.value == UnderlyingInterface.NATIVE_NVME
    assert snap.media_type.value == MediaType.NVME_SSD
    assert snap.physical_drive_index.source == PropertySource.SYNTHETIC_TEST_DESCRIPTOR
    assert snap.physical_drive_index.confidence == "SYNTHETIC"


def test_bus_type_mapping():
    """Verify Windows STORAGE_BUS_TYPE mapping to TransportBus enum."""
    assert DeviceIntelligenceEngine.map_bus_type(0x11) == TransportBus.NVME
    assert DeviceIntelligenceEngine.map_bus_type(0x0B) == TransportBus.SATA
    assert DeviceIntelligenceEngine.map_bus_type(0x07) == TransportBus.USB
    assert DeviceIntelligenceEngine.map_bus_type(0x01) == TransportBus.SCSI
    assert DeviceIntelligenceEngine.map_bus_type(0x0A) == TransportBus.SAS
    assert DeviceIntelligenceEngine.map_bus_type(0x0E) == TransportBus.VIRTUAL
    assert DeviceIntelligenceEngine.map_bus_type(0x99) == TransportBus.UNKNOWN


def test_transport_and_underlying_interface_decoupling():
    """Verify USB bridge layered interface decoupling."""
    # USB External NVMe Enclosure
    sim_usb_nvme = {
        "disk_number": 3,
        "bus_type": "USB-NVME",
        "is_usb_bridge": True,
        "removable": True,
    }
    snap_un = DeviceIntelligenceEngine.create_snapshot(r"\\.\PhysicalDrive3", simulated_descriptor=sim_usb_nvme)
    assert snap_un.transport_bus.value == TransportBus.USB
    assert snap_un.underlying_interface.value == UnderlyingInterface.USB_BRIDGE_NVME
    assert snap_un.is_usb_bridge.value is True

    # Native NVMe M.2
    sim_native = {
        "disk_number": 1,
        "bus_type": "NVME",
        "removable": False,
    }
    snap_native = DeviceIntelligenceEngine.create_snapshot(r"\\.\PhysicalDrive1", simulated_descriptor=sim_native)
    assert snap_native.transport_bus.value == TransportBus.NVME
    assert snap_native.underlying_interface.value == UnderlyingInterface.NATIVE_NVME
    assert snap_native.is_usb_bridge.value is False


def test_system_and_boot_disk_detection():
    """Verify system drive path matching."""
    assert DeviceIntelligenceEngine.is_system_drive(r"\\.\PhysicalDrive0", 0) is True
    assert DeviceIntelligenceEngine.is_system_drive(r"\\.\C:") is True
    assert DeviceIntelligenceEngine.is_system_drive("C:") is True
    assert DeviceIntelligenceEngine.is_system_drive("C:\\") is True
    assert DeviceIntelligenceEngine.is_system_drive(r"\\.\PhysicalDrive1", 1) is False
    assert DeviceIntelligenceEngine.is_system_drive(r"\\.\E:") is False
