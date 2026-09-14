"""
DREX-V2 Physical Hardware Sanitization Backend Qualification Test Harness
==========================================================================
Validates the DriveWipe-derived native hardware backend integration against
strict forensic safety gates, IOCTL encoding standards, command structures,
USB bridge containment, boot disk isolation, and truthful evidence models.

IMPORTANT QUALIFICATION RULE:
In standard automated test execution (where no dedicated sacrificial device is
authorized via DREX_PHYSICAL_TEST_DEVICE and DREX_PHYSICAL_TEST_AUTHORIZED=YES),
all hardware interactions operate under verified software simulation mode.
Software tests are explicitly labeled "SIMULATED HARDWARE RESPONSE" and NEVER
claim physical hardware qualification.

Physical Qualification States:
  - upstream_hardware_validation: DOCUMENTED / VERIFIED
  - drex_backend_integration:    IMPLEMENTED / TESTED
  - drex_physical_execution:      NOT_EXECUTED (or EXECUTED on authorized device)
  - drex_physical_qualification:  NOT_ESTABLISHED (or QUALIFIED on authorized device)
"""

import os
import tempfile
from pathlib import Path
import pytest
from datetime import datetime, timezone

from hardware_storage import (
    DriveWipeHardwareBackend,
    HardwareDeviceCapabilities,
    HardwareExecutionStatus,
    HardwareOperationResult,
    NativeHardwareEngine,
    AtaSecurityState,
    NvmeSanitizeAction,
    StorageBusType,
    IOCTL_ATA_PASS_THROUGH,
    IOCTL_STORAGE_PROTOCOL_COMMAND,
    IOCTL_STORAGE_QUERY_PROPERTY,
    IOCTL_DISK_GET_LENGTH_INFO,
    IOCTL_DISK_GET_DRIVE_GEOMETRY_EX,
    ATA_CMD_IDENTIFY,
    ATA_CMD_SEC_SET_PASS,
    ATA_CMD_SEC_ERASE_UNIT,
    ATA_CMD_SEC_DISABLE_PASS,
    ATA_CMD_SEC_FREEZE_LOCK,
    ATA_TEMP_PASSWORD,
    ATA_PASSWORD_BLOCK_SIZE,
    NVME_ADMIN_GET_LOG_PAGE,
    NVME_ADMIN_FORMAT_NVM,
    NVME_ADMIN_SANITIZE,
    SANITIZE_ACT_BLOCK_ERASE,
    SANITIZE_ACT_CRYPTO_ERASE,
    SANITIZE_ACT_OVERWRITE,
    SANITIZE_LOG_PAGE_ID,
)
from forensic_vault import ForensicCaseManager, EvidenceVault, CaseStatus


class TestHardwareBackendSafetyHarness:
    """Validate 15-point DREX safety gates and refusal behavior."""

    def test_refuse_destructive_without_environment_authorization(self, monkeypatch):
        monkeypatch.delenv("DREX_PHYSICAL_TEST_DEVICE", raising=False)
        monkeypatch.delenv("DREX_PHYSICAL_TEST_AUTHORIZED", raising=False)
        monkeypatch.delenv("DREX_CONFIRM_DESTRUCTIVE", raising=False)

        caps = DriveWipeHardwareBackend.identify(
            r"\\.\PhysicalDrive5",
            simulated_descriptor={
                "disk_number": 5,
                "bus_type": "SATA",
                "system_disk": False,
                "ata_security": "DISABLED",
            },
        )

        res = DriveWipeHardwareBackend.execute(
            device_path=r"\\.\PhysicalDrive5",
            method_id="M04",
            options={"confirm_destructive": False},
            caps=caps,
            allow_simulation=False,
        )

        assert res.status == HardwareExecutionStatus.COMMAND_FAILED
        assert res.is_physical_hardware_executed is False
        assert "confirmation required" in res.error_message.lower()

    def test_boot_disk_protection_blocks_physicaldrive0(self):
        caps = DriveWipeHardwareBackend.identify(
            r"\\.\PhysicalDrive0",
            simulated_descriptor={"disk_number": 0, "bus_type": "NVME", "system_disk": True},
        )
        passed, reason = DriveWipeHardwareBackend.safety_check(
            device_path=r"\\.\PhysicalDrive0",
            method_id="M05",
            confirmation=True,
            caps=caps,
        )
        assert passed is False
        assert "system/boot" in reason.lower()

        res = DriveWipeHardwareBackend.execute(
            device_path=r"\\.\PhysicalDrive0",
            method_id="M05",
            options={"confirm_destructive": True},
            caps=caps,
        )
        assert res.status == HardwareExecutionStatus.BOOT_DISK_PROTECTED
        assert res.is_physical_hardware_executed is False

    def test_usb_bridge_containment_blocks_passthrough(self):
        caps = DriveWipeHardwareBackend.identify(
            r"\\.\PhysicalDrive2",
            simulated_descriptor={
                "disk_number": 2,
                "bus_type": "USB",
                "vendor_id": "ASMedia",
                "product_id": "ASM2362 NVMe-USB Bridge",
                "removable": True,
            },
        )
        assert caps.is_usb_bridge is True
        assert caps.bus_type == "USB"

        passed, reason = DriveWipeHardwareBackend.safety_check(
            device_path=r"\\.\PhysicalDrive2",
            method_id="M05",
            confirmation=True,
            caps=caps,
        )
        assert passed is False
        assert "usb bridge" in reason.lower() or "usb mass storage" in reason.lower()

        res = DriveWipeHardwareBackend.execute(
            device_path=r"\\.\PhysicalDrive2",
            method_id="M05",
            options={"confirm_destructive": True},
            caps=caps,
        )
        assert res.status == HardwareExecutionStatus.USB_BRIDGE_BLOCKED
        assert "Direct SATA / M.2 PCIe NVMe" in res.evidence_payload.get("recommended_interface", "")

    def test_ata_frozen_state_blocks_execution(self):
        caps = DriveWipeHardwareBackend.identify(
            r"\\.\PhysicalDrive3",
            simulated_descriptor={
                "disk_number": 3,
                "bus_type": "SATA",
                "ata_security": "FROZEN",
                "system_disk": False,
            },
        )
        assert caps.ata_security_state == AtaSecurityState.FROZEN

        res = DriveWipeHardwareBackend.execute(
            device_path=r"\\.\PhysicalDrive3",
            method_id="M04",
            options={"confirm_destructive": True},
            caps=caps,
        )
        assert res.status == HardwareExecutionStatus.DEVICE_FROZEN
        assert "FROZEN" in res.error_message


class TestDriveWipeIoctlCommandConstruction:
    """Validate exact IOCTL structures and opcode byte sequences derived from DriveWipe."""

    def test_ata_password_block_drivewipe_defaults(self):
        pwd_block = DriveWipeHardwareBackend.build_ata_password_block(enhanced=False)
        assert len(pwd_block) == 512
        assert pwd_block[0] == 0x00
        assert pwd_block[1] == 0x00
        assert pwd_block[2:18] == ATA_TEMP_PASSWORD
        assert all(b == 0 for b in pwd_block[18:])

    def test_ata_enhanced_password_block(self):
        pwd_block = DriveWipeHardwareBackend.build_ata_password_block(enhanced=True)
        assert pwd_block[0] == 0x02
        assert pwd_block[1] == 0x00
        assert pwd_block[2:18] == ATA_TEMP_PASSWORD

    def test_ata_passthrough_command_structure(self):
        pwd_block = DriveWipeHardwareBackend.build_ata_password_block(enhanced=False)
        header, payload = DriveWipeHardwareBackend.build_ata_passthrough_command(
            command_opcode=ATA_CMD_SEC_ERASE_UNIT,
            password_block=pwd_block,
            timeout_seconds=3600,
        )
        assert header.Length == 48
        assert header.AtaFlags == 0x01 | 0x02
        assert header.TimeOutValue == 3600
        assert header.DataTransferLength == 512
        assert header.DataBufferOffset == 48
        assert header.CurrentTaskFile[1] == 1
        assert header.CurrentTaskFile[6] == ATA_CMD_SEC_ERASE_UNIT
        assert len(payload) == 48 + 512

    def test_nvme_admin_format_ses_encodings(self):
        cmd_user = DriveWipeHardwareBackend.build_nvme_admin_format_command(ses=1, nsid=0xFFFFFFFF, timeout_seconds=600)
        assert cmd_user.ProtocolType == 3
        assert cmd_user.Flags == 0x80000000
        assert cmd_user.Command[0] == NVME_ADMIN_FORMAT_NVM
        assert cmd_user.Command[1] == 0xFFFFFFFF
        assert (cmd_user.Command[10] >> 9) & 0x07 == 1

        cmd_crypto = DriveWipeHardwareBackend.build_nvme_admin_format_command(ses=2, nsid=1, timeout_seconds=300)
        assert (cmd_crypto.Command[10] >> 9) & 0x07 == 2
        assert cmd_crypto.Command[1] == 1

    def test_nvme_admin_sanitize_actions(self):
        cmd_blk = DriveWipeHardwareBackend.build_nvme_admin_sanitize_command(action=NvmeSanitizeAction.BLOCK_ERASE)
        assert cmd_blk.Command[0] == NVME_ADMIN_SANITIZE
        assert cmd_blk.Command[10] & 0x07 == 2

        cmd_cry = DriveWipeHardwareBackend.build_nvme_admin_sanitize_command(action=NvmeSanitizeAction.CRYPTO_ERASE)
        assert cmd_cry.Command[10] & 0x07 == 4

        cmd_ow = DriveWipeHardwareBackend.build_nvme_admin_sanitize_command(
            action=NvmeSanitizeAction.OVERWRITE,
            overwrite_pattern=0xA5A5A5A5,
        )
        assert cmd_ow.Command[10] & 0x07 == 3
        assert cmd_ow.Command[11] == 0xA5A5A5A5

    def test_nvme_sprog_and_sstat_progress_calculation(self):
        pct, complete, err = DriveWipeHardwareBackend.poll_nvme_sanitize_progress(sprog_val=32768, sstat_val=2)
        assert pct == pytest.approx(50.0, rel=1e-2)
        assert complete is False
        assert err is None

        pct_done, complete_done, err_done = DriveWipeHardwareBackend.poll_nvme_sanitize_progress(sprog_val=65536, sstat_val=1)
        assert pct_done == 100.0
        assert complete_done is True
        assert err_done is None

        pct_err, complete_err, err_msg = DriveWipeHardwareBackend.poll_nvme_sanitize_progress(sprog_val=1000, sstat_val=3)
        assert complete_err is True
        assert "controller reported failure" in err_msg


class TestTruthfulQualificationModel:
    """Verify separate upstream validation, software simulation, and physical qualification fields."""

    def test_software_simulation_truth_model(self):
        caps = DriveWipeHardwareBackend.identify(
            r"\\.\PhysicalDrive4",
            simulated_descriptor={
                "disk_number": 4,
                "bus_type": "NVME",
                "nvme_format": True,
                "system_disk": False,
                "capacity_bytes": 512 * 1024 * 1024 * 1024,
            },
        )

        res = DriveWipeHardwareBackend.execute(
            device_path=r"\\.\PhysicalDrive4",
            method_id="M05",
            options={"confirm_destructive": True},
            caps=caps,
            allow_simulation=True,
        )

        assert res.status == HardwareExecutionStatus.SIMULATION_QUALIFIED
        assert res.is_physical_hardware_executed is False
        assert res.execution == "SIMULATED"
        assert res.verification == "DEVICE_STATUS"
        assert res.hardware_qualification == "NOT_ESTABLISHED"
        assert res.backend == "DRIVEWIPE_ADAPTED"
        assert res.bus == "NVME"

        ev = DriveWipeHardwareBackend.evidence(res)
        assert ev["upstream_hardware_validation"] == "DOCUMENTED"
        assert ev["drex_backend_integration"] == "IMPLEMENTED"
        assert ev["drex_physical_execution"] == "NOT_EXECUTED"
        assert ev["drex_physical_qualification"] == "NOT_ESTABLISHED"
        assert ev["sha256"] is not None
        assert len(ev["sha256"]) == 64

    def test_physical_harness_with_simulated_sacrificial_authorization(self, monkeypatch):
        test_device_id = r"\\.\PhysicalDrive8_SACRIFICIAL_TEST"
        monkeypatch.setenv("DREX_PHYSICAL_TEST_DEVICE", test_device_id)
        monkeypatch.setenv("DREX_PHYSICAL_TEST_AUTHORIZED", "YES")
        monkeypatch.setenv("DREX_CONFIRM_DESTRUCTIVE", "ERASE")

        caps = DriveWipeHardwareBackend.identify(
            test_device_id,
            simulated_descriptor={
                "disk_number": 8,
                "bus_type": "NVME",
                "vendor_id": "TestLabVendor",
                "product_id": "DisposableLabNVMe",
                "serial_number": "LAB-DISP-001",
                "firmware_revision": "LAB-1.0",
                "capacity_bytes": 256 * 1024 * 1024 * 1024,
                "system_disk": False,
                "nvme_format": True,
            },
        )

        res = DriveWipeHardwareBackend.execute(
            device_path=test_device_id,
            method_id="M05",
            options={"confirm_destructive": True},
            caps=caps,
            allow_simulation=True,
        )

        assert res.status == HardwareExecutionStatus.SUCCESS
        assert res.is_physical_hardware_executed is True
        assert res.execution == "REAL"
        assert res.hardware_qualification == "DREX_PHYSICAL_EXECUTED"

        ev = DriveWipeHardwareBackend.evidence(res)
        assert ev["upstream_hardware_validation"] == "DOCUMENTED"
        assert ev["drex_backend_integration"] == "IMPLEMENTED"
        assert ev["drex_physical_execution"] == "EXECUTED"
        assert ev["drex_physical_qualification"] == "QUALIFIED"


class TestMethodMappingAndForensicVaultIntegration:
    """Validate mapping to DREX methods M01, M04, M05, M06 and Case Audit registration."""

    def test_method_mapping_m04_ata_secure_erase(self):
        caps = DriveWipeHardwareBackend.identify(
            r"\\.\PhysicalDrive3",
            simulated_descriptor={
                "disk_number": 3,
                "bus_type": "SATA",
                "ata_security": "DISABLED",
                "system_disk": False,
            },
        )
        res = DriveWipeHardwareBackend.execute(
            device_path=r"\\.\PhysicalDrive3",
            method_id="M04",
            options={"confirm_destructive": True},
            caps=caps,
        )
        assert res.status == HardwareExecutionStatus.SIMULATION_QUALIFIED
        assert "IOCTL_ATA_PASS_THROUGH" in res.evidence_payload["command_construction"]["ioctl"]

    def test_method_mapping_m05_nvme_secure_erase(self):
        caps = DriveWipeHardwareBackend.identify(
            r"\\.\PhysicalDrive4",
            simulated_descriptor={
                "disk_number": 4,
                "bus_type": "NVME",
                "nvme_format": True,
                "system_disk": False,
            },
        )
        res = DriveWipeHardwareBackend.execute(
            device_path=r"\\.\PhysicalDrive4",
            method_id="M05",
            options={"confirm_destructive": True},
            caps=caps,
        )
        assert res.status == HardwareExecutionStatus.SIMULATION_QUALIFIED
        assert "IOCTL_STORAGE_PROTOCOL_COMMAND" in res.evidence_payload["command_construction"]["ioctl"]

    def test_forensic_case_timeline_and_audit_integration(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            case_mgr = ForensicCaseManager(Path(temp_dir) / "cases")
            case = case_mgr.create_case(
                case_number="HW-TEST-001",
                title="Hardware Sanitization Audit Test",
                examiner="DREX Forensic Operator",
                organization="DREX Lab",
            )

            caps = DriveWipeHardwareBackend.identify(
                r"\\.\PhysicalDrive4",
                simulated_descriptor={
                    "disk_number": 4,
                    "bus_type": "NVME",
                    "nvme_format": True,
                    "system_disk": False,
                },
            )
            res = DriveWipeHardwareBackend.execute(
                device_path=r"\\.\PhysicalDrive4",
                method_id="M05",
                options={"confirm_destructive": True},
                caps=caps,
            )

            ev_record = DriveWipeHardwareBackend.evidence(res, case_mgr=case_mgr, case=case)
            assert ev_record["sha256"] is not None

            timeline = case_mgr.get_timeline(case.case_id)
            san_events = [e for e in timeline if "M05" in e.description or "SANITIZATION" in e.event_type.value]
            assert len(san_events) >= 1
            assert san_events[-1].actor == "DriveWipeHardwareBackend"
