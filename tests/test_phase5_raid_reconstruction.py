"""Tests for DREX-V2 Phase 5 Virtual RAID Reconstruction Engine
============================================================
Validates RAID 0, 1, 5 (left-symmetric, dedicated-parity), and 10 reconstruction,
including bit-exact single-disk XOR parity reconstruction and streaming mode.
"""

import hashlib
import pytest
from pathlib import Path

from recovery_adapter import VirtualRaidReconstructor


class TestVirtualRaidReconstruction:
    """Validate deterministic algorithmic RAID reconstruction."""

    def test_raid0_reconstruction(self):
        # 2 disks with 16-byte chunks
        chunk = 16
        disk0 = b"A" * chunk + b"C" * chunk
        disk1 = b"B" * chunk + b"D" * chunk
        expected = b"A" * chunk + b"B" * chunk + b"C" * chunk + b"D" * chunk

        reconstructed = VirtualRaidReconstructor.reconstruct_raid0([disk0, disk1], chunk_size=chunk)
        assert reconstructed == expected

    def test_raid0_streaming_reconstruction(self, tmp_path):
        chunk = 16
        d0 = tmp_path / "disk0.raw"
        d1 = tmp_path / "disk1.raw"
        out = tmp_path / "array.raw"

        d0.write_bytes(b"A" * chunk + b"C" * chunk)
        d1.write_bytes(b"B" * chunk + b"D" * chunk)
        expected = b"A" * chunk + b"B" * chunk + b"C" * chunk + b"D" * chunk

        written = VirtualRaidReconstructor.reconstruct_raid0_stream([d0, d1], out, chunk_size=chunk)
        assert written == len(expected)
        assert out.read_bytes() == expected

    def test_raid1_reconstruction(self):
        disk0 = b"MIRRORED_PAYLOAD_DATA_0123456789"
        disk1 = b"MIRRORED_PAYLOAD_DATA_0123456789"
        assert VirtualRaidReconstructor.reconstruct_raid1([disk0, disk1]) == disk0

    def test_raid5_normal_left_symmetric(self):
        # 3 disks: 2 data disks + 1 rotating parity disk per stripe
        chunk = 8
        d0_stripe0 = b"DATA_000"
        d1_stripe0 = b"DATA_001"
        p_stripe0 = bytes(a ^ b for a, b in zip(d0_stripe0, d1_stripe0))

        d0_stripe1 = b"DATA_010"
        p_stripe1 = b"PARITY_1"  # rotating position
        d1_stripe1 = bytes(a ^ b for a, b in zip(d0_stripe1, p_stripe1))

        # Disk 0: data0, data0
        disk0 = d0_stripe0 + d0_stripe1
        # Disk 1: data1, parity1
        disk1 = d1_stripe0 + p_stripe1
        # Disk 2: parity0, data1
        disk2 = p_stripe0 + d1_stripe1

        reconstructed = VirtualRaidReconstructor.reconstruct_raid5(
            [disk0, disk1, disk2],
            chunk_size=chunk,
            layout="left-symmetric",
        )
        assert len(reconstructed) == chunk * 4  # 2 data chunks per stripe * 2 stripes = 32 bytes

    def test_raid5_degraded_xor_recovery_disk0(self):
        chunk = 16
        d0 = b"SECRET_PAYLOAD_0"
        d1 = b"SECRET_PAYLOAD_1"
        parity = bytes(a ^ b for a, b in zip(d0, d1))

        # Reconstruct degraded array where Disk 0 is missing (zeroed)
        disk0_offline = b"\x00" * chunk
        disk1 = d1
        disk2_parity = parity

        degraded = VirtualRaidReconstructor.reconstruct_raid5(
            [disk0_offline, disk1, disk2_parity],
            chunk_size=chunk,
            missing_idx=0,
            layout="dedicated-parity",
        )
        assert degraded == d0 + d1

    def test_raid5_degraded_xor_recovery_disk1(self):
        chunk = 16
        d0 = b"SECRET_PAYLOAD_0"
        d1 = b"SECRET_PAYLOAD_1"
        parity = bytes(a ^ b for a, b in zip(d0, d1))

        # Reconstruct degraded array where Disk 1 is missing
        disk0 = d0
        disk1_offline = b"\x00" * chunk
        disk2_parity = parity

        degraded = VirtualRaidReconstructor.reconstruct_raid5(
            [disk0, disk1_offline, disk2_parity],
            chunk_size=chunk,
            missing_idx=1,
            layout="dedicated-parity",
        )
        assert degraded == d0 + d1

    def test_raid5_streaming_reconstruction(self, tmp_path):
        chunk = 16
        d0 = tmp_path / "r5_disk0.raw"
        d1 = tmp_path / "r5_disk1.raw"
        p = tmp_path / "r5_parity.raw"
        out = tmp_path / "r5_reconstructed.raw"

        data0 = b"STRIPE_0_DATA_A_" + b"STRIPE_1_DATA_A_"
        data1 = b"STRIPE_0_DATA_B_" + b"STRIPE_1_DATA_B_"
        parity_bytes = bytes(a ^ b for a, b in zip(data0, data1))

        d0.write_bytes(data0)
        d1.write_bytes(data1)
        p.write_bytes(parity_bytes)

        # Degraded streaming reconstruction with disk 0 missing
        written = VirtualRaidReconstructor.reconstruct_raid5_stream(
            [d0, d1, p],
            out,
            chunk_size=chunk,
            missing_idx=0,
            layout="dedicated-parity",
        )

        expected = b"STRIPE_0_DATA_A_STRIPE_0_DATA_B_STRIPE_1_DATA_A_STRIPE_1_DATA_B_"
        assert written == len(expected)
        assert out.read_bytes() == expected

    def test_raid10_reconstruction(self):
        chunk = 16
        m0_a = b"A" * chunk
        m0_b = b"A" * chunk  # mirror 0
        m1_a = b"B" * chunk
        m1_b = b"B" * chunk  # mirror 1

        reconstructed = VirtualRaidReconstructor.reconstruct_raid10(
            [m0_a, m0_b, m1_a, m1_b],
            chunk_size=chunk,
        )
        assert reconstructed == b"A" * chunk + b"B" * chunk

    def test_unsupported_raid_layout_rejected(self):
        with pytest.raises(ValueError, match="Unsupported RAID5 layout"):
            VirtualRaidReconstructor.reconstruct_raid5(
                [b"A" * 16, b"B" * 16, b"C" * 16],
                chunk_size=16,
                layout="unknown-exotic-parity",
            )
