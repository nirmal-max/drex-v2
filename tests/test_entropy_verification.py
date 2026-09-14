"""Unit and Integration Tests for DREX-V2 Shannon Entropy Verification Engine (Phase 6 Track E)."""

import os
import secrets
import pytest

from entropy_engine import (
    calculate_shannon_entropy,
    evaluate_sanitization_entropy,
    generate_entropy_heatmap,
    scan_entropy_blocks,
)


def test_entropy_zero_buffer():
    """Verify zero-filled buffer has Shannon entropy H = 0.0000."""
    zero_buf = b"\x00" * 8192
    ent = calculate_shannon_entropy(zero_buf)
    assert ent == 0.0


def test_entropy_constant_byte():
    """Verify constant byte buffer has Shannon entropy H = 0.0000."""
    const_buf = b"\xFF" * 8192
    ent = calculate_shannon_entropy(const_buf)
    assert ent == 0.0


def test_entropy_csprng_random_stream():
    """Verify CSPRNG stream achieves high entropy H > 7.90 for 4KB blocks."""
    rnd_buf = secrets.token_bytes(8192)
    ent = calculate_shannon_entropy(rnd_buf)
    assert ent >= 7.90


def test_evaluate_sanitization_entropy_zero_profile():
    """Verify sanitization evaluation with 'zero' profile passes on 0x00 bytes."""
    zero_buf = b"\x00" * 16384
    eval_res = evaluate_sanitization_entropy(zero_buf, expected_pattern="zero")

    assert eval_res.is_compliant is True
    assert eval_res.verdict == "PASSED"
    assert eval_res.max_entropy < 0.05


def test_evaluate_sanitization_entropy_random_profile():
    """Verify sanitization evaluation with 'random' profile passes on CSPRNG bytes."""
    rnd_buf = secrets.token_bytes(16384)
    eval_res = evaluate_sanitization_entropy(rnd_buf, expected_pattern="random")

    assert eval_res.is_compliant is True
    assert eval_res.verdict == "PASSED"
    assert eval_res.mean_entropy >= 7.90


def test_generate_entropy_heatmap():
    """Verify windowed entropy heatmap returns correct window count and distribution."""
    # Create mixed data: 4KB zero + 4KB random
    mixed = (b"\x00" * 4096) + secrets.token_bytes(4096)
    heatmap = generate_entropy_heatmap(mixed, window_size=4096, step_size=4096)

    assert len(heatmap["windows"]) == 2
    assert heatmap["windows"][0]["entropy"] == 0.0
    assert heatmap["windows"][1]["entropy"] >= 7.90
    assert heatmap["uniform_ratio"] == 0.5
    assert heatmap["high_entropy_ratio"] == 0.5
