"""DREX-V2 Physics-Based Shannon Entropy Verification Engine

Calculates Shannon entropy across sector buffers to provide cryptographic
and sanitization evidence signals.

Entropy Range:
- H = 0.000 bits/byte: Completely uniform constant buffer (e.g. all 0x00 or all 0xFF).
- H in [1.0, 5.5] bits/byte: Structured text, XML, source code, ASCII strings.
- H in [5.5, 7.5] bits/byte: Executables, uncompressed media, structured binary files.
- H in [7.95, 8.00] bits/byte: High-entropy CSPRNG random stream or AES-encrypted ciphertext.

Attribution:
- Shannon entropy formula adapted from SecureForge and devil-net (MIT License).
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import List, Optional, Tuple


@dataclass
class BlockEntropyResult:
    block_index: int
    offset: int
    size: int
    entropy: float
    is_uniform: bool
    is_high_entropy: bool


@dataclass
class EntropyEvaluation:
    mean_entropy: float
    min_entropy: float
    max_entropy: float
    total_blocks: int
    expected_pattern: str
    is_compliant: bool
    verdict: str
    evidence_notes: str


def calculate_shannon_entropy(data: bytes) -> float:
    """Calculate the Shannon entropy of a byte array in bits/byte [0.0, 8.0]."""
    if not data:
        return 0.0

    length = len(data)
    freq: dict[int, int] = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1

    entropy = 0.0
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)

    return round(entropy, 4)


def scan_entropy_blocks(data: bytes, block_size: int = 4096) -> List[BlockEntropyResult]:
    """Slice data into blocks and calculate per-block Shannon entropy."""
    results: List[BlockEntropyResult] = []
    if not data or block_size <= 0:
        return results

    num_blocks = (len(data) + block_size - 1) // block_size
    for i in range(num_blocks):
        offset = i * block_size
        chunk = data[offset:offset + block_size]
        ent = calculate_shannon_entropy(chunk)
        results.append(
            BlockEntropyResult(
                block_index=i,
                offset=offset,
                size=len(chunk),
                entropy=ent,
                is_uniform=ent < 0.01,
                is_high_entropy=ent >= 7.90,
            )
        )
    return results


def evaluate_sanitization_entropy(
    data: bytes,
    expected_pattern: str = "random",
    block_size: int = 4096,
) -> EntropyEvaluation:
    """Evaluate whether post-erasure readback buffer matches expected entropy profile.
    
    IMPORTANT: High entropy is an evidence signal of CSPRNG / cryptographic passes,
    not by itself standalone proof of physical sanitization.
    """
    blocks = scan_entropy_blocks(data, block_size=block_size)
    if not blocks:
        return EntropyEvaluation(
            mean_entropy=0.0,
            min_entropy=0.0,
            max_entropy=0.0,
            total_blocks=0,
            expected_pattern=expected_pattern,
            is_compliant=False,
            verdict="INCONCLUSIVE",
            evidence_notes="Empty data buffer provided for entropy evaluation.",
        )

    entropies = [b.entropy for b in blocks]
    mean_ent = sum(entropies) / len(entropies)
    min_ent = min(entropies)
    max_ent = max(entropies)

    is_compliant = False
    verdict = "FAILED"
    notes = ""

    if expected_pattern in ("zero", "0x00", "0xFF", "constant"):
        # Expect near-zero entropy across all blocks
        if max_ent < 0.05:
            is_compliant = True
            verdict = "PASSED"
            notes = f"Verified uniform constant pattern (Mean H = {mean_ent:.4f} b/B, Max H = {max_ent:.4f} b/B)."
        elif max_ent < 0.50:
            is_compliant = True
            verdict = "PASSED_WITH_WARNING"
            notes = f"Slight entropy residual observed (Mean H = {mean_ent:.4f} b/B, Max H = {max_ent:.4f} b/B)."
        else:
            verdict = "FAILED"
            notes = f"Expected zero/constant pattern but found non-uniform data (Max H = {max_ent:.4f} b/B)."

    elif expected_pattern in ("random", "csprng", "crypto"):
        # Expect high entropy (typically >= 7.90 b/B for 4KB blocks)
        if min_ent >= 7.90:
            is_compliant = True
            verdict = "PASSED"
            notes = f"Verified high-entropy CSPRNG random distribution (Mean H = {mean_ent:.4f} b/B, Min H = {min_ent:.4f} b/B)."
        elif mean_ent >= 7.70:
            is_compliant = True
            verdict = "PASSED_WITH_WARNING"
            notes = f"Acceptable entropy distribution with minor local variance (Mean H = {mean_ent:.4f} b/B, Min H = {min_ent:.4f} b/B)."
        else:
            verdict = "FAILED"
            notes = f"Expected CSPRNG random distribution but observed low entropy (Mean H = {mean_ent:.4f} b/B, Min H = {min_ent:.4f} b/B)."

    else:
        verdict = "INCONCLUSIVE"
        notes = f"Unknown expected pattern '{expected_pattern}'. Mean H = {mean_ent:.4f} b/B."

    return EntropyEvaluation(
        mean_entropy=round(mean_ent, 4),
        min_entropy=round(min_ent, 4),
        max_entropy=round(max_ent, 4),
        total_blocks=len(blocks),
        expected_pattern=expected_pattern,
        is_compliant=is_compliant,
        verdict=verdict,
        evidence_notes=notes,
    )
