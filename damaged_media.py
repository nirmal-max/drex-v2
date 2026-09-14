"""DREX-V2 Clean-Room Damaged Media Mapfile Engine & Parser
=========================================================
Implements a strict, clean-room parser and serializer for the public GNU ddrescue
mapfile specification (v1.28 standard).

Mapfile Block Status Tokens:
  - '?' : NON_TRIED     (Unattempted sector ranges)
  - '*' : NON_TRIMMED   (Areas bordering error sectors before trimming)
  - '/' : NON_SCRAPED   (Trimmed bad areas before single-sector scraping)
  - '-' : BAD_SECTOR    (Hardware read error / bad sector)
  - '+' : FINISHED      (Rescued intact data)

Licensing & Attribution:
  - This module is an independent clean-room specification implementation.
  - Zero GNU GPL source code is copied into this module.
  - Public file format specification reference: GNU ddrescue manual (Antonio Diaz Diaz).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


class MapBlockStatus(str, Enum):
    NON_TRIED = "?"
    NON_TRIMMED = "*"
    NON_SCRAPED = "/"
    BAD_SECTOR = "-"
    FINISHED = "+"

    @classmethod
    def from_token(cls, token: str) -> MapBlockStatus:
        t = token.strip()
        for item in cls:
            if item.value == t:
                return item
        if t in ("0x00", "0", "00", "?"):
            return cls.NON_TRIED
        elif t in ("0x01", "1", "01", "+"):
            return cls.FINISHED
        elif t in ("0x02", "2", "-"):
            return cls.BAD_SECTOR
        elif t in ("0x03", "3", "*"):
            return cls.NON_TRIMMED
        elif t in ("0x04", "4", "/"):
            return cls.NON_SCRAPED
        raise ValueError(f"Invalid ddrescue mapfile status token: {token!r}")


@dataclass
class MapfileBlock:
    """A contiguous block in a ddrescue mapfile."""
    pos: int
    size: int
    status: MapBlockStatus

    @property
    def end(self) -> int:
        return self.pos + self.size

    def to_line(self) -> str:
        return f"0x{self.pos:08X}  0x{self.size:08X}  {self.status.value}"


@dataclass
class DdrescueMapfile:
    """In-memory representation of a GNU ddrescue mapfile."""
    current_pos: int = 0
    current_status: MapBlockStatus = MapBlockStatus.NON_TRIED
    current_pass: int = 1
    blocks: List[MapfileBlock] = field(default_factory=list)
    source_uri: str = ""
    destination_uri: str = ""
    comment_headers: List[str] = field(default_factory=list)

    @property
    def total_size(self) -> int:
        if not self.blocks:
            return 0
        return max(b.end for b in self.blocks)

    @property
    def rescued_bytes(self) -> int:
        return sum(b.size for b in self.blocks if b.status == MapBlockStatus.FINISHED)

    @property
    def bad_bytes(self) -> int:
        return sum(b.size for b in self.blocks if b.status == MapBlockStatus.BAD_SECTOR)

    @property
    def non_tried_bytes(self) -> int:
        return sum(b.size for b in self.blocks if b.status == MapBlockStatus.NON_TRIED)

    @property
    def non_trimmed_bytes(self) -> int:
        return sum(b.size for b in self.blocks if b.status == MapBlockStatus.NON_TRIMMED)

    @property
    def non_scraped_bytes(self) -> int:
        return sum(b.size for b in self.blocks if b.status == MapBlockStatus.NON_SCRAPED)

    @property
    def is_complete(self) -> bool:
        """Returns True if there are no non-tried, non-trimmed, or non-scraped blocks."""
        return (self.non_tried_bytes == 0 and self.non_trimmed_bytes == 0 and self.non_scraped_bytes == 0)

    @property
    def rescued_ratio(self) -> float:
        tot = self.total_size
        return (self.rescued_bytes / tot) if tot > 0 else 0.0

    def compute_sha256(self) -> str:
        """Computes deterministic SHA-256 hash of the canonical mapfile serialization."""
        return hashlib.sha256(self.to_mapfile_text().encode("utf-8")).hexdigest()

    def summary_stats(self) -> Dict[str, Any]:
        tot = self.total_size
        return {
            "total_bytes": tot,
            "rescued_bytes": self.rescued_bytes,
            "bad_bytes": self.bad_bytes,
            "non_tried_bytes": self.non_tried_bytes,
            "non_trimmed_bytes": self.non_trimmed_bytes,
            "non_scraped_bytes": self.non_scraped_bytes,
            "rescued_ratio": self.rescued_ratio,
            "rescued_percent": round(self.rescued_ratio * 100.0, 2),
            "is_complete": self.is_complete,
            "block_count": len(self.blocks),
            "current_pos": self.current_pos,
            "current_pass": self.current_pass,
            "sha256": self.compute_sha256(),
        }

    def validate_integrity(self) -> List[str]:
        """Validates that block offsets are strictly monotonically increasing without gaps or overlaps."""
        issues: List[str] = []
        if not self.blocks:
            return issues

        last_end = 0
        for i, b in enumerate(self.blocks):
            if b.size <= 0:
                issues.append(f"Block {i} has invalid non-positive size {b.size}")
            if b.pos < last_end:
                issues.append(f"Block {i} overlaps previous block: pos 0x{b.pos:X} < last_end 0x{last_end:X}")
            elif b.pos > last_end and i > 0:
                issues.append(f"Block {i} has gap: pos 0x{b.pos:X} > last_end 0x{last_end:X}")
            last_end = b.end
        return issues

    def to_mapfile_text(self) -> str:
        """Serializes the in-memory mapfile to standard GNU ddrescue text representation."""
        lines = [
            "# Mapfile generated / maintained by DREX-V2 Damaged Media Engine",
            "# Current_status ?",
            "# pos_current   status",
            f"0x{self.current_pos:08X}     {self.current_status.value}",
            "# current_pass   current_status",
            f"{self.current_pass}               {self.current_status.value}",
            "#  pos        size        status",
        ]
        for b in self.blocks:
            lines.append(b.to_line())
        return "\n".join(lines) + "\n"

    def write_to_file(self, path: Path | str) -> None:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(self.to_mapfile_text(), encoding="utf-8")

    @classmethod
    def parse_mapfile(cls, content_or_path: str | Path) -> DdrescueMapfile:
        """Parses a GNU ddrescue mapfile from string content or file path."""
        if isinstance(content_or_path, Path) or (isinstance(content_or_path, str) and "\n" not in content_or_path and Path(content_or_path).is_file()):
            text = Path(content_or_path).read_text(encoding="utf-8", errors="replace")
        else:
            text = str(content_or_path)

        lines = [line.strip() for line in text.splitlines()]
        data_lines = [l for l in lines if l and not l.startswith("#")]

        if not data_lines:
            raise ValueError("Invalid mapfile: no non-comment header or block lines found.")

        cur_pos = 0
        cur_status = MapBlockStatus.NON_TRIED
        cur_pass = 1
        block_start_idx = 0

        # Check if line 0 is a 2-column header (pos_current status)
        line0_parts = data_lines[0].split()
        if len(line0_parts) == 2:
            cur_pos = int(line0_parts[0], 0)
            cur_status = MapBlockStatus.from_token(line0_parts[1])
            block_start_idx = 1
            if len(data_lines) > 1:
                line1_parts = data_lines[1].split()
                if len(line1_parts) == 2 and (line1_parts[0].isdigit() or line1_parts[0].startswith("0x")):
                    cur_pass = int(line1_parts[0], 0)
                    cur_status = MapBlockStatus.from_token(line1_parts[1])
                    block_start_idx = 2

        blocks: List[MapfileBlock] = []
        for line in data_lines[block_start_idx:]:
            parts = line.split()
            if len(parts) >= 3:
                pos = int(parts[0], 0)
                size = int(parts[1], 0)
                status = MapBlockStatus.from_token(parts[2])
                blocks.append(MapfileBlock(pos=pos, size=size, status=status))

        mf = cls(
            current_pos=cur_pos,
            current_status=cur_status,
            current_pass=cur_pass,
            blocks=blocks,
        )
        return mf

    @classmethod
    def create_initial(cls, total_size: int, block_size: int = 65536) -> DdrescueMapfile:
        """Creates an initial mapfile where all blocks are NON_TRIED ('?')."""
        if total_size <= 0:
            return cls(blocks=[])

        blocks: List[MapfileBlock] = []
        pos = 0
        while pos < total_size:
            sz = min(block_size, total_size - pos)
            blocks.append(MapfileBlock(pos=pos, size=sz, status=MapBlockStatus.NON_TRIED))
            pos += sz

        return cls(
            current_pos=0,
            current_status=MapBlockStatus.NON_TRIED,
            current_pass=1,
            blocks=blocks,
        )

    def merge(self, other: DdrescueMapfile) -> DdrescueMapfile:
        """Merges two mapfiles representing the same source media across different passes.
        
        Resolution priority per sector:
          FINISHED ('+') > BAD_SECTOR ('-') > NON_SCRAPED ('/') > NON_TRIMMED ('*') > NON_TRIED ('?')
        """
        priority = {
            MapBlockStatus.FINISHED: 5,
            MapBlockStatus.BAD_SECTOR: 4,
            MapBlockStatus.NON_SCRAPED: 3,
            MapBlockStatus.NON_TRIMMED: 2,
            MapBlockStatus.NON_TRIED: 1,
        }

        tot = max(self.total_size, other.total_size)
        if tot == 0:
            return DdrescueMapfile()

        # Collect critical boundary split points
        points = {0, tot}
        for b in self.blocks:
            points.add(b.pos)
            points.add(b.end)
        for b in other.blocks:
            points.add(b.pos)
            points.add(b.end)

        sorted_points = sorted(points)
        new_blocks: List[MapfileBlock] = []

        # Helper to query status at an exact offset
        def get_status(mf: DdrescueMapfile, offset: int) -> MapBlockStatus:
            for b in mf.blocks:
                if b.pos <= offset < b.end:
                    return b.status
            return MapBlockStatus.NON_TRIED

        for i in range(len(sorted_points) - 1):
            p1 = sorted_points[i]
            p2 = sorted_points[i + 1]
            sz = p2 - p1
            if sz <= 0:
                continue
            st1 = get_status(self, p1)
            st2 = get_status(other, p1)
            winner = st1 if priority[st1] >= priority[st2] else st2
            
            # Coalesce adjacent blocks with same status
            if new_blocks and new_blocks[-1].status == winner and new_blocks[-1].end == p1:
                new_blocks[-1].size += sz
            else:
                new_blocks.append(MapfileBlock(pos=p1, size=sz, status=winner))

        merged_pass = max(self.current_pass, other.current_pass)
        merged_pos = max(self.current_pos, other.current_pos)
        
        return DdrescueMapfile(
            current_pos=merged_pos,
            current_status=MapBlockStatus.FINISHED if self.is_complete or other.is_complete else MapBlockStatus.NON_TRIED,
            current_pass=merged_pass,
            blocks=new_blocks,
        )
