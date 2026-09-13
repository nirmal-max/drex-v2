"""DREX-V2 NTFS $Bitmap Cluster Allocation & Policy Engine

Provides forensic cluster allocation intelligence from the NTFS $Bitmap attribute.

Supported Scan Policies:
- FREE_ONLY: Prioritizes unallocated (deleted) clusters for rapid recovery scans.
- FREE_FIRST: Traverses unallocated clusters first, then scans allocated space for slack/embedded files.
- FULL_VOLUME: Traverses every cluster sequentially regardless of allocation state.
- TARGETED: Scans a designated range of clusters specified by the investigator.

Attribution:
- NTFS $Bitmap bitfield concepts adapted from ForensiX / SIH26 (MIT License).
"""

from __future__ import annotations

from enum import Enum
from dataclasses import dataclass, field
from typing import Generator, List, Optional, Tuple


class BitmapScanPolicy(Enum):
    FREE_ONLY = "FREE_ONLY"
    FREE_FIRST = "FREE_FIRST"
    FULL_VOLUME = "FULL_VOLUME"
    TARGETED = "TARGETED"


@dataclass
class ClusterRun:
    start_cluster: int
    length: int
    is_allocated: bool

    @property
    def end_cluster(self) -> int:
        return self.start_cluster + self.length - 1


@dataclass
class VolumeAllocationStats:
    total_clusters: int
    allocated_clusters: int
    free_clusters: int
    free_percentage: float
    cluster_size_bytes: int
    unallocated_runs_count: int


class NtfsBitmapAnalyzer:
    """Parses NTFS $Bitmap stream and yields cluster scan ranges based on policy."""

    def __init__(
        self,
        bitmap_data: bytes,
        bytes_per_sector: int = 512,
        sectors_per_cluster: int = 8,
        total_clusters: Optional[int] = None,
    ):
        self.bitmap_data = bitmap_data
        self.bytes_per_sector = bytes_per_sector
        self.sectors_per_cluster = sectors_per_cluster
        self.cluster_size = bytes_per_sector * sectors_per_cluster

        # Total clusters in bitmap: 8 clusters per byte
        max_possible_clusters = len(bitmap_data) * 8
        self.total_clusters = (
            min(total_clusters, max_possible_clusters)
            if total_clusters is not None
            else max_possible_clusters
        )

    def is_cluster_allocated(self, cluster_idx: int) -> bool:
        """Check if a specific cluster is allocated (bit is 1)."""
        if cluster_idx < 0 or cluster_idx >= self.total_clusters:
            return False
        byte_idx = cluster_idx // 8
        bit_idx = cluster_idx % 8
        if byte_idx >= len(self.bitmap_data):
            return False
        return bool(self.bitmap_data[byte_idx] & (1 << bit_idx))

    def get_allocation_stats(self) -> VolumeAllocationStats:
        """Calculate aggregate volume cluster statistics."""
        allocated_count = 0
        runs_count = 0
        in_free_run = False

        for c_idx in range(self.total_clusters):
            is_alloc = self.is_cluster_allocated(c_idx)
            if is_alloc:
                allocated_count += 1
                if in_free_run:
                    in_free_run = False
            else:
                if not in_free_run:
                    runs_count += 1
                    in_free_run = True

        free_count = self.total_clusters - allocated_count
        free_pct = (free_count / max(self.total_clusters, 1)) * 100.0

        return VolumeAllocationStats(
            total_clusters=self.total_clusters,
            allocated_clusters=allocated_count,
            free_clusters=free_count,
            free_percentage=round(free_pct, 2),
            cluster_size_bytes=self.cluster_size,
            unallocated_runs_count=runs_count,
        )

    def extract_cluster_runs(
        self,
        policy: BitmapScanPolicy = BitmapScanPolicy.FREE_ONLY,
        start_cluster: int = 0,
        cluster_limit: Optional[int] = None,
    ) -> List[ClusterRun]:
        """Extract contiguous runs of clusters matching the requested scan policy."""
        runs: List[ClusterRun] = []
        limit = (
            min(self.total_clusters, start_cluster + cluster_limit)
            if cluster_limit is not None
            else self.total_clusters
        )

        if policy == BitmapScanPolicy.FULL_VOLUME:
            # Full volume is a single run spanning the entire range
            if limit > start_cluster:
                runs.append(
                    ClusterRun(
                        start_cluster=start_cluster,
                        length=limit - start_cluster,
                        is_allocated=False,
                    )
                )
            return runs

        if policy == BitmapScanPolicy.TARGETED:
            # Targeted scans the specific sub-range
            if limit > start_cluster:
                runs.append(
                    ClusterRun(
                        start_cluster=start_cluster,
                        length=limit - start_cluster,
                        is_allocated=False,
                    )
                )
            return runs

        # Group contiguous bits into runs
        current_alloc: Optional[bool] = None
        run_start = start_cluster
        run_len = 0

        unallocated_runs: List[ClusterRun] = []
        allocated_runs: List[ClusterRun] = []

        for c in range(start_cluster, limit):
            alloc = self.is_cluster_allocated(c)
            if current_alloc is None:
                current_alloc = alloc
                run_start = c
                run_len = 1
            elif alloc == current_alloc:
                run_len += 1
            else:
                r = ClusterRun(start_cluster=run_start, length=run_len, is_allocated=current_alloc)
                if current_alloc:
                    allocated_runs.append(r)
                else:
                    unallocated_runs.append(r)
                current_alloc = alloc
                run_start = c
                run_len = 1

        if run_len > 0 and current_alloc is not None:
            r = ClusterRun(start_cluster=run_start, length=run_len, is_allocated=current_alloc)
            if current_alloc:
                allocated_runs.append(r)
            else:
                unallocated_runs.append(r)

        if policy == BitmapScanPolicy.FREE_ONLY:
            return unallocated_runs
        elif policy == BitmapScanPolicy.FREE_FIRST:
            return unallocated_runs + allocated_runs

        return unallocated_runs

    def cluster_to_byte_offset(self, cluster_idx: int) -> int:
        """Convert a cluster index into absolute volume byte offset."""
        return cluster_idx * self.cluster_size
