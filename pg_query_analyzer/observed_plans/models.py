"""Data models for observed PostgreSQL plan snapshots."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Optional


@dataclass(frozen=True)
class PlanSummary:
    """Small, indexable summary extracted from a full EXPLAIN plan."""

    top_node_type: str = ""
    total_cost: Optional[float] = None
    plan_rows: Optional[int] = None
    actual_total_time: Optional[float] = None
    actual_rows: Optional[float] = None
    node_count: int = 0
    seq_scan_count: int = 0
    temp_written_blocks: int = 0
    shared_read_blocks: int = 0
    shared_hit_blocks: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "top_node_type": self.top_node_type,
            "total_cost": self.total_cost,
            "plan_rows": self.plan_rows,
            "actual_total_time": self.actual_total_time,
            "actual_rows": self.actual_rows,
            "node_count": self.node_count,
            "seq_scan_count": self.seq_scan_count,
            "temp_written_blocks": self.temp_written_blocks,
            "shared_read_blocks": self.shared_read_blocks,
            "shared_hit_blocks": self.shared_hit_blocks,
        }


@dataclass(frozen=True)
class ObservedPlanSnapshot:
    """A normalized view of one observed query plan."""

    snapshot_id: str
    captured_at: str
    source: str
    query_text: str = ""
    normalized_query: str = ""
    query_fingerprint: str = ""
    queryid: Optional[str] = None
    plan_document: str = ""
    plan_hash: str = ""
    plan_shape_hash: str = ""
    summary: PlanSummary = field(default_factory=PlanSummary)
    source_name: str = ""
    connection_label: str = ""
    database: str = ""
    user: str = ""
    hypopg_pair_group_id: Optional[str] = None
    hypopg_pair_role: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "snapshot_id": self.snapshot_id,
            "captured_at": self.captured_at,
            "source": self.source,
            "query_text": self.query_text,
            "normalized_query": self.normalized_query,
            "query_fingerprint": self.query_fingerprint,
            "queryid": self.queryid,
            "plan_document": self.plan_document,
            "plan_hash": self.plan_hash,
            "plan_shape_hash": self.plan_shape_hash,
            "summary": self.summary.to_dict(),
            "source_name": self.source_name,
            "connection_label": self.connection_label,
            "database": self.database,
            "user": self.user,
            "hypopg_pair_group_id": self.hypopg_pair_group_id,
            "hypopg_pair_role": self.hypopg_pair_role,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True)
class WorkloadCandidate:
    """A pg_stat_statements row that may need an observed plan snapshot."""

    query_text: str
    query_fingerprint: str
    queryid: Optional[str] = None
    calls: int = 0
    rows_sum: int = 0
    mean_ms: float = 0.0
    total_ms: float = 0.0
    journal_matches: int = 0
    saved_queryid_match: bool = False
    merged_queryids: tuple[str, ...] = ()
    source: str = "pg_stat_statements"

    @property
    def needs_plan_snapshot(self) -> bool:
        return self.journal_matches <= 0 and not self.saved_queryid_match

    def to_dict(self) -> Dict[str, Any]:
        return {
            "query_text": self.query_text,
            "query_fingerprint": self.query_fingerprint,
            "queryid": self.queryid,
            "calls": self.calls,
            "rows_sum": self.rows_sum,
            "mean_ms": self.mean_ms,
            "total_ms": self.total_ms,
            "journal_matches": self.journal_matches,
            "saved_queryid_match": self.saved_queryid_match,
            "merged_queryids": list(self.merged_queryids),
            "source": self.source,
            "needs_plan_snapshot": self.needs_plan_snapshot,
        }
