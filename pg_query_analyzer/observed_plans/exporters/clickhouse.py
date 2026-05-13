"""ClickHouse export helpers for observed plan snapshots."""

from __future__ import annotations

import json
from typing import Any, Iterable

from pg_query_analyzer.observed_plans.models import ObservedPlanSnapshot

CLICKHOUSE_OBSERVED_PLANS_DDL = """
CREATE TABLE IF NOT EXISTS observed_plan_snapshots
(
    captured_at String,
    snapshot_id String,
    source LowCardinality(String),
    source_name String,
    queryid String,
    query_fingerprint String,
    query_text String,
    plan_hash String,
    plan_shape_hash String,
    top_node_type LowCardinality(String),
    total_cost Nullable(Float64),
    plan_rows Nullable(Int64),
    actual_total_time Nullable(Float64),
    actual_rows Nullable(Float64),
    node_count UInt32,
    seq_scan_count UInt32,
    temp_written_blocks UInt64,
    shared_read_blocks UInt64,
    shared_hit_blocks UInt64,
    hypopg_pair_group_id String,
    hypopg_pair_role LowCardinality(String),
    plan_document String,
    metadata_json String
)
ENGINE = MergeTree
ORDER BY (query_fingerprint, captured_at, plan_shape_hash)
""".strip()


def snapshot_to_clickhouse_row(snapshot: ObservedPlanSnapshot) -> dict[str, Any]:
    summary = snapshot.summary
    return {
        "captured_at": snapshot.captured_at,
        "snapshot_id": snapshot.snapshot_id,
        "source": snapshot.source,
        "source_name": snapshot.source_name,
        "queryid": snapshot.queryid or "",
        "query_fingerprint": snapshot.query_fingerprint,
        "query_text": snapshot.query_text,
        "plan_hash": snapshot.plan_hash,
        "plan_shape_hash": snapshot.plan_shape_hash,
        "top_node_type": summary.top_node_type,
        "total_cost": summary.total_cost,
        "plan_rows": summary.plan_rows,
        "actual_total_time": summary.actual_total_time,
        "actual_rows": summary.actual_rows,
        "node_count": summary.node_count,
        "seq_scan_count": summary.seq_scan_count,
        "temp_written_blocks": summary.temp_written_blocks,
        "shared_read_blocks": summary.shared_read_blocks,
        "shared_hit_blocks": summary.shared_hit_blocks,
        "hypopg_pair_group_id": snapshot.hypopg_pair_group_id or "",
        "hypopg_pair_role": snapshot.hypopg_pair_role or "",
        "plan_document": snapshot.plan_document,
        "metadata_json": json.dumps(snapshot.metadata, ensure_ascii=False, sort_keys=True),
    }


def snapshots_to_json_each_row(snapshots: Iterable[ObservedPlanSnapshot]) -> str:
    lines = [
        json.dumps(snapshot_to_clickhouse_row(snapshot), ensure_ascii=False, sort_keys=True)
        for snapshot in snapshots
    ]
    return "\n".join(lines) + ("\n" if lines else "")
