"""SQLite storage for observed plan snapshots."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Iterable, List

from pg_query_analyzer.observed_plans.models import ObservedPlanSnapshot, PlanSummary
from pg_query_analyzer.observed_plans.sources.journal import load_observed_snapshots_from_journal

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS observed_plan_snapshots (
    snapshot_id TEXT PRIMARY KEY,
    captured_at TEXT NOT NULL,
    source TEXT NOT NULL,
    source_name TEXT NOT NULL DEFAULT '',
    query_text TEXT NOT NULL DEFAULT '',
    normalized_query TEXT NOT NULL DEFAULT '',
    query_fingerprint TEXT NOT NULL DEFAULT '',
    queryid TEXT,
    plan_document TEXT NOT NULL DEFAULT '',
    plan_hash TEXT NOT NULL DEFAULT '',
    plan_shape_hash TEXT NOT NULL DEFAULT '',
    connection_label TEXT NOT NULL DEFAULT '',
    database_name TEXT NOT NULL DEFAULT '',
    user_name TEXT NOT NULL DEFAULT '',
    hypopg_pair_group_id TEXT,
    hypopg_pair_role TEXT,
    summary_json TEXT NOT NULL DEFAULT '{}',
    metadata_json TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_observed_plan_identity
ON observed_plan_snapshots(queryid, query_fingerprint, captured_at);

CREATE INDEX IF NOT EXISTS idx_observed_plan_shape
ON observed_plan_snapshots(query_fingerprint, plan_shape_hash);
""".strip()


def initialize_sqlite_store(db_path: str | Path) -> None:
    with sqlite3.connect(str(db_path)) as conn:
        conn.executescript(SCHEMA_SQL)


def upsert_snapshots(db_path: str | Path, snapshots: Iterable[ObservedPlanSnapshot]) -> int:
    """Insert or replace snapshots, returning the number of rows processed."""

    initialize_sqlite_store(db_path)
    rows = [_snapshot_to_row(snapshot) for snapshot in snapshots]
    if not rows:
        return 0

    columns = list(rows[0].keys())
    placeholders = ", ".join("?" for _ in columns)
    update_cols = [col for col in columns if col != "snapshot_id"]
    update_sql = ", ".join(f"{col}=excluded.{col}" for col in update_cols)

    sql = (
        f"INSERT INTO observed_plan_snapshots ({', '.join(columns)}) "
        f"VALUES ({placeholders}) "
        f"ON CONFLICT(snapshot_id) DO UPDATE SET {update_sql}"
    )
    with sqlite3.connect(str(db_path)) as conn:
        conn.executemany(sql, [[row[col] for col in columns] for row in rows])
    return len(rows)


def load_snapshots(db_path: str | Path) -> List[ObservedPlanSnapshot]:
    initialize_sqlite_store(db_path)
    with sqlite3.connect(str(db_path)) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute("""
            SELECT * FROM observed_plan_snapshots
            ORDER BY captured_at, snapshot_id
            """).fetchall()
    return [_row_to_snapshot(row) for row in rows]


def sync_journal_to_sqlite(journal_file: str | Path, db_path: str | Path) -> int:
    """Load observed snapshots from the legacy JSON journal and upsert them into SQLite."""

    snapshots = load_observed_snapshots_from_journal(str(journal_file))
    return upsert_snapshots(db_path, snapshots)


def _snapshot_to_row(snapshot: ObservedPlanSnapshot) -> dict[str, object]:
    return {
        "snapshot_id": snapshot.snapshot_id,
        "captured_at": snapshot.captured_at,
        "source": snapshot.source,
        "source_name": snapshot.source_name,
        "query_text": snapshot.query_text,
        "normalized_query": snapshot.normalized_query,
        "query_fingerprint": snapshot.query_fingerprint,
        "queryid": snapshot.queryid,
        "plan_document": snapshot.plan_document,
        "plan_hash": snapshot.plan_hash,
        "plan_shape_hash": snapshot.plan_shape_hash,
        "connection_label": snapshot.connection_label,
        "database_name": snapshot.database,
        "user_name": snapshot.user,
        "hypopg_pair_group_id": snapshot.hypopg_pair_group_id,
        "hypopg_pair_role": snapshot.hypopg_pair_role,
        "summary_json": json.dumps(snapshot.summary.to_dict(), ensure_ascii=False, sort_keys=True),
        "metadata_json": json.dumps(snapshot.metadata, ensure_ascii=False, sort_keys=True),
    }


def _row_to_snapshot(row: sqlite3.Row) -> ObservedPlanSnapshot:
    summary_raw = _json_dict(row["summary_json"])
    metadata = _json_dict(row["metadata_json"])
    return ObservedPlanSnapshot(
        snapshot_id=row["snapshot_id"],
        captured_at=row["captured_at"],
        source=row["source"],
        source_name=row["source_name"],
        query_text=row["query_text"],
        normalized_query=row["normalized_query"],
        query_fingerprint=row["query_fingerprint"],
        queryid=row["queryid"],
        plan_document=row["plan_document"],
        plan_hash=row["plan_hash"],
        plan_shape_hash=row["plan_shape_hash"],
        connection_label=row["connection_label"],
        database=row["database_name"],
        user=row["user_name"],
        hypopg_pair_group_id=row["hypopg_pair_group_id"],
        hypopg_pair_role=row["hypopg_pair_role"],
        summary=PlanSummary(
            top_node_type=str(summary_raw.get("top_node_type") or ""),
            total_cost=summary_raw.get("total_cost"),
            plan_rows=summary_raw.get("plan_rows"),
            actual_total_time=summary_raw.get("actual_total_time"),
            actual_rows=summary_raw.get("actual_rows"),
            node_count=int(summary_raw.get("node_count") or 0),
            seq_scan_count=int(summary_raw.get("seq_scan_count") or 0),
            temp_written_blocks=int(summary_raw.get("temp_written_blocks") or 0),
            shared_read_blocks=int(summary_raw.get("shared_read_blocks") or 0),
            shared_hit_blocks=int(summary_raw.get("shared_hit_blocks") or 0),
        ),
        metadata=metadata,
    )


def _json_dict(raw: str) -> dict:
    try:
        value = json.loads(raw or "{}")
    except json.JSONDecodeError:
        return {}
    return value if isinstance(value, dict) else {}
