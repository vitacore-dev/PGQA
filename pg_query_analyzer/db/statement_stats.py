"""Read workload aggregates from PostgreSQL pg_stat_statements (requires extension)."""

from __future__ import annotations

from typing import Any, Dict, List, Literal, Optional

SortKey = Literal["total_time", "mean_time", "calls", "rows"]

_SORT_KEYS = frozenset({"total_time", "mean_time", "calls", "rows"})


class StatementStatsError(Exception):
    """Raised when pg_stat_statements is unavailable or the query cannot run."""


def is_pg_stat_statements_installed(cursor) -> bool:
    cursor.execute("""
        SELECT EXISTS (
            SELECT 1 FROM pg_extension WHERE extname = 'pg_stat_statements'
        )
        """)
    row = cursor.fetchone()
    return bool(row and row[0])


def _timing_column_names(cursor) -> tuple[str, str]:
    """PG13+ uses total_exec_time/mean_exec_time; PG12 uses total_time/mean_time."""
    cursor.execute("""
        SELECT EXISTS (
            SELECT 1 FROM pg_attribute
            WHERE attrelid = 'pg_stat_statements'::regclass
              AND attname = 'total_exec_time'
              AND NOT attisdropped
        )
        """)
    modern = bool(cursor.fetchone()[0])
    if modern:
        return "total_exec_time", "mean_exec_time"
    return "total_time", "mean_time"


def _order_sql_fragment(sort_key: str, total_col: str, mean_col: str) -> str:
    if sort_key == "total_time":
        return total_col
    if sort_key == "mean_time":
        return mean_col
    if sort_key == "calls":
        return "calls"
    if sort_key == "rows":
        return "rows"
    return total_col


def fetch_top_statements(
    cursor,
    *,
    limit: int,
    sort_key: str = "total_time",
    max_query_chars: int = 16000,
) -> List[Dict[str, Any]]:
    """Return normalized rows for the current database only.

    ``sort_key`` must be one of total_time, mean_time, calls, rows (validated).
    """
    if not is_pg_stat_statements_installed(cursor):
        raise StatementStatsError(
            "Расширение pg_stat_statements не установлено в этой базе. "
            "Выполните: CREATE EXTENSION IF NOT EXISTS pg_stat_statements;"
        )

    sk = sort_key if sort_key in _SORT_KEYS else "total_time"
    lim = max(1, min(int(limit), 500))
    total_col, mean_col = _timing_column_names(cursor)
    order_frag = _order_sql_fragment(sk, total_col, mean_col)

    sql = f"""
        SELECT queryid::text AS queryid,
               LEFT(query, %s)::text AS query_text,
               calls::bigint AS calls,
               rows::bigint AS rows_sum,
               round({mean_col}::numeric, 4) AS mean_ms,
               round({total_col}::numeric, 4) AS total_ms
        FROM pg_stat_statements
        WHERE dbid = (SELECT oid FROM pg_database WHERE datname = current_database())
        ORDER BY {order_frag} DESC NULLS LAST
        LIMIT %s
    """
    cursor.execute(sql, (max_query_chars, lim))
    colnames = [d[0] for d in cursor.description]
    return [dict(zip(colnames, row)) for row in cursor.fetchall()]


def lookup_queryid_for_executed_statement(cursor, executed_sql: str) -> Optional[str]:
    """Find ``pg_stat_statements.queryid`` for the exact executed SQL text (current DB).

    ``executed_sql`` must match ``pg_stat_statements.query`` byte-for-byte (e.g. full
    ``EXPLAIN (FORMAT JSON) …``). Returns ``None`` if extension is off or no row.

    Very long queries may fail to match if the server truncates stored text.
    """
    sql = (executed_sql or "").strip()
    if not sql:
        return None
    if not is_pg_stat_statements_installed(cursor):
        return None
    cursor.execute(
        """
        SELECT queryid::text FROM pg_stat_statements
        WHERE dbid = (SELECT oid FROM pg_database WHERE datname = current_database())
          AND query = %s
        LIMIT 1
        """,
        (sql,),
    )
    row = cursor.fetchone()
    return row[0] if row else None


def aggregate_statements_by_fingerprint(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Merge rows sharing the same ``normalize_query_text`` fingerprint (client-side workload view).

    Sums ``calls``, ``rows_sum``, ``total_ms``; recomputes ``mean_ms`` from summed totals.
    ``queryid`` becomes a short marker ``Σ<N>`` where *N* is the number of distinct source queryids merged.
    """
    from pg_query_analyzer.analysis.sql_normalize import normalize_query_text

    merged: Dict[str, Dict[str, Any]] = {}
    for row in rows:
        qt_full = row.get("query_text") or ""
        qt_strip = qt_full.strip()
        fp_key = (
            normalize_query_text(qt_strip) if qt_strip else (qt_strip or str(row.get("queryid")))
        )
        bucket = merged.setdefault(
            fp_key,
            {
                "calls": 0,
                "rows_sum": 0,
                "total_ms": 0.0,
                "query_text": qt_strip,
                "fingerprint": fp_key,
                "_sources": [],
            },
        )
        calls_i = int(row.get("calls") or 0)
        rs_i = int(row.get("rows_sum") or 0)
        tot = float(row.get("total_ms") or 0.0)

        bucket["calls"] += calls_i
        bucket["rows_sum"] += rs_i
        bucket["total_ms"] += tot

        if len(qt_strip) > len(bucket["query_text"]):
            bucket["query_text"] = qt_strip

        q_src = str(row.get("queryid") or "").strip()
        if q_src and q_src not in bucket["_sources"]:
            bucket["_sources"].append(q_src)

    out: List[Dict[str, Any]] = []
    for _, b in merged.items():
        sources = list(b["_sources"])
        calls = int(b["calls"])
        rs = int(b["rows_sum"])
        tot_ms = float(b["total_ms"])
        mean_ms = round(tot_ms / calls, 4) if calls else 0.0
        n_src = len(sources)

        merged_row: Dict[str, Any] = {
            "queryid": (f"Σ{n_src}" if n_src > 1 else (sources[0] if sources else "")),
            "query_text": b["query_text"],
            "calls": calls,
            "rows_sum": rs,
            "mean_ms": mean_ms,
            "total_ms": round(tot_ms, 4),
            "fingerprint": b["fingerprint"],
            "journal_matches": 0,
            "_merged_queryids": sources,
            "_aggregation_count": max(n_src, 1),
        }
        out.append(merged_row)
    return out


def reset_pg_stat_statements(cursor) -> None:
    """Сбросить накопленную статистику ``pg_stat_statements`` (глобально для кластера).

    Обычно нужны права суперпользователя или эквивалентные на выполнение функции.
    """
    cursor.execute("SELECT pg_stat_statements_reset()")
