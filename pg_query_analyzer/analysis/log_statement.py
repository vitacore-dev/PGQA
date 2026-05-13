"""Parse SQL from PostgreSQL server logs (``log_statement`` and csvlog ``query`` column)."""

from __future__ import annotations

import csv
import hashlib
import io
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Tuple

from pg_query_analyzer.analysis.sql_inspect import referenced_tables
from pg_query_analyzer.analysis.sql_normalize import normalize_query_text

_STATEMENT_RE = re.compile(r"\bLOG:\s+statement:\s*(.*)$", re.IGNORECASE)
# Rare: some builds / wrappers emit only "STATEMENT:" on the line.
_ALT_STATEMENT_RE = re.compile(r"^\s*STATEMENT:\s*(.*)$", re.IGNORECASE)


@dataclass
class LogStatementRecord:
    """One captured SQL statement from a log."""

    sql: str
    line_start: int
    log_prefix: str = ""
    detail: str = ""


@dataclass
class AggregatedLogStatement:
    """Grouped by ``normalize_query_text`` fingerprint."""

    fingerprint: str
    count: int
    sample_sql: str
    tables: List[str] = field(default_factory=list)


def looks_like_csvlog_header(first_line: str) -> bool:
    s = first_line.strip("\ufeff").strip()
    if not s or "," not in s:
        return False
    low = s.lower()
    first_field = s.split(",", 1)[0].strip().strip('"').lower()
    return first_field.startswith("log_time") and "message" in low


def parse_log_statement_records(text: str) -> List[LogStatementRecord]:
    """Extract statements from full log file contents (csvlog or stderr-style text)."""

    raw = text or ""
    if not raw.strip():
        return []

    first = raw.split("\n", 1)[0].strip("\ufeff")
    if looks_like_csvlog_header(first):
        return _parse_csvlog(raw)

    return _parse_stderr_style_log(raw)


def _parse_csvlog(content: str) -> List[LogStatementRecord]:
    records: List[LogStatementRecord] = []
    try:
        reader = csv.DictReader(io.StringIO(content))
    except csv.Error:
        return []

    if not reader.fieldnames:
        return []

    fields_lower = {f.lower(): f for f in reader.fieldnames}
    msg_key = fields_lower.get("message")
    query_key = fields_lower.get("query")
    detail_key = fields_lower.get("detail")

    for row_idx, row in enumerate(reader, start=2):
        if not row:
            continue
        sql = ""
        detail = ""
        if detail_key:
            detail = (row.get(detail_key) or "").strip()

        if query_key:
            qcol = (row.get(query_key) or "").strip()
            if qcol:
                sql = _coerce_sql_from_log_field(qcol)

        if not sql and msg_key:
            msg = (row.get(msg_key) or "").strip()
            sql = _coerce_sql_from_log_field(msg)

        if not sql:
            continue

        sql = _finalize_sql(sql)
        if not sql:
            continue

        records.append(
            LogStatementRecord(
                sql=sql,
                line_start=row_idx,
                log_prefix="csvlog",
                detail=detail,
            )
        )

    return records


def _coerce_sql_from_log_field(fragment: str) -> str:
    """Normalize ``query`` or ``message`` cell: strip ``LOG: statement:`` wrapper if present."""

    t = (fragment or "").strip()
    if not t:
        return ""
    extracted = _sql_from_message_line(t)
    if extracted:
        return extracted
    low = t.lower()
    key = "statement:"
    pos = low.find(key)
    if pos >= 0:
        return t[pos + len(key) :].strip()
    return t


def _sql_from_message_line(message: str) -> str:
    """Extract SQL from a single-line or multi-line ``message`` field."""

    if not message:
        return ""

    lines = message.splitlines()
    if not lines:
        return ""

    first = lines[0]
    m = _STATEMENT_RE.search(first)
    if not m:
        m2 = _ALT_STATEMENT_RE.match(first)
        if not m2:
            return ""
        parts = [m2.group(1)]
    else:
        parts = [m.group(1)]

    for extra in lines[1:]:
        if extra.startswith("\t"):
            parts.append(extra[1:])
        else:
            parts.append(extra)

    return "\n".join(parts).strip()


def _parse_stderr_style_log(content: str) -> List[LogStatementRecord]:
    lines = content.splitlines()
    records: List[LogStatementRecord] = []
    i = 0
    n = len(lines)

    while i < n:
        line = lines[i]
        lineno = i + 1
        m = _STATEMENT_RE.search(line)
        if not m:
            m_alt = _ALT_STATEMENT_RE.match(line.strip())
            if m_alt:
                parts = [m_alt.group(1)]
                log_prefix = line[: m_alt.start()].strip() if m_alt.start() > 0 else ""
            else:
                i += 1
                continue
        else:
            parts = [m.group(1)]
            log_prefix = line[: m.start()].strip()

        i += 1
        detail_buf: List[str] = []

        while i < n:
            nxt = lines[i]
            if nxt.startswith("\t"):
                parts.append(nxt[1:] if nxt.startswith("\t") else nxt)
                i += 1
                continue

            if _STATEMENT_RE.search(nxt) or _ALT_STATEMENT_RE.match(nxt.strip()):
                break

            if re.match(r"^\d{4}-\d{2}-\d{2}\s", nxt):
                break

            det_m = re.match(r"^\s*DETAIL:\s*(.*)$", nxt, re.IGNORECASE)
            if det_m:
                detail_buf.append(det_m.group(1).strip())
                i += 1
                continue

            hint_m = re.match(r"^\s*HINT:\s*", nxt, re.IGNORECASE)
            if hint_m:
                i += 1
                continue

            ctx_m = re.match(r"^\s*CONTEXT:\s*", nxt, re.IGNORECASE)
            if ctx_m:
                i += 1
                continue

            break

        sql = _finalize_sql("\n".join(parts))
        if sql:
            records.append(
                LogStatementRecord(
                    sql=sql,
                    line_start=lineno,
                    log_prefix=log_prefix,
                    detail="\n".join(detail_buf) if detail_buf else "",
                )
            )

    return records


def _finalize_sql(sql: str) -> str:
    s = (sql or "").strip()
    return s


_TX_FIRST_WORD = frozenset(
    {
        "begin",
        "commit",
        "rollback",
        "savepoint",
        "release",
        "start",  # START TRANSACTION
    }
)


def is_transaction_control_sql(sql: str) -> bool:
    """Heuristic: hide BEGIN/COMMIT/ROLLBACK/SAVEPOINT noise."""

    s = (sql or "").strip()
    if not s:
        return False
    head = s.split(None, 2)
    if not head:
        return False
    w = head[0].lower().rstrip(";")
    if w in _TX_FIRST_WORD:
        return True
    if len(head) >= 2 and w == "start" and head[1].lower().startswith("transaction"):
        return True
    if len(head) >= 2 and w == "rollback" and head[1].lower().startswith("to"):
        return True
    return False


def aggregate_log_statements(
    records: List[LogStatementRecord],
    *,
    hide_transaction_commands: bool = True,
    max_tables: int = 12,
) -> Tuple[List[AggregatedLogStatement], Dict[str, Any]]:
    """Group records by normalized fingerprint; collect counts and a sample."""

    buckets: Dict[str, Dict[str, Any]] = {}
    skipped_tx = 0

    for rec in records:
        sql = rec.sql.strip()
        if not sql:
            continue
        if hide_transaction_commands and is_transaction_control_sql(sql):
            skipped_tx += 1
            continue

        fp = normalize_query_text(sql)
        if not fp:
            fp = hashlib_fallback_fingerprint(sql)

        if fp not in buckets:
            tables = referenced_tables(sql)[:max_tables]
            buckets[fp] = {
                "count": 0,
                "sample_sql": sql,
                "sample_line": rec.line_start,
                "tables": tables,
            }
        buckets[fp]["count"] += 1

    aggregated: List[AggregatedLogStatement] = []
    for fp, data in buckets.items():
        aggregated.append(
            AggregatedLogStatement(
                fingerprint=fp,
                count=int(data["count"]),
                sample_sql=str(data["sample_sql"]),
                tables=list(data.get("tables") or []),
            )
        )

    aggregated.sort(key=lambda a: (-a.count, a.fingerprint))

    meta = {
        "raw_statement_count": len(records),
        "unique_fingerprints": len(aggregated),
        "skipped_transaction_commands": skipped_tx,
    }
    return aggregated, meta


def hashlib_fallback_fingerprint(sql: str) -> str:
    """When normalization returns empty, use a short stable hash."""

    return "raw:" + hashlib.sha256(sql.encode("utf-8")).hexdigest()[:16]
