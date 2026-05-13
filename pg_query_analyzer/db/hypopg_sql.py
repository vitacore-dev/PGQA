"""HypoPG helpers — hypothetical indexes visible only to EXPLAIN (same session)."""

from __future__ import annotations

import re
from typing import Any

from pg_query_analyzer.db.explain_sql import ExplainSqlError, explain_format_json_sql

_ANALYSIS_MARKUP_TAGS = (
    "[table]",
    "[/table]",
    "[rec]",
    "[/rec]",
    "[warning]",
    "[/warning]",
    "[hl]",
    "[/hl]",
    "[title]",
    "[/title]",
    "[section]",
    "[/section]",
    "[error]",
    "[/error]",
    "[seqscan]",
    "[/seqscan]",
    "[i]",
    "[/i]",
)

_CREATE_INDEX_SQL = re.compile(
    r"\bCREATE\s+(?:UNIQUE\s+)?INDEX\b[\s\S]*?;",
    re.IGNORECASE,
)


class HypoPGError(Exception):
    """HypoPG unavailable or DDL rejected."""


def strip_analysis_markup(text: str) -> str:
    """Remove rich-text markers used by the analyzer from pasted/plain buffer."""
    t = text or ""
    for tag in _ANALYSIS_MARKUP_TAGS:
        t = t.replace(tag, "")
    return t


def normalize_statement_for_hypopg(ddl: str) -> str:
    """HypoPG typically rejects ``CONCURRENTLY``; collapse whitespace and trim trailing ``;``."""
    s = (ddl or "").strip()
    if not s:
        return ""
    s = re.sub(r"\s+CONCURRENTLY\b", " ", s, flags=re.IGNORECASE)
    s = s.rstrip(";").strip()
    s = re.sub(r"\s+", " ", s)
    return s


def extract_hypopg_create_index_ddls(text: str) -> list[str]:
    """Pull ``CREATE INDEX … ;`` fragments from analyzer HTML/plain output or clipboard.

    Returns normalized one-line statements suitable for ``hypopg_create_index`` (no trailing ``;``).
    Order preserved; duplicates removed (first wins).
    """
    raw = strip_analysis_markup(text or "")
    seen: set[str] = set()
    out: list[str] = []
    for m in _CREATE_INDEX_SQL.finditer(raw):
        stmt = normalize_statement_for_hypopg(m.group(0))
        if stmt and stmt not in seen:
            seen.add(stmt)
            out.append(stmt)
    return out


def is_hypopg_installed(cursor) -> bool:
    cursor.execute("""
        SELECT EXISTS (
            SELECT 1 FROM pg_extension WHERE extname = 'hypopg'
        )
        """)
    row = cursor.fetchone()
    return bool(row and row[0])


def hypopg_reset(cursor) -> None:
    cursor.execute("SELECT hypopg_reset()")


def hypopg_create_index(cursor, create_index_statement: str) -> None:
    """Apply one hypothetical index DDL via HypoPG."""
    ddl = normalize_statement_for_hypopg(create_index_statement)
    if not ddl:
        raise HypoPGError("Пустая строка CREATE INDEX.")
    cursor.execute("SELECT * FROM hypopg_create_index(%s)", (ddl,))
    cursor.fetchall()


def explain_json_with_hypothetical_indexes(
    cursor,
    *,
    query_sql: str,
    create_index_ddls: list[str],
) -> Any:
    """Run ``hypopg_reset``, apply DDLs, ``EXPLAIN (FORMAT JSON)``, then ``hypopg_reset``.

    Caller must use one connection / session for the whole sequence.
    Returns raw JSON plan value from PostgreSQL (often ``str`` or ``dict`` depending on adapter).
    """
    q = (query_sql or "").strip()
    if not q:
        raise HypoPGError("Нет текста запроса.")

    lines = [
        ln.strip() for ln in create_index_ddls if ln.strip() and not ln.strip().startswith("--")
    ]
    if not lines:
        raise HypoPGError("Укажите хотя бы одну строку CREATE INDEX для HypoPG.")

    if not is_hypopg_installed(cursor):
        raise HypoPGError(
            "Расширение hypopg не установлено. Выполните: CREATE EXTENSION IF NOT EXISTS hypopg;"
        )

    hypopg_reset(cursor)

    for ln in lines:
        hypopg_create_index(cursor, ln)

    try:
        explain_sql = explain_format_json_sql(q)
    except ExplainSqlError as e:
        raise HypoPGError(str(e)) from e
    cursor.execute(explain_sql)
    row = cursor.fetchone()
    plan_val = row[0] if row else None

    hypopg_reset(cursor)
    return plan_val
