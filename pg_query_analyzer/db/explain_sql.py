"""Helpers for building EXPLAIN statements from user SQL safely."""

from __future__ import annotations

import re

from psycopg2.extensions import adapt
from pglast import parse_sql
from pglast.parser import ParseError

_PG_BIND_PLACEHOLDER = re.compile(r"(?<!\$)\$\d+\b")
_EXPLAINABLE_STATEMENTS = {
    "DeleteStmt",
    "InsertStmt",
    "MergeStmt",
    "SelectStmt",
    "UpdateStmt",
}


class ExplainSqlError(ValueError):
    """Raised when a user query is not safe to wrap in EXPLAIN."""


def validate_single_statement_sql(query_sql: str) -> str:
    """Return stripped SQL only when it is exactly one PostgreSQL statement."""

    sql = (query_sql or "").strip()
    if not sql:
        raise ExplainSqlError("Нет текста запроса.")
    if has_pg_bind_placeholders(sql):
        raise ExplainSqlError(
            "Запрос содержит параметризованные плейсхолдеры ($1, $2, ...), "
            "но значения параметров недоступны. Скопируйте запрос в редактор "
            "и подставьте конкретные значения вместо $N."
        )

    statements = _parse_single_statement(sql)

    if len(statements) != 1:
        raise ExplainSqlError(
            "Для EXPLAIN разрешён ровно один SQL statement. "
            "Удалите дополнительные команды после ';'."
        )

    statement_type = type(statements[0].stmt).__name__
    if statement_type not in _EXPLAINABLE_STATEMENTS:
        raise ExplainSqlError(
            f"PostgreSQL EXPLAIN не поддерживает statement типа {statement_type}. "
            "Выберите SELECT/INSERT/UPDATE/DELETE/MERGE query или выполните команду вручную."
        )

    return sql


def _parse_single_statement(sql: str):
    try:
        return parse_sql(sql)
    except ParseError as e:
        raise ExplainSqlError(f"SQL не удалось разобрать: {e}") from e


def has_pg_bind_placeholders(query_sql: str) -> bool:
    return bool(_PG_BIND_PLACEHOLDER.search(query_sql or ""))


def pg_bind_placeholders(query_sql: str) -> list[str]:
    """Return distinct placeholders like ``$1`` sorted by placeholder number."""

    seen = {match.group(0) for match in _PG_BIND_PLACEHOLDER.finditer(query_sql or "")}
    return sorted(seen, key=lambda placeholder: int(placeholder[1:]))


def substitute_pg_bind_placeholders(query_sql: str, values: dict[str, str]) -> str:
    """Substitute ``$N`` placeholders with SQL string literals.

    The source values come from the UI, not from PostgreSQL's original bind
    parameters. Treat them as literal values; users can type ``NULL`` for SQL
    NULL when needed.
    """

    sql = query_sql or ""
    missing = [
        placeholder for placeholder in pg_bind_placeholders(sql) if placeholder not in values
    ]
    if missing:
        raise ExplainSqlError(f"Не заданы значения для: {', '.join(missing)}")

    def replacement(match: re.Match[str]) -> str:
        placeholder = match.group(0)
        value = values[placeholder]
        if value.strip().upper() == "NULL":
            return "NULL"
        return adapt(value).getquoted().decode("utf-8")

    return _PG_BIND_PLACEHOLDER.sub(replacement, sql)


def explain_format_json_sql(query_sql: str) -> str:
    return f"EXPLAIN (FORMAT JSON) {validate_single_statement_sql(query_sql)}"


def explain_analyze_format_json_buffers_sql(query_sql: str) -> str:
    return f"EXPLAIN (ANALYZE, FORMAT JSON, BUFFERS) {validate_single_statement_sql(query_sql)}"


def explain_format_json_buffers_sql(query_sql: str) -> str:
    return f"EXPLAIN (FORMAT JSON, BUFFERS) {validate_single_statement_sql(query_sql)}"
