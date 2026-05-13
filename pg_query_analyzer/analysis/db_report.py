"""Database health report collection and markdown rendering."""

from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
from typing import Any

import psycopg2
from psycopg2.extras import RealDictCursor


def _rows(cursor) -> list[dict[str, Any]]:
    return [dict(x) for x in cursor.fetchall()]


def _safe_preview(text: str, limit: int = 240) -> str:
    if not text:
        return ""
    compact = re.sub(r"\s+", " ", text).strip()
    if len(compact) <= limit:
        return compact
    return compact[: limit - 1] + "…"


def _is_explainable_select(sql_text: str) -> bool:
    if not sql_text:
        return False
    lowered = sql_text.lstrip().lower()
    if not (lowered.startswith("select") or lowered.startswith("with")):
        return False
    if re.search(r"\$[0-9]+\b", sql_text):
        return False
    low = sql_text.lower()
    if "_temp" in low or " pg_temp." in low:
        return False
    return True


def collect_database_report_snapshot(
    conn: psycopg2.extensions.connection,
    *,
    include_explain: bool = True,
    top_n_statements: int = 10,
    explain_timeout_ms: int = 120000,
) -> dict[str, Any]:
    snapshot: dict[str, Any] = {"warnings": []}
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute("SET default_transaction_read_only = on")

        cur.execute("""
            SELECT version() AS version,
                   current_database() AS current_database,
                   current_user AS current_user,
                   inet_server_addr()::text AS server_addr,
                   inet_server_port() AS server_port,
                   pg_postmaster_start_time() AS postmaster_start,
                   now() AS snapshot_time
            """)
        snapshot["server"] = dict(cur.fetchone())

        cur.execute("SELECT pg_size_pretty(pg_database_size(current_database())) AS db_size_pretty")
        snapshot["database_size"] = dict(cur.fetchone())

        cur.execute("""
            SELECT state,
                   count(*)::int AS sessions,
                   max(EXTRACT(EPOCH FROM (now() - query_start)))::numeric(12,2) AS max_query_age_s
            FROM pg_stat_activity
            WHERE datname = current_database()
            GROUP BY state
            ORDER BY sessions DESC
            """)
        snapshot["activity_states"] = _rows(cur)

        cur.execute("""
            SELECT pid,
                   usename,
                   application_name,
                   client_addr::text AS client_addr,
                   state,
                   wait_event_type,
                   wait_event,
                   EXTRACT(EPOCH FROM (now() - query_start))::numeric(12,2) AS age_s,
                   LEFT(query, 700) AS query_preview
            FROM pg_stat_activity
            WHERE datname = current_database()
              AND state = 'active'
              AND pid <> pg_backend_pid()
            ORDER BY query_start ASC
            LIMIT 8
            """)
        snapshot["long_active_queries"] = _rows(cur)

        cur.execute("""
            SELECT count(*)::int AS waiting_locks
            FROM pg_locks l
            JOIN pg_stat_activity a ON a.pid = l.pid
            WHERE NOT l.granted
              AND a.datname = current_database()
            """)
        snapshot["blocking"] = dict(cur.fetchone())

        cur.execute("""
            SELECT blks_hit, blks_read,
                   CASE WHEN blks_hit + blks_read > 0
                        THEN round(100.0 * blks_hit / NULLIF(blks_hit + blks_read, 0), 2)
                        ELSE NULL END AS cache_hit_pct
            FROM pg_stat_database
            WHERE datname = current_database()
            """)
        snapshot["cache"] = dict(cur.fetchone())

        cur.execute("SELECT * FROM pg_stat_bgwriter")
        snapshot["bgwriter"] = dict(cur.fetchone())

        cur.execute("""
            SELECT name, setting, unit
            FROM pg_settings
            WHERE name IN (
                'shared_buffers',
                'effective_cache_size',
                'work_mem',
                'maintenance_work_mem',
                'max_connections',
                'max_worker_processes',
                'max_parallel_workers_per_gather',
                'wal_level',
                'archive_mode',
                'shared_preload_libraries'
            )
            ORDER BY name
            """)
        snapshot["key_settings"] = _rows(cur)

        cur.execute("""
            SELECT EXISTS (
                SELECT 1 FROM pg_available_extensions WHERE name = 'pg_stat_statements'
            ) AS ext_available,
            EXISTS (
                SELECT 1 FROM pg_extension WHERE extname = 'pg_stat_statements'
            ) AS ext_installed
            """)
        ext = dict(cur.fetchone())
        snapshot["pg_stat_statements"] = {"status": ext, "top_statements": []}

        if ext.get("ext_installed"):
            cur.execute(
                """
                SELECT queryid,
                       calls,
                       round(total_exec_time::numeric, 3) AS total_exec_ms,
                       round(mean_exec_time::numeric, 3) AS mean_exec_ms,
                       rows,
                       shared_blks_read,
                       shared_blks_hit,
                       temp_blks_written,
                       LEFT(query, 420) AS query_preview,
                       query
                FROM pg_stat_statements
                WHERE dbid = (SELECT oid FROM pg_database WHERE datname = current_database())
                ORDER BY total_exec_time DESC NULLS LAST
                LIMIT %s
                """,
                (int(max(1, top_n_statements)),),
            )
            top_statements = _rows(cur)
            snapshot["pg_stat_statements"]["top_statements"] = top_statements
        else:
            snapshot["warnings"].append(
                "Расширение pg_stat_statements не установлено в текущей БД."
            )

    snapshot["explain"] = None
    if include_explain and snapshot["pg_stat_statements"]["top_statements"]:
        explain_result: dict[str, Any] = {
            "selected_query_preview": "",
            "selected_queryid": None,
            "plan_text": [],
            "error": "",
        }
        explain_sql = ""
        for row in snapshot["pg_stat_statements"]["top_statements"]:
            candidate = (row.get("query") or "").strip().rstrip(";")
            if _is_explainable_select(candidate):
                explain_sql = candidate
                explain_result["selected_query_preview"] = _safe_preview(candidate, 360)
                explain_result["selected_queryid"] = row.get("queryid")
                break

        if not explain_sql:
            explain_result["error"] = (
                "Подходящий SQL для EXPLAIN ANALYZE не найден "
                "(часто из-за параметров $1..$N или temp-объектов)."
            )
        else:
            with conn.cursor() as cur:
                cur.execute(f"SET statement_timeout = {int(max(1000, explain_timeout_ms))}")
                try:
                    cur.execute(f"EXPLAIN (ANALYZE, BUFFERS, FORMAT TEXT)\n{explain_sql}")
                    explain_result["plan_text"] = [x[0] for x in cur.fetchall()]
                except Exception as exc:  # noqa: BLE001
                    explain_result["error"] = str(exc)
                    snapshot["warnings"].append(
                        "EXPLAIN (ANALYZE, BUFFERS) не выполнен: " + _safe_preview(str(exc), 240)
                    )
        snapshot["explain"] = explain_result
    return snapshot


def build_database_report_markdown(snapshot: dict[str, Any], ai_summary: str = "") -> str:
    server = snapshot.get("server") or {}
    size = snapshot.get("database_size") or {}
    cache = snapshot.get("cache") or {}
    blocking = snapshot.get("blocking") or {}
    status = (snapshot.get("pg_stat_statements") or {}).get("status") or {}
    top_statements = (snapshot.get("pg_stat_statements") or {}).get("top_statements") or []
    explain = snapshot.get("explain") or {}
    now = server.get("snapshot_time") or ""

    md: list[str] = []
    md.append("# Отчёт по работе PostgreSQL")
    md.append("")
    md.append(f"- Дата снимка: `{now}`")
    md.append(f"- База: `{server.get('current_database', 'N/A')}`")
    md.append(f"- Пользователь: `{server.get('current_user', 'N/A')}`")
    md.append(f"- Сервер: `{server.get('server_addr', 'N/A')}:{server.get('server_port', 'N/A')}`")
    md.append("")

    if ai_summary.strip():
        md.append("## AI-сводка")
        md.append("")
        md.append(ai_summary.strip())
        md.append("")

    md.append("## Основные метрики")
    md.append("")
    md.append(f"- Версия: `{server.get('version', 'N/A')}`")
    md.append(f"- Размер текущей БД: `{size.get('db_size_pretty', 'N/A')}`")
    md.append(
        f"- Cache hit: `{cache.get('cache_hit_pct', 'N/A')}%` "
        f"(hit={cache.get('blks_hit', 'N/A')}, read={cache.get('blks_read', 'N/A')})"
    )
    md.append(f"- Ожидающих блокировок: `{blocking.get('waiting_locks', 'N/A')}`")
    md.append("")

    md.append("## Состояния сессий")
    md.append("")
    for row in snapshot.get("activity_states") or []:
        md.append(
            f"- `{row.get('state') or '(null)'}`: {row.get('sessions')} "
            f"(max age s: {row.get('max_query_age_s')})"
        )
    if not (snapshot.get("activity_states") or []):
        md.append("- Нет данных.")
    md.append("")

    md.append("## Долгие активные запросы")
    md.append("")
    for row in snapshot.get("long_active_queries") or []:
        md.append(
            f"- pid `{row.get('pid')}` age `{row.get('age_s')}s` "
            f"user `{row.get('usename')}` wait `{row.get('wait_event_type')}/{row.get('wait_event')}`"
        )
        md.append(f"  preview: `{_safe_preview(row.get('query_preview') or '', 180)}`")
    if not (snapshot.get("long_active_queries") or []):
        md.append("- Активных запросов не найдено.")
    md.append("")

    md.append("## Ключевые настройки")
    md.append("")
    for s in snapshot.get("key_settings") or []:
        val = f"{s.get('setting', '')}{s.get('unit', '')}".strip()
        md.append(f"- `{s.get('name')}` = `{val}`")
    md.append("")

    md.append("## pg_stat_statements")
    md.append("")
    md.append(
        f"- Доступно: `{status.get('ext_available')}`; установлено: `{status.get('ext_installed')}`"
    )
    if top_statements:
        md.append("")
        md.append(
            "| queryid | calls | total_exec_ms | mean_exec_ms | temp_blks_written | preview |"
        )
        md.append("| --- | ---: | ---: | ---: | ---: | --- |")
        for row in top_statements:
            md.append(
                f"| `{row.get('queryid')}` | {row.get('calls')} | {row.get('total_exec_ms')} | "
                f"{row.get('mean_exec_ms')} | {row.get('temp_blks_written')} | "
                f"{_safe_preview(row.get('query_preview') or '', 110)} |"
            )
    md.append("")

    md.append("## EXPLAIN (ANALYZE, BUFFERS)")
    md.append("")
    if not explain:
        md.append("- Не выполнялся.")
    elif explain.get("error"):
        md.append(f"- Ошибка: `{explain.get('error')}`")
        if explain.get("selected_query_preview"):
            md.append(f"- Кандидат: `{explain.get('selected_query_preview')}`")
    else:
        md.append(f"- QueryId: `{explain.get('selected_queryid')}`")
        md.append(f"- SQL preview: `{explain.get('selected_query_preview')}`")
        md.append("")
        md.append("```")
        for ln in explain.get("plan_text") or []:
            md.append(str(ln))
        md.append("```")
    md.append("")

    warnings = snapshot.get("warnings") or []
    if warnings:
        md.append("## Примечания")
        md.append("")
        for w in warnings:
            md.append(f"- {w}")
        md.append("")
    return "\n".join(md)


def build_ai_input_payload(snapshot: dict[str, Any]) -> str:
    top = (snapshot.get("pg_stat_statements") or {}).get("top_statements") or []
    compact_top = []
    for row in top[:8]:
        compact_top.append(
            {
                "queryid": row.get("queryid"),
                "calls": row.get("calls"),
                "total_exec_ms": row.get("total_exec_ms"),
                "mean_exec_ms": row.get("mean_exec_ms"),
                "temp_blks_written": row.get("temp_blks_written"),
                "preview": _safe_preview(row.get("query_preview") or "", 180),
            }
        )
    payload = {
        "server": snapshot.get("server"),
        "database_size": snapshot.get("database_size"),
        "activity_states": snapshot.get("activity_states"),
        "long_active_queries": snapshot.get("long_active_queries"),
        "cache": snapshot.get("cache"),
        "blocking": snapshot.get("blocking"),
        "key_settings": snapshot.get("key_settings"),
        "top_statements": compact_top,
        "explain": snapshot.get("explain"),
        "warnings": snapshot.get("warnings"),
    }
    return json.dumps(payload, ensure_ascii=False, default=str)


def generate_ai_summary_openai(
    snapshot: dict[str, Any],
    *,
    api_key: str | None = None,
    model: str | None = None,
    base_url: str | None = None,
    timeout_s: int = 40,
) -> str:
    resolved_key = (api_key or os.getenv("PGQA_OPENAI_API_KEY") or "").strip()
    if not resolved_key:
        raise RuntimeError("PGQA_OPENAI_API_KEY не задан")

    resolved_model = (model or os.getenv("PGQA_AI_MODEL") or "gpt-4o-mini").strip()
    endpoint = (base_url or os.getenv("PGQA_AI_BASE_URL") or "https://api.openai.com/v1").rstrip(
        "/"
    )
    url = endpoint + "/chat/completions"

    evidence = build_ai_input_payload(snapshot)
    prompt = (
        "Ты senior PostgreSQL performance engineer. "
        "Сделай краткую русскоязычную сводку для DBA в 8-12 буллетов: "
        "главные риски, вероятные причины, приоритеты (P1/P2/P3), "
        "и безопасный план проверки (без изменения БД). "
        "Не выдумывай отсутствующие метрики."
    )
    body = {
        "model": resolved_model,
        "temperature": 0.2,
        "messages": [
            {"role": "system", "content": prompt},
            {"role": "user", "content": "Данные снимка PostgreSQL:\n" + evidence},
        ],
    }
    req = urllib.request.Request(
        url=url,
        method="POST",
        headers={
            "Authorization": f"Bearer {resolved_key}",
            "Content-Type": "application/json",
        },
        data=json.dumps(body).encode("utf-8"),
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"AI HTTP error {exc.code}: {detail[:280]}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"AI network error: {exc}") from exc

    choices = payload.get("choices") or []
    if not choices:
        raise RuntimeError("AI ответ пуст (choices отсутствует)")
    message = (choices[0].get("message") or {}).get("content") or ""
    text = str(message).strip()
    if not text:
        raise RuntimeError("AI не вернул текст")
    return text
