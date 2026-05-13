"""Heuristic analysis of PostgreSQL EXPLAIN plans (internal tree format)."""

from __future__ import annotations

import re
from collections import defaultdict
from typing import Any, Dict, List, MutableMapping, Optional, Tuple

from pg_query_analyzer.analysis.sql_inspect import (
    extract_predicate_fields_from_filter,
    join_columns_for_relation,
    referenced_tables,
    sort_key_columns,
)


def remove_circular_refs(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {
            k: remove_circular_refs(v) for k, v in obj.items() if k not in ("parent", "children")
        }
    if isinstance(obj, list):
        return [remove_circular_refs(item) for item in obj]
    if isinstance(obj, (str, int, float, bool)) or obj is None:
        return obj
    return str(obj)


def identify_problems(
    node: MutableMapping[str, Any],
    analysis: MutableMapping[str, Any],
    analyzer_settings: MutableMapping[str, Any],
    parent: Optional[MutableMapping[str, Any]] = None,
) -> None:
    seq_scan_warning = analyzer_settings.get("thresholds", {}).get("seq_scan_warning_cost", 150)
    nested_loop_warning = analyzer_settings.get("thresholds", {}).get(
        "nested_loop_warning_cost", 500
    )

    if node["type"] == "Seq Scan" and node["cost"] > seq_scan_warning:
        table_name = node["properties"].get("Relation-Name", "unknown table")
        analysis["problems"].append(
            f'Отсутствие индекса для таблицы {table_name} (стоимость: {node["cost"]:.2f})'
        )

    if node["type"] == "Nested Loop" and node["cost"] > nested_loop_warning:
        analysis["problems"].append(f'Дорогостоящий Nested Loop (стоимость: {node["cost"]:.2f})')

    props = node.get("properties") or {}
    spill_types = frozenset({"Hash Join", "Hash Aggregate", "Incremental Sort"})
    enable_spill = analyzer_settings.get("analysis", {}).get("enable_spill_problems", True)
    temp_thr = int(analyzer_settings.get("thresholds", {}).get("temp_spill_warning_blocks", 1))
    tw_spill = _int_prop(props, "Temp-Written-Blocks", "Temp Written Blocks")
    if (
        enable_spill
        and tw_spill is not None
        and tw_spill >= temp_thr
        and node["type"] in spill_types
    ):
        analysis["problems"].append(
            f'{node["type"]}: запись во временные файлы ({tw_spill} Temp Written Blocks) — '
            "нехватка work_mem или слишком крупная хеш-таблица/сортировка"
        )

    if node["type"] == "Sort" and props.get("Sort-Method") == "external":
        analysis["problems"].append(
            "Сортировка с использованием временных файлов (не хватает work_mem)"
        )

    for child in node.get("children", []):
        identify_problems(child, analysis, analyzer_settings, node)


def _float_prop(props: MutableMapping[str, Any], *names: str) -> Optional[float]:
    for name in names:
        raw = props.get(name)
        if raw is None or raw == "":
            continue
        try:
            return float(raw)
        except (TypeError, ValueError):
            continue
    return None


def _int_prop(props: MutableMapping[str, Any], *names: str) -> Optional[int]:
    for name in names:
        raw = props.get(name)
        if raw is None or raw == "":
            continue
        try:
            return int(float(raw))
        except (TypeError, ValueError):
            continue
    return None


def _collect_row_estimate_mismatch_nodes(
    node: MutableMapping[str, Any],
    threshold_ratio: float,
    min_rows_floor: float,
    acc: List[MutableMapping[str, Any]],
) -> None:
    props = node.get("properties") or {}
    plan_r = _float_prop(props, "Plan-Rows", "Plan Rows")
    actual_r = _float_prop(props, "Actual-Rows", "Actual Rows")
    if plan_r is not None and actual_r is not None:
        if max(plan_r, actual_r) >= min_rows_floor:
            if plan_r < 1e-9:
                ratio = float("inf") if actual_r > 1e-9 else 1.0
            else:
                ratio = max(actual_r / plan_r, plan_r / max(actual_r, 1e-9))
            if ratio >= threshold_ratio:
                acc.append(
                    {
                        "node": node,
                        "plan": plan_r,
                        "actual": actual_r,
                        "ratio": ratio,
                        "type": node.get("type", ""),
                    }
                )
    for child in node.get("children") or []:
        _collect_row_estimate_mismatch_nodes(child, threshold_ratio, min_rows_floor, acc)


def append_row_estimate_vs_actual_section(
    analysis: MutableMapping[str, Any],
    plan_tree: MutableMapping[str, Any],
    analyzer_settings: MutableMapping[str, Any],
) -> int:
    """Append «EXPLAIN ANALYZE: оценка vs факт» to ``analysis['general']``.

    Returns number of mismatch nodes listed (after truncation).
    """
    if not analyzer_settings.get("analysis", {}).get("enable_row_estimate_analysis", True):
        return 0

    thr = float(analyzer_settings.get("thresholds", {}).get("rows_estimate_ratio_warn", 10.0))
    min_floor = float(analyzer_settings.get("thresholds", {}).get("rows_estimate_min_rows", 1.0))
    max_n = int(analyzer_settings.get("analysis", {}).get("max_row_estimate_mismatch_nodes", 8))

    acc: List[MutableMapping[str, Any]] = []
    _collect_row_estimate_mismatch_nodes(plan_tree, thr, min_floor, acc)
    if not acc:
        return 0

    acc.sort(key=lambda x: x["ratio"], reverse=True)
    shown = acc[:max_n]

    analysis["general"] += "[section]EXPLAIN ANALYZE: оценка vs факт (строки)[/section]\n"
    analysis["general"] += (
        "Узлы, где отношение оценённых строк (Plan Rows) к фактическим (Actual Rows) "
        f"достигает не менее {thr:g}× в ту или другую сторону. "
        "Такое часто связано со статистикой (ANALYZE), селективностью предикатов или корреляциями столбцов.\n\n"
    )
    for item in shown:
        node = item["node"]
        node_id = str(id(node))
        typ = item["type"]
        plan_r = item["plan"]
        actual_r = item["actual"]
        ratio = item["ratio"]
        props = node.get("properties") or {}
        rel = props.get("Relation-Name") or props.get("Alias")
        suffix = f" — {rel}" if rel else ""
        ratio_str = "∞" if ratio == float("inf") else f"{ratio:.1f}"
        analysis["general"] += (
            f"[hl][link=node://{node_id}]{typ}{suffix}[/link][/hl]\n"
            f"• Оценка: {plan_r:g}, факт: {actual_r:g}, отношение ~{ratio_str}×\n"
        )
    if len(acc) > max_n:
        analysis[
            "general"
        ] += f"\n[i]Показано {max_n} из {len(acc)} узлов с порогом ≥{thr:g}×.[/i]\n"
    analysis["general"] += (
        "\n[rec]Рекомендация: ANALYZE по затронутым таблицам; при необходимости "
        "ALTER TABLE … ALTER COLUMN … SET STATISTICS; расширенная статистика (CREATE STATISTICS).[/rec]\n\n"
    )
    return len(shown)


def _filter_text_for_scan_node(node: MutableMapping[str, Any]) -> str:
    props = node.get("properties") or {}
    ntype = node.get("type") or ""
    if ntype == "Seq Scan":
        return (props.get("Filter") or "").strip()
    if ntype == "Bitmap Heap Scan":
        return (props.get("Filter") or props.get("Recheck Cond") or "").strip()
    return ""


def confidence_stale_statistics_signal(worst_ratio: float, nodes_on_relation: int) -> int:
    """Heuristic 0–100: stronger when ratio is huge and multiple nodes implicate the same relation."""
    base = 28
    if worst_ratio == float("inf"):
        base += 42
    else:
        base += min(38, (float(worst_ratio) ** 0.5) * 3.8)
    base += min(18, nodes_on_relation * 3)
    return max(8, min(96, int(base)))


def confidence_missing_index_hypothesis(
    scan_type: str,
    cost_percent: float,
    ast_equality_count: int,
    ordered_field_count: int,
    join_field_count: int,
) -> int:
    """Heuristic 0–100 for index DDL suggestions from plan filters (not ground truth)."""
    base = 26
    base += min(24, cost_percent * 0.24)
    base += min(20, ast_equality_count * 4)
    base += min(12, join_field_count * 3)
    base += min(8, max(0, ordered_field_count - 1) * 2)
    if scan_type == "Seq Scan":
        base += 7
    elif scan_type == "Bitmap Heap Scan":
        base += 4
    return max(10, min(93, int(base)))


def append_stale_statistics_section(
    analysis: MutableMapping[str, Any],
    plan_tree: MutableMapping[str, Any],
    analyzer_settings: MutableMapping[str, Any],
) -> int:
    """Summarize plan/actual row mismatches by relation as statistics-quality signals."""
    if not analyzer_settings.get("analysis", {}).get("enable_stale_statistics_analysis", True):
        return 0

    thr = float(analyzer_settings.get("thresholds", {}).get("rows_estimate_ratio_warn", 10.0))
    min_floor = float(analyzer_settings.get("thresholds", {}).get("rows_estimate_min_rows", 1.0))
    max_rel = int(analyzer_settings.get("analysis", {}).get("max_stale_statistics_relations", 12))

    acc: List[MutableMapping[str, Any]] = []
    _collect_row_estimate_mismatch_nodes(plan_tree, thr, min_floor, acc)
    if not acc:
        return 0

    by_rel: Dict[str, List[MutableMapping[str, Any]]] = defaultdict(list)
    for item in acc:
        node = item["node"]
        props = node.get("properties") or {}
        rk = props.get("Relation-Name") or props.get("Alias") or "?"
        by_rel[str(rk)].append(item)

    analysis["general"] += "[section]Сигналы устаревшей или недостаточной статистики[/section]\n"
    analysis["general"] += (
        "По данным EXPLAIN ANALYZE: узлы, где отношение Plan Rows к Actual Rows "
        f"достигает ≥{thr:g}× (при числе строк не ниже {min_floor:g}). "
        "Такие расхождения часто связаны с устаревшим ANALYZE, недооценкой селективности "
        "или корреляциями столбцов (см. расширенную статистику CREATE STATISTICS).\n\n"
    )

    rel_summaries: List[Tuple[str, float, List[MutableMapping[str, Any]]]] = []
    for rel, items in by_rel.items():
        worst = max(
            items,
            key=lambda x: float("inf") if x["ratio"] == float("inf") else float(x["ratio"]),
        )
        wr = float("inf") if worst["ratio"] == float("inf") else float(worst["ratio"])
        rel_summaries.append((rel, wr, items))

    rel_summaries.sort(
        key=lambda x: (-(float("inf") if x[1] == float("inf") else x[1]), x[0]),
    )
    shown_rel = rel_summaries[:max_rel]
    show_conf = analyzer_settings.get("analysis", {}).get("enable_confidence_scores", True)

    for rel, worst_r, items in shown_rel:
        ratio_str = "∞" if worst_r == float("inf") else f"{worst_r:.1f}"
        analysis["general"] += f"[hl]• {rel}[/hl]\n"
        analysis["general"] += (
            f"  Худшее расхождение ~{ratio_str}× по {len(items)} узлу(ам). "
            f"Проверка: [b]ANALYZE {rel}[/b]; при сохранении проблемы — "
            "[b]ALTER TABLE … ALTER COLUMN … SET STATISTICS[/b] или "
            "[b]CREATE STATISTICS[/b] (dependencies / multivariate histograms по версии PG).\n"
        )
        if show_conf:
            conf = confidence_stale_statistics_signal(worst_r, len(items))
            analysis["general"] += f"  [i]Уверенность сигнала (эвристика): {conf}/100.[/i]\n"
        analysis["general"] += "\n"

    if len(rel_summaries) > max_rel:
        analysis["general"] += f"[i]Показано {max_rel} из {len(rel_summaries)} отношений.[/i]\n\n"
    else:
        analysis["general"] += "\n"

    return len(shown_rel)


def _build_index_hypothesis_bundle(
    node: MutableMapping[str, Any],
    join_conditions: List[str],
    order_by_fields: List[str],
    total_cost: float,
    analyzer_settings: MutableMapping[str, Any],
) -> Optional[Dict[str, Any]]:
    """Extract filter/join columns and suggested index shape for Seq Scan or Bitmap Heap Scan."""
    props = node.get("properties") or {}
    if "Relation-Name" not in props:
        return None

    table_name = props["Relation-Name"]
    filter_condition = _filter_text_for_scan_node(node)
    cost_percent = (node["cost"] / total_cost) * 100 if total_cost else 0.0
    scan_type = node.get("type") or ""

    equality_fields: List[str] = []
    range_fields: List[str] = []
    like_fields: List[Dict[str, str]] = []
    in_fields: List[str] = []
    between_fields: List[str] = []
    neq_fields: List[str] = []
    is_null_fields: List[str] = []
    is_not_null_fields: List[str] = []
    ast_equality_count = 0

    if filter_condition:
        parsed_pred = extract_predicate_fields_from_filter(filter_condition)
        ast_useful = False
        if parsed_pred is not None:
            np = parsed_pred
            ast_useful = (
                len(np["equality_fields"])
                + len(np["range_fields"])
                + len(np["like_fields"])
                + len(np["in_fields"])
                + len(np["between_fields"])
                + len(np.get("neq_fields", []))
                + len(np.get("is_null_fields", []))
                + len(np.get("is_not_null_fields", []))
            ) > 0

        if ast_useful and parsed_pred is not None:
            np = parsed_pred
            equality_fields.extend(np["equality_fields"])
            ast_equality_count = len(np["equality_fields"])
            range_fields.extend(np["range_fields"])
            like_fields.extend(np["like_fields"])
            in_fields.extend(np["in_fields"])
            between_fields.extend(np["between_fields"])
            neq_fields.extend(np.get("neq_fields", []))
            is_null_fields.extend(np.get("is_null_fields", []))
            is_not_null_fields.extend(np.get("is_not_null_fields", []))
        else:
            equality_pattern = r"(\w+)\s*=\s*(?:\'[^\']*\'|\d+)"
            range_pattern = r"(\w+)\s*(>=?|<=?)\s*(?:\'[^\']*\'|\d+)"
            like_pattern = r"(\w+)\s+LIKE\s+\'([^\']*)\'"
            in_pattern = r"(\w+)\s+IN\s*\([^)]+\)"
            between_pattern = r"(\w+)\s+BETWEEN\s+(?:\'[^\']*\'|\d+)\s+AND\s+(?:\'[^\']*\'|\d+)"

            for match in re.finditer(equality_pattern, filter_condition, re.IGNORECASE):
                equality_fields.append(match.group(1))

            for match in re.finditer(range_pattern, filter_condition, re.IGNORECASE):
                range_fields.append(match.group(1))

            for match in re.finditer(like_pattern, filter_condition, re.IGNORECASE):
                like_fields.append({"field": match.group(1), "pattern": match.group(2)})

            for match in re.finditer(in_pattern, filter_condition, re.IGNORECASE):
                in_fields.append(match.group(1))

            for match in re.finditer(between_pattern, filter_condition, re.IGNORECASE):
                between_fields.append(match.group(1))

    alias_prop = (props.get("Alias") or "").strip()
    join_fields = join_columns_for_relation(
        join_conditions,
        table_name,
        alias_prop or None,
    )

    all_fields: List[tuple] = []
    all_fields.extend([("equality", f) for f in equality_fields])
    all_fields.extend([("range", f) for f in range_fields])
    for lf in like_fields:
        if isinstance(lf, dict) and lf.get("field"):
            all_fields.append(("like", lf["field"]))
        elif isinstance(lf, str):
            all_fields.append(("like", lf))
    all_fields.extend([("in", f) for f in in_fields])
    all_fields.extend([("between", f) for f in between_fields])
    all_fields.extend([("neq", f) for f in neq_fields])
    all_fields.extend([("is_null", f) for f in is_null_fields])
    all_fields.extend([("is_not_null", f) for f in is_not_null_fields])
    all_fields.extend([("join", f) for f in join_fields])
    all_fields.extend(
        [("order", f) for f in order_by_fields if f not in [x[1] for x in all_fields]]
    )

    unique_fields: List[tuple] = []
    seen = set()
    for priority, field in all_fields:
        if field not in seen:
            seen.add(field)
            unique_fields.append((priority, field))

    if not unique_fields:
        return None

    max_fields = analyzer_settings.get("analysis", {}).get("max_index_fields", 5)
    ordered_fields: List[str] = []
    priority_order = [
        "equality",
        "join",
        "in",
        "between",
        "range",
        "neq",
        "is_null",
        "is_not_null",
        "like",
        "order",
    ]
    for priority in priority_order:
        for p, field in unique_fields[:max_fields]:
            if p == priority and field not in ordered_fields:
                ordered_fields.append(field)

    if len(ordered_fields) > max_fields:
        ordered_fields = ordered_fields[:max_fields]

    has_like = any(p == "like" for p, _ in unique_fields)
    like_info = like_fields[0] if has_like and like_fields else None

    index_type = "BTREE"
    index_options = ""

    if has_like and like_info:
        pattern = like_info.get("pattern", "")
        if pattern.startswith("%") and pattern.endswith("%"):
            index_type = "GIN"
            index_options = "gin_trgm_ops"
        elif pattern.startswith("%"):
            index_type = "GIN"
            index_options = "gin_trgm_ops"
        elif pattern.endswith("%"):
            index_type = "BTREE"
            index_options = "varchar_pattern_ops"

    dedup_key = (table_name.lower(), tuple(ordered_fields))
    conf = confidence_missing_index_hypothesis(
        scan_type,
        cost_percent,
        ast_equality_count,
        len(ordered_fields),
        len(join_fields),
    )

    return {
        "dedup_key": dedup_key,
        "sort_cost": float(node["cost"]),
        "node": node,
        "table_name": table_name,
        "filter_condition": filter_condition,
        "cost_percent": cost_percent,
        "ordered_fields": ordered_fields,
        "unique_fields": unique_fields,
        "like_fields": like_fields,
        "like_info": like_info,
        "index_type": index_type,
        "index_options": index_options,
        "join_fields": join_fields,
        "scan_type": scan_type,
        "max_fields": max_fields,
        "confidence": conf,
    }


def _append_index_hypothesis_bundle_to_optimization(
    analysis: MutableMapping[str, Any],
    bundle: Dict[str, Any],
    order_by_fields: List[str],
    analyzer_settings: MutableMapping[str, Any],
) -> None:
    """Render one consolidated index hypothesis (DDL + check + optional confidence)."""
    table_name = bundle["table_name"]
    node = bundle["node"]
    filter_condition = bundle["filter_condition"]
    cost_percent = bundle["cost_percent"]
    ordered_fields = bundle["ordered_fields"]
    unique_fields = bundle["unique_fields"]
    index_type = bundle["index_type"]
    index_options = bundle["index_options"]
    join_fields = bundle["join_fields"]
    scan_type = bundle["scan_type"]
    max_fields = bundle["max_fields"]
    confidence = bundle["confidence"]

    scan_human = (
        "Seq Scan"
        if scan_type == "Seq Scan"
        else ("Bitmap Heap Scan" if scan_type == "Bitmap Heap Scan" else scan_type)
    )
    analysis["optimization"] += (
        f"[warning]⚠️ Таблица {table_name} ({scan_human}, узел "
        f'{node["cost"]:.2f} — {cost_percent:.1f}% от плана)[/warning]\n'
    )
    if filter_condition:
        analysis["optimization"] += f"[rec]Условие фильтрации: {filter_condition}[/rec]\n"
    if join_fields:
        analysis["optimization"] += f'[rec]JOIN поля: {", ".join(join_fields)}[/rec]\n'
    if order_by_fields:
        analysis["optimization"] += f'[rec]ORDER BY поля: {", ".join(order_by_fields)}[/rec]\n'

    analysis[
        "optimization"
    ] += "[rec]Гипотеза индекса (проверяйте на копии / под нагрузкой):[/rec]\n"
    fields_str = ", ".join(ordered_fields)

    if index_type == "GIN":
        analysis["optimization"] += (
            f"[table]CREATE INDEX CONCURRENTLY idx_{table_name[:20]}_"
            f'{ordered_fields[0][:15] if ordered_fields else "opt"}_gin ON {table_name}[/table]\n'
        )
        analysis["optimization"] += f"[table]    USING GIN ({fields_str} gin_trgm_ops);[/table]\n"
    elif index_options:
        like_only = [f for p, f in unique_fields if p == "like"]
        other_f = [f for p, f in unique_fields if p != "like"]
        final_fields = like_only + other_f
        final_fields_str = ", ".join(final_fields[:max_fields])
        analysis["optimization"] += (
            f"[table]CREATE INDEX CONCURRENTLY idx_{table_name[:20]}_"
            f'{ordered_fields[0][:15] if ordered_fields else "opt"}_pattern ON {table_name}[/table]\n'
        )
        analysis["optimization"] += f"[table]    ({final_fields_str} {index_options});[/table]\n"
    else:
        analysis["optimization"] += (
            f"[table]CREATE INDEX CONCURRENTLY idx_{table_name[:20]}_"
            f'{ordered_fields[0][:15] if ordered_fields else "opt"}_idx ON {table_name}[/table]\n'
        )
        analysis["optimization"] += f"[table]    ({fields_str});[/table]\n"

    analysis["optimization"] += (
        "[rec]Ожидаемый эффект: меньше блоков / ранний отсев строк при фильтрации и соединениях по перечисленным "
        "столбцам. Цена: дополнительное место на диске и время INSERT/UPDATE/DELETE.[/rec]\n"
    )
    analysis["optimization"] += f"[rec]После создания индекса: ANALYZE {table_name};[/rec]\n"
    if filter_condition:
        analysis["optimization"] += (
            f"[i]Как проверить: EXPLAIN (ANALYZE, BUFFERS) с тем же запросом; сравнить стоимость узла "
            f"{scan_human} и общий cost.[/i]\n"
        )
    if analyzer_settings.get("analysis", {}).get("enable_confidence_scores", True):
        analysis["optimization"] += (
            f"[i]Уверенность гипотезы (эвристика): {confidence}/100 — выше при крупной доле стоимости плана, "
            "явных предикатах = и полях JOIN из плана.[/i]\n"
        )
    analysis["optimization"] += "\n"


def _collect_buffer_io_candidates(
    node: MutableMapping[str, Any],
    temp_acc: List[MutableMapping[str, Any]],
    disk_acc: List[MutableMapping[str, Any]],
    shared_read_warn_blocks: int,
) -> None:
    props = node.get("properties") or {}
    tw_raw = _int_prop(props, "Temp-Written-Blocks", "Temp Written Blocks")
    tr_raw = _int_prop(props, "Temp-Read-Blocks", "Temp Read Blocks")
    if tw_raw is not None or tr_raw is not None:
        tw = tw_raw or 0
        tr = tr_raw or 0
        if tw + tr > 0:
            temp_acc.append(
                {
                    "node": node,
                    "type": node.get("type", ""),
                    "temp_written": tw,
                    "temp_read": tr,
                    "score": tw + tr,
                }
            )

    sr_raw = _int_prop(props, "Shared-Read-Blocks", "Shared Read Blocks")
    if sr_raw is not None:
        sr = sr_raw
        thr = shared_read_warn_blocks if shared_read_warn_blocks > 0 else 1
        if sr >= thr:
            sh = _int_prop(props, "Shared-Hit-Blocks", "Shared Hit Blocks") or 0
            disk_acc.append(
                {
                    "node": node,
                    "type": node.get("type", ""),
                    "shared_read": sr,
                    "shared_hit": sh,
                }
            )

    for child in node.get("children") or []:
        _collect_buffer_io_candidates(child, temp_acc, disk_acc, shared_read_warn_blocks)


def append_buffers_io_section(
    analysis: MutableMapping[str, Any],
    plan_tree: MutableMapping[str, Any],
    analyzer_settings: MutableMapping[str, Any],
) -> Tuple[int, int]:
    """Append «буферы и ввод-вывод» for ``EXPLAIN (ANALYZE, BUFFERS)``.

    Returns ``(listed_temp_nodes, listed_disk_nodes)``.
    """
    if not analyzer_settings.get("analysis", {}).get("enable_buffers_io_analysis", True):
        return 0, 0

    sr_thr = int(analyzer_settings.get("thresholds", {}).get("buffers_shared_read_warn_blocks", 64))
    max_n = int(analyzer_settings.get("analysis", {}).get("max_buffers_io_nodes", 8))

    temp_acc: List[MutableMapping[str, Any]] = []
    disk_acc: List[MutableMapping[str, Any]] = []
    _collect_buffer_io_candidates(plan_tree, temp_acc, disk_acc, sr_thr)

    temp_acc.sort(key=lambda x: x["score"], reverse=True)
    disk_acc.sort(key=lambda x: x["shared_read"], reverse=True)

    shown_temp = temp_acc[:max_n]
    shown_disk = disk_acc[:max_n]

    if not shown_temp and not shown_disk:
        return 0, 0

    thr_disp = sr_thr if sr_thr > 0 else 1
    analysis["general"] += "[section]EXPLAIN ANALYZE: буферы и ввод-вывод[/section]\n"
    analysis["general"] += (
        "Данные из плана с опцией BUFFERS (в приложении: "
        "`EXPLAIN (ANALYZE, BUFFERS, FORMAT …)`).\n\n"
    )

    if shown_temp:
        analysis["general"] += (
            "[b]Временные файлы (спиллы sort/hash и др.)[/b]\n"
            "Узлы с ненулевым Temp Read/Write Blocks — часто не хватает `work_mem` или данных для больших "
            "операций в памяти.\n\n"
        )
        for item in shown_temp:
            node = item["node"]
            node_id = str(id(node))
            typ = item["type"]
            rel = (node.get("properties") or {}).get("Relation-Name") or (
                node.get("properties") or {}
            ).get("Alias")
            suffix = f" — {rel}" if rel else ""
            analysis["general"] += (
                f"[hl][link=node://{node_id}]{typ}{suffix}[/link][/hl]\n"
                f'• Temp Written: {item["temp_written"]}, Temp Read: {item["temp_read"]}\n'
            )
        analysis["general"] += "\n"

    if shown_disk:
        analysis["general"] += (
            f"[b]Чтение shared-буферов с диска (≥ {thr_disp} блоков)[/b]\n"
            "Высокий Shared Read при контексте cold cache или больших сканированиях; смотрите также общую долю "
            "чтений относительно попаданий в кэш по узлу.\n\n"
        )
        for item in shown_disk:
            node = item["node"]
            node_id = str(id(node))
            typ = item["type"]
            rel = (node.get("properties") or {}).get("Relation-Name") or (
                node.get("properties") or {}
            ).get("Alias")
            suffix = f" — {rel}" if rel else ""
            sr = item["shared_read"]
            sh = item["shared_hit"]
            total = sr + sh
            pct = (100.0 * sr / total) if total > 0 else 0.0
            analysis["general"] += (
                f"[hl][link=node://{node_id}]{typ}{suffix}[/link][/hl]\n"
                f"• Shared Hit: {sh}, Shared Read: {sr} (~{pct:.0f}% чтений с диска по узлу)\n"
            )
        analysis["general"] += "\n"

    if len(temp_acc) > max_n:
        analysis[
            "general"
        ] += f"[i]Временные блоки: показано {max_n} из {len(temp_acc)} узлов.[/i]\n"
    if len(disk_acc) > max_n:
        analysis[
            "general"
        ] += f"[i]Дисковые чтения: показано {max_n} из {len(disk_acc)} узлов.[/i]\n"

    analysis["general"] += (
        "[rec]Спиллы: увеличить `work_mem` для сессии или оператора (осторожно с параллелизмом); "
        "сократить объём сортировки/хеша запросом. "
        "Чтения с диска: индексы, прогрев, параметры планировщика (`random_page_cost`), актуальный ANALYZE."
        "[/rec]\n\n"
    )

    return len(shown_temp), len(shown_disk)


def analyze_plan_structure(
    plan_tree: MutableMapping[str, Any],
    analyzer_settings: MutableMapping[str, Any],
    sql_query: Optional[str] = None,
) -> Tuple[
    Dict[str, Any],
    Dict[str, Any],
]:
    """Return (analysis dict, meta with total_cost, expensive_nodes, most_expensive_node_info).

    If ``sql_query`` is provided and parses as SQL, referenced tables are listed in the analysis.
    """
    analysis: Dict[str, Any] = {
        "general": "",
        "optimization": "",
        "settings": "",
        "problems": [],
    }
    total_cost = plan_tree["cost"]

    high_cost_absolute = analyzer_settings.get("thresholds", {}).get("high_cost_absolute", 10000)

    if total_cost > high_cost_absolute:
        analysis["general"] += (
            f"[error]⚠️ Внимание: план имеет очень высокую стоимость ({total_cost:.2f})! "
            f"Требуется оптимизация.[/error]\n\n"
        )
    elif total_cost > high_cost_absolute / 2:
        analysis["general"] += (
            f"[error]⚠️ План имеет высокую стоимость ({total_cost:.2f}). "
            f"Рекомендуется оптимизация.[/error]\n\n"
        )

    op_stats: defaultdict[str, int] = defaultdict(int)

    def collect_stats(node: MutableMapping[str, Any]) -> None:
        op_stats[node["type"]] += 1
        for child in node["children"]:
            collect_stats(child)

    collect_stats(plan_tree)

    analysis["general"] += "[section]Основные метрики[/section]\n"
    analysis["general"] += f"• Общая стоимость плана: {total_cost:.2f}\n"
    analysis["general"] += f"• Всего операций: {sum(op_stats.values())}\n\n"

    if sql_query and sql_query.strip():
        rt = referenced_tables(sql_query)
        if rt:
            analysis["general"] += "[section]Объекты в тексте SQL[/section]\n"
            analysis["general"] += (
                "Упомянутые отношения (таблицы/представления): " + ", ".join(rt) + "\n\n"
            )

    append_row_estimate_vs_actual_section(analysis, plan_tree, analyzer_settings)
    append_stale_statistics_section(analysis, plan_tree, analyzer_settings)
    append_buffers_io_section(analysis, plan_tree, analyzer_settings)

    index_scan_nodes: List[MutableMapping[str, Any]] = []

    def find_index_scans(node: MutableMapping[str, Any]) -> None:
        if node["type"] in ("Index Scan", "Bitmap Index Scan", "Index Only Scan"):
            index_scan_nodes.append(node)
        for child in node["children"]:
            find_index_scans(child)

    find_index_scans(plan_tree)

    if index_scan_nodes:
        expensive_percent = analyzer_settings.get("thresholds", {}).get(
            "expensive_operation_percent", 15
        )
        expensive_indexes = [
            n for n in index_scan_nodes if (n["cost"] / total_cost) * 100 > expensive_percent
        ]
        if expensive_indexes:
            analysis["general"] += "[section]Индексы с высокой стоимостью[/section]\n"
            max_indexes_display = analyzer_settings.get("analysis", {}).get(
                "max_expensive_indexes_display", 5
            )
            for i, node in enumerate(
                sorted(expensive_indexes, key=lambda x: x["cost"], reverse=True)[
                    :max_indexes_display
                ]
            ):
                node_id = str(id(node))
                cost_percent = (node["cost"] / total_cost) * 100
                index_name = node["properties"].get("Index-Name", "неизвестный индекс")
                table_name = node["properties"].get("Relation-Name", "неизвестная таблица")

                analysis[
                    "general"
                ] += f"[hl][link=node://{node_id}]Индекс {i + 1}: {index_name}[/link][/hl]\n"
                analysis["general"] += f"• Таблица: {table_name}\n"
                analysis[
                    "general"
                ] += f'• Стоимость: {node["cost"]:.2f} ({cost_percent:.1f}% от общего плана)\n'
                if "Index-Cond" in node["properties"]:
                    analysis["general"] += f'• Условие: {node["properties"]["Index-Cond"]}\n'
                analysis["general"] += "\n"

    seq_scan_nodes: List[MutableMapping[str, Any]] = []

    def find_seq_scans(node: MutableMapping[str, Any]) -> None:
        if node["type"] == "Seq Scan":
            seq_scan_nodes.append(node)
        for child in node["children"]:
            find_seq_scans(child)

    find_seq_scans(plan_tree)

    bitmap_heap_scan_nodes: List[MutableMapping[str, Any]] = []

    def find_bitmap_heap_scans(node: MutableMapping[str, Any]) -> None:
        if node["type"] == "Bitmap Heap Scan" and "Relation-Name" in node.get("properties", {}):
            bitmap_heap_scan_nodes.append(node)
        for child in node["children"]:
            find_bitmap_heap_scans(child)

    find_bitmap_heap_scans(plan_tree)

    scan_nodes_for_index_hints: List[MutableMapping[str, Any]] = (
        list(seq_scan_nodes) + bitmap_heap_scan_nodes
    )

    table_stats: defaultdict[tuple, List[MutableMapping[str, Any]]] = defaultdict(list)
    if seq_scan_nodes:
        analysis["general"] += "[section]Анализ Seq Scan операций[/section]\n"
        analysis["general"] += (
            "Обнаружены последовательные сканирования таблиц - это может быть узким местом "
            "производительности.\n\n"
        )

        for node in seq_scan_nodes:
            if "Relation-Name" in node["properties"]:
                table_name = node["properties"]["Relation-Name"]
                alias = node["properties"].get("Alias", "")
                table_stats[(table_name, alias)].append(node)

    if table_stats:
        analysis["general"] += "Таблицы с Seq Scan:\n"
        seq_scan_warning = analyzer_settings.get("thresholds", {}).get("seq_scan_warning_cost", 150)
        for (table_name, alias), nodes in table_stats.items():
            display_name = f"{table_name} (как {alias})" if alias else table_name
            table_total_cost = sum(n["cost"] for n in nodes)
            if table_total_cost > seq_scan_warning:
                analysis["general"] += (
                    f"[error]• {display_name} ({len(nodes)} операций, "
                    f"общая стоимость: {table_total_cost:.2f})[/error]\n"
                )
            else:
                analysis["general"] += (
                    f"[seqscan]• {display_name} ({len(nodes)} операций, "
                    f"общая стоимость: {table_total_cost:.2f})[/seqscan]\n"
                )
        analysis["general"] += "\n"

    if "Nested Loop" in op_stats:
        analysis["general"] += "[section]Анализ Nested Loop операций[/section]\n"
        analysis["general"] += f"Обнаружено {op_stats['Nested Loop']} операций Nested Loop.\n\n"

    expensive_nodes: List[MutableMapping[str, Any]] = []
    expensive_fraction = (
        analyzer_settings.get("thresholds", {}).get("expensive_operation_percent", 15) / 100
    )

    def find_expensive(
        node: MutableMapping[str, Any], threshold: float = expensive_fraction
    ) -> None:
        if node["cost"] > total_cost * threshold:
            expensive_nodes.append(node)
        for child in node["children"]:
            find_expensive(child, threshold)

    find_expensive(plan_tree)

    most_expensive_node_info: Any = ""

    if expensive_nodes:
        analysis[
            "general"
        ] += f"[section]Самые ресурсоемкие операции (>{expensive_fraction * 100:.0f}% от общей стоимости)[/section]\n"
        max_expensive_display = analyzer_settings.get("analysis", {}).get(
            "max_expensive_operations_display", 5
        )
        for i, node in enumerate(
            sorted(expensive_nodes, key=lambda x: x["cost"], reverse=True)[:max_expensive_display]
        ):
            node_id = str(id(node))
            cost_percent = (node["cost"] / total_cost) * 100

            analysis[
                "general"
            ] += f'[hl][link=node://{node_id}]Операция {i + 1}: {node["type"]}[/link][/hl]\n'
            analysis[
                "general"
            ] += f'• Стоимость: {node["cost"]:.2f} ({cost_percent:.1f}% от общего плана)\n'

            if "Relation-Name" in node["properties"]:
                table_name = node["properties"]["Relation-Name"]
                alias = node["properties"].get("Alias", "")
                if alias and alias != table_name:
                    table_name = f"{table_name} (как {alias})"
                analysis["general"] += f"• Таблица: {table_name}\n"

            if "Filter" in node["properties"]:
                analysis["general"] += f'• Условие: {node["properties"]["Filter"]}\n'

            if node["type"] == "Seq Scan" and cost_percent > 15:
                analysis["general"] += "[error]⚠️ Критически высокая стоимость Seq Scan[/error]\n"

            analysis["general"] += "\n"

            raw_most = max(expensive_nodes, key=lambda x: x["cost"])
            most_expensive_node_info = remove_circular_refs(raw_most)

    analysis["optimization"] += "[title]Рекомендации по оптимизации запроса[/title]\n\n"

    if scan_nodes_for_index_hints and analyzer_settings.get("analysis", {}).get(
        "enable_index_recommendations", True
    ):
        analysis["optimization"] += (
            "[section]Рекомендации по созданию индексов[/section]\n"
            "Учитываются узлы Seq Scan и Bitmap Heap Scan с разбором Filter / Recheck Cond "
            "(плюс условия соединений и ORDER BY из плана). Одна и та же гипотеза по составу столбцов "
            "для одной таблицы объединяется (берётся узел с максимальной стоимостью).\n\n"
        )

        join_conditions: List[str] = []
        order_by_fields: List[str] = []

        def extract_join_info(node: MutableMapping[str, Any]) -> None:
            if node["type"] in ("Hash Join", "Merge Join", "Nested Loop"):
                if "Hash-Cond" in node["properties"]:
                    join_conditions.append(node["properties"]["Hash-Cond"])
                if "Join-Filter" in node["properties"]:
                    join_conditions.append(node["properties"]["Join-Filter"])
                if "Merge-Cond" in node["properties"]:
                    join_conditions.append(node["properties"]["Merge-Cond"])
            if "Sort-Key" in node["properties"] and node["type"] == "Sort":
                sk_prop = node["properties"]["Sort-Key"]
                sk_cols = sort_key_columns(sk_prop)
                if sk_cols:
                    for col in sk_cols:
                        order_by_fields.append(col.split(".")[-1].lower())
                else:
                    order_by_fields.extend(re.findall(r"[a-z_][a-z0-9_]*", sk_prop.lower()))
            for child in node.get("children", []):
                extract_join_info(child)

        extract_join_info(plan_tree)

        raw_bundles: List[Dict[str, Any]] = []
        for node in scan_nodes_for_index_hints:
            b = _build_index_hypothesis_bundle(
                node, join_conditions, order_by_fields, total_cost, analyzer_settings
            )
            if b:
                raw_bundles.append(b)

        merged: Dict[tuple, Dict[str, Any]] = {}
        for b in raw_bundles:
            key = b["dedup_key"]
            prev = merged.get(key)
            if prev is None or b["sort_cost"] > prev["sort_cost"]:
                merged[key] = b

        for bundle in sorted(merged.values(), key=lambda x: -x["sort_cost"]):
            _append_index_hypothesis_bundle_to_optimization(
                analysis, bundle, order_by_fields, analyzer_settings
            )

        if scan_nodes_for_index_hints:
            analysis[
                "optimization"
            ] += "[section]Дополнительные рекомендации по индексам[/section]\n"
            analysis[
                "optimization"
            ] += "• Используйте CONCURRENTLY для создания индексов без блокировки записи\n"
            analysis[
                "optimization"
            ] += "• Для LIKE '%text%' используйте GIN индекс с расширением pg_trgm\n"
            analysis[
                "optimization"
            ] += "• Для LIKE 'text%' используйте BTREE с varchar_pattern_ops\n"
            analysis[
                "optimization"
            ] += "• Составные индексы эффективны для нескольких условий AND\n"
            analysis[
                "optimization"
            ] += "• Поля для индекса: сначала =, потом > < BETWEEN, потом LIKE, потом ORDER BY\n\n"

    nested_loop_nodes = [n for n in expensive_nodes if n["type"] == "Nested Loop"]
    if nested_loop_nodes and analyzer_settings.get("analysis", {}).get(
        "enable_join_optimization", True
    ):
        analysis["optimization"] += "[section]Оптимизация JOIN операций[/section]\n"
        analysis["optimization"] += "Рекомендации:\n"
        analysis["optimization"] += "- Nested Loop может быть неэффективен для больших таблиц\n"
        analysis["optimization"] += "- Рассмотрите использование Hash Join или Merge Join\n"
        analysis["optimization"] += "- Проверьте, есть ли подходящие индексы для соединений\n"
        analysis["optimization"] += "- Используйте CTE (WITH) для сложных запросов\n"
        analysis["optimization"] += "- Разбейте сложный запрос на несколько простых\n\n"

    analysis["optimization"] += "[section]Оптимизация структуры запроса[/section]\n"
    analysis[
        "optimization"
    ] += "- Используйте EXISTS вместо JOIN + DISTINCT для проверки существования записей\n"
    analysis["optimization"] += "- Замените LIKE/~~* на простые сравнения, если возможно\n"
    analysis["optimization"] += "- Минимизируйте вызовы функций в WHERE условиях\n"
    analysis[
        "optimization"
    ] += "- Используйте FETCH FIRST 1 ROW ONLY вместо LIMIT 1 для лучшей читаемости\n\n"

    if analyzer_settings.get("analysis", {}).get("enable_parallel_recommendations", True):
        analysis["optimization"] += "[section]Параллельное выполнение[/section]\n"
        analysis[
            "optimization"
        ] += "- Включите параллельное выполнение: SET max_parallel_workers_per_gather = N\n"
        analysis[
            "optimization"
        ] += "- Увеличьте parallel_setup_cost и parallel_tuple_cost для больших запросов\n\n"

    analysis["settings"] += "[title]Рекомендации по настройке PostgreSQL[/title]\n\n"
    analysis["settings"] += "[section]Параметры сервера[/section]\n"
    analysis["settings"] += "- Увеличьте work_mem для сложных запросов: SET work_mem = '64MB'\n"
    analysis[
        "settings"
    ] += "- Включите параллельное выполнение: SET max_parallel_workers_per_gather = 4\n"
    analysis["settings"] += "- Обновите статистику таблиц: ANALYZE table_name\n"
    analysis["settings"] += (
        "- Увеличьте statistics_target для таблиц с плохими оценками: "
        "ALTER TABLE table_name ALTER COLUMN column_name SET STATISTICS 1000\n\n"
    )

    if analyzer_settings.get("analysis", {}).get("enable_vacuum_recommendations", True):
        analysis["settings"] += "[section]Рекомендации по обслуживанию[/section]\n"
        analysis["settings"] += "- Регулярно выполняйте VACUUM для таблиц с частыми UPDATE/DELETE\n"
        analysis[
            "settings"
        ] += "- Используйте pg_stat_user_tables для мониторинга мертвых строк\n\n"

    identify_problems(plan_tree, analysis, analyzer_settings)

    if analysis["problems"]:
        analysis["general"] += "[section]Критические проблемы[/section]\n"
        for problem in analysis["problems"]:
            analysis["general"] += f"[error]⚠️ {problem}[/error]\n"
        analysis["general"] += "\n"

    if not analysis["settings"]:
        analysis["settings"] = "[title]Рекомендации по настройке PostgreSQL[/title]\n\n"
        analysis["settings"] += "[section]Общие рекомендации[/section]\n"
        analysis["settings"] += "- Регулярно обновляйте статистику таблиц (ANALYZE)\n"
        analysis["settings"] += "- Настройте параметры памяти под вашу нагрузку\n"
        analysis["settings"] += "- Используйте pg_stat_statements для анализа производительности\n"

    meta = {
        "total_cost": total_cost,
        "expensive_nodes": expensive_nodes,
        "most_expensive_node_info": most_expensive_node_info,
    }
    return analysis, meta
