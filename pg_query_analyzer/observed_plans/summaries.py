"""Extract compact metrics from parsed PostgreSQL plans."""

from __future__ import annotations

from typing import Any, Dict, Iterable, Optional

from pg_query_analyzer.analysis.plan_parser import parse_plan_document
from pg_query_analyzer.observed_plans.models import PlanSummary


def summarize_plan_document(plan_document: str) -> PlanSummary:
    tree = parse_plan_document(plan_document)
    return summarize_plan_tree(tree)


def summarize_plan_tree(plan_tree: Dict[str, Any]) -> PlanSummary:
    props = plan_tree.get("properties") or {}
    totals = {
        "node_count": 0,
        "seq_scan_count": 0,
        "temp_written_blocks": 0,
        "shared_read_blocks": 0,
        "shared_hit_blocks": 0,
    }

    for node in _walk(plan_tree):
        node_props = node.get("properties") or {}
        totals["node_count"] += 1
        if node.get("type") == "Seq Scan":
            totals["seq_scan_count"] += 1
        totals["temp_written_blocks"] += _int_prop(
            node_props,
            "Temp-Written-Blocks",
            "Temp Written Blocks",
        )
        totals["shared_read_blocks"] += _int_prop(
            node_props,
            "Shared-Read-Blocks",
            "Shared Read Blocks",
        )
        totals["shared_hit_blocks"] += _int_prop(
            node_props,
            "Shared-Hit-Blocks",
            "Shared Hit Blocks",
        )

    return PlanSummary(
        top_node_type=str(plan_tree.get("type") or ""),
        total_cost=_float_value(plan_tree.get("cost")),
        plan_rows=_int_value(plan_tree.get("rows")),
        actual_total_time=_float_prop(props, "Actual-Total-Time", "Actual Total Time"),
        actual_rows=_float_prop(props, "Actual-Rows", "Actual Rows"),
        node_count=totals["node_count"],
        seq_scan_count=totals["seq_scan_count"],
        temp_written_blocks=totals["temp_written_blocks"],
        shared_read_blocks=totals["shared_read_blocks"],
        shared_hit_blocks=totals["shared_hit_blocks"],
    )


def _walk(node: Dict[str, Any]) -> Iterable[Dict[str, Any]]:
    yield node
    for child in node.get("children") or []:
        if isinstance(child, dict):
            yield from _walk(child)


def _float_prop(props: Dict[str, Any], *names: str) -> Optional[float]:
    for name in names:
        parsed = _float_value(props.get(name))
        if parsed is not None:
            return parsed
    return None


def _int_prop(props: Dict[str, Any], *names: str) -> int:
    for name in names:
        parsed = _int_value(props.get(name))
        if parsed is not None:
            return parsed
    return 0


def _float_value(value: Any) -> Optional[float]:
    if value is None or value == "":
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _int_value(value: Any) -> Optional[int]:
    parsed = _float_value(value)
    if parsed is None:
        return None
    return int(parsed)
