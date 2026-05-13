"""Structured comparisons between observed plan snapshots."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, List, Optional

from pg_query_analyzer.observed_plans.models import ObservedPlanSnapshot


@dataclass(frozen=True)
class PlanDiffItem:
    severity: str
    title: str
    before_value: Any = None
    after_value: Any = None
    details: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "severity": self.severity,
            "title": self.title,
            "before_value": self.before_value,
            "after_value": self.after_value,
            "details": self.details,
        }


def diff_snapshots(before: ObservedPlanSnapshot, after: ObservedPlanSnapshot) -> List[PlanDiffItem]:
    items: List[PlanDiffItem] = []

    if (
        before.plan_shape_hash
        and after.plan_shape_hash
        and before.plan_shape_hash != after.plan_shape_hash
    ):
        items.append(
            PlanDiffItem(
                severity="info",
                title="Изменилась форма плана",
                before_value=before.plan_shape_hash[:12],
                after_value=after.plan_shape_hash[:12],
            )
        )

    _append_numeric_delta(
        items,
        title="Изменилась общая стоимость",
        before_value=before.summary.total_cost,
        after_value=after.summary.total_cost,
        regression_when_higher=True,
    )
    _append_numeric_delta(
        items,
        title="Изменилось фактическое время выполнения",
        before_value=before.summary.actual_total_time,
        after_value=after.summary.actual_total_time,
        regression_when_higher=True,
    )
    _append_numeric_delta(
        items,
        title="Изменилось количество Seq Scan",
        before_value=before.summary.seq_scan_count,
        after_value=after.summary.seq_scan_count,
        regression_when_higher=True,
    )
    _append_numeric_delta(
        items,
        title="Изменилась запись во временные блоки",
        before_value=before.summary.temp_written_blocks,
        after_value=after.summary.temp_written_blocks,
        regression_when_higher=True,
    )

    if before.summary.top_node_type != after.summary.top_node_type:
        items.append(
            PlanDiffItem(
                severity="info",
                title="Изменился корневой узел плана",
                before_value=before.summary.top_node_type,
                after_value=after.summary.top_node_type,
            )
        )

    return items


def _append_numeric_delta(
    items: List[PlanDiffItem],
    *,
    title: str,
    before_value: Optional[float],
    after_value: Optional[float],
    regression_when_higher: bool,
) -> None:
    if before_value is None or after_value is None or before_value == after_value:
        return

    is_regression = (
        after_value > before_value if regression_when_higher else after_value < before_value
    )
    severity = "warning" if is_regression else "success"
    details = ""
    if before_value:
        pct = ((after_value - before_value) / before_value) * 100
        details = f"{pct:+.1f}%"

    items.append(
        PlanDiffItem(
            severity=severity,
            title=title,
            before_value=before_value,
            after_value=after_value,
            details=details,
        )
    )
