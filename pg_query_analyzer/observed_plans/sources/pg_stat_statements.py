"""Workload candidate adapter for pg_stat_statements rows."""

from __future__ import annotations

from collections import Counter
from typing import Any, Dict, Iterable, List, Sequence

from pg_query_analyzer.observed_plans.fingerprints import compute_query_fingerprint
from pg_query_analyzer.observed_plans.models import ObservedPlanSnapshot, WorkloadCandidate


def workload_candidates_from_pg_stat_rows(
    rows: Iterable[Dict[str, Any]],
    snapshots: Sequence[ObservedPlanSnapshot],
) -> List[WorkloadCandidate]:
    """Convert pg_stat_statements rows into plan-capture candidates.

    ``pg_stat_statements`` stores workload statistics, not plans. This adapter
    marks rows that have no matching observed plan by fingerprint or queryid.
    """

    fingerprint_counts = Counter(
        snapshot.query_fingerprint for snapshot in snapshots if snapshot.query_fingerprint
    )
    saved_queryids = {str(snapshot.queryid).strip() for snapshot in snapshots if snapshot.queryid}

    candidates: List[WorkloadCandidate] = []
    for row in rows:
        query_text = str(row.get("query_text") or "").strip()
        fingerprint = str(row.get("fingerprint") or "").strip()
        if not fingerprint and query_text:
            fingerprint = compute_query_fingerprint(query_text)

        queryid = _optional_str(row.get("queryid"))
        merged_queryids = tuple(
            qid
            for qid in (_optional_str(value) for value in row.get("_merged_queryids") or [])
            if qid
        )
        queryids_to_match = set(merged_queryids)
        if queryid and not queryid.startswith("Σ"):
            queryids_to_match.add(queryid)

        candidates.append(
            WorkloadCandidate(
                query_text=query_text,
                query_fingerprint=fingerprint,
                queryid=queryid,
                calls=_int_value(row.get("calls")),
                rows_sum=_int_value(row.get("rows_sum")),
                mean_ms=_float_value(row.get("mean_ms")),
                total_ms=_float_value(row.get("total_ms")),
                journal_matches=fingerprint_counts.get(fingerprint, 0) if fingerprint else 0,
                saved_queryid_match=bool(queryids_to_match & saved_queryids),
                merged_queryids=merged_queryids,
            )
        )

    candidates.sort(key=lambda candidate: candidate.total_ms, reverse=True)
    return candidates


def _optional_str(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _int_value(value: Any) -> int:
    try:
        return int(float(value or 0))
    except (TypeError, ValueError):
        return 0


def _float_value(value: Any) -> float:
    try:
        return float(value or 0.0)
    except (TypeError, ValueError):
        return 0.0
