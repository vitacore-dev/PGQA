"""Legacy query journal adapter for observed plan snapshots."""

from __future__ import annotations

import hashlib
from typing import Any, Dict, Iterable, List, Optional

from pg_query_analyzer.observed_plans.fingerprints import (
    compute_plan_hash,
    compute_plan_shape_hash,
    compute_query_fingerprint,
)
from pg_query_analyzer.observed_plans.models import ObservedPlanSnapshot
from pg_query_analyzer.observed_plans.summaries import summarize_plan_document
from pg_query_analyzer.storage.journal import JOURNAL_FILE, load_journal_entries


def load_observed_snapshots_from_journal(
    journal_file: str = JOURNAL_FILE,
) -> List[ObservedPlanSnapshot]:
    return observed_snapshots_from_journal_entries(load_journal_entries(journal_file))


def observed_snapshots_from_journal_entries(
    entries: Iterable[Dict[str, Any]],
) -> List[ObservedPlanSnapshot]:
    snapshots: List[ObservedPlanSnapshot] = []
    for entry in entries:
        snapshot = observed_snapshot_from_journal_entry(entry)
        if snapshot is not None:
            snapshots.append(snapshot)
    return snapshots


def observed_snapshot_from_journal_entry(
    entry: Dict[str, Any],
) -> Optional[ObservedPlanSnapshot]:
    plan_document = str(entry.get("xml_content") or "")
    if not plan_document.strip():
        return None

    query_text = str(entry.get("query") or "")
    normalized_query = compute_query_fingerprint(query_text)
    source = _snapshot_source(entry)

    try:
        summary = summarize_plan_document(plan_document)
        plan_hash = compute_plan_hash(plan_document)
        plan_shape_hash = compute_plan_shape_hash(plan_document)
    except Exception:
        summary = summarize_plan_document_fallback()
        plan_hash = ""
        plan_shape_hash = ""

    return ObservedPlanSnapshot(
        snapshot_id=_snapshot_id(entry),
        captured_at=str(entry.get("timestamp") or ""),
        source=source,
        query_text=query_text,
        normalized_query=normalized_query,
        query_fingerprint=normalized_query,
        queryid=_optional_str(entry.get("statement_queryid")),
        plan_document=plan_document,
        plan_hash=plan_hash,
        plan_shape_hash=plan_shape_hash,
        summary=summary,
        source_name=str(entry.get("source_name") or ""),
        hypopg_pair_group_id=_optional_str(entry.get("hypopg_pair_group_id")),
        hypopg_pair_role=_optional_str(entry.get("hypopg_pair_role")),
        metadata={
            "legacy_source_type": entry.get("source_type"),
            "legacy_plan_origin": entry.get("plan_origin"),
            "custom_name": entry.get("custom_name"),
            "description": entry.get("description"),
        },
    )


def summarize_plan_document_fallback():
    from pg_query_analyzer.observed_plans.models import PlanSummary

    return PlanSummary()


def _snapshot_id(entry: Dict[str, Any]) -> str:
    raw = "|".join(
        [
            str(entry.get("timestamp") or ""),
            str(entry.get("source_name") or ""),
            str(entry.get("statement_queryid") or ""),
            str(entry.get("hypopg_pair_group_id") or ""),
        ]
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _snapshot_source(entry: Dict[str, Any]) -> str:
    origin = str(entry.get("plan_origin") or "")
    source_type = str(entry.get("source_type") or "")
    if origin == "hypopg" or source_type == "hypopg":
        return "hypopg"
    if origin == "auto_explain":
        return "auto_explain"
    if origin == "file" or source_type == "file":
        return "file"
    if origin:
        return origin
    return "manual"


def _optional_str(value: Any) -> Optional[str]:
    if value is None:
        return None
    text = str(value).strip()
    return text or None
