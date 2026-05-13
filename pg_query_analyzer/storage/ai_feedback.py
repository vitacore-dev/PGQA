"""Persistence for user feedback on AI outputs."""

from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from typing import Any

from pg_query_analyzer.storage.json_io import atomic_write_json

AI_FEEDBACK_FILE = "ai_feedback.json"


def _feedback_path() -> str:
    pkg_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(pkg_root, AI_FEEDBACK_FILE)


def load_feedback_events() -> list[dict[str, Any]]:
    path = _feedback_path()
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, list):
            return [x for x in data if isinstance(x, dict)]
    except FileNotFoundError:
        return []
    except Exception:
        return []
    return []


def append_feedback_event(
    feature: str, rating: str, model: str, metadata: dict[str, Any] | None = None
):
    events = load_feedback_events()
    events.append(
        {
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "feature": str(feature or ""),
            "rating": str(rating or ""),
            "model": str(model or ""),
            "metadata": metadata or {},
        }
    )
    atomic_write_json(_feedback_path(), events, indent=2, ensure_ascii=False)


def summarize_feedback(events: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    data = events if events is not None else load_feedback_events()
    total = 0
    useful = 0
    not_useful = 0
    by_feature: dict[str, dict[str, int]] = {}
    for ev in data:
        if not isinstance(ev, dict):
            continue
        rating = str(ev.get("rating") or "")
        feature = str(ev.get("feature") or "unknown")
        if rating not in {"useful", "not_useful"}:
            continue
        total += 1
        if rating == "useful":
            useful += 1
        else:
            not_useful += 1
        feature_bucket = by_feature.setdefault(feature, {"useful": 0, "not_useful": 0, "total": 0})
        feature_bucket[rating] += 1
        feature_bucket["total"] += 1
    useful_ratio = (useful / total * 100.0) if total else 0.0
    return {
        "total": total,
        "useful": useful,
        "not_useful": not_useful,
        "useful_ratio": useful_ratio,
        "by_feature": by_feature,
    }
