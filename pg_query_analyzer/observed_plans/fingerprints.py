"""Stable fingerprints for queries and plan shapes."""

from __future__ import annotations

import hashlib
import json
from typing import Any, Dict

from pg_query_analyzer.analysis.plan_parser import parse_plan_document
from pg_query_analyzer.analysis.sql_normalize import normalize_query_text


def compute_query_fingerprint(query_text: str) -> str:
    return normalize_query_text(query_text or "")


def compute_plan_hash(plan_document: str) -> str:
    """Hash the full parsed plan tree, excluding process-local object ids."""

    tree = parse_plan_document(plan_document)
    return _sha256_json(_canonical_plan_tree(tree, shape_only=False))


def compute_plan_shape_hash(plan_document: str) -> str:
    """Hash plan topology and key identifiers while ignoring costs/timings."""

    tree = parse_plan_document(plan_document)
    return _sha256_json(_canonical_plan_tree(tree, shape_only=True))


def _sha256_json(payload: Dict[str, Any]) -> str:
    raw = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _canonical_plan_tree(node: Dict[str, Any], *, shape_only: bool) -> Dict[str, Any]:
    props = dict(node.get("properties") or {})
    canonical: Dict[str, Any] = {
        "type": node.get("type", ""),
        "relation": props.get("Relation-Name") or props.get("Relation Name") or "",
        "index": props.get("Index-Name") or props.get("Index Name") or "",
        "children": [
            _canonical_plan_tree(child, shape_only=shape_only)
            for child in node.get("children", [])
            if isinstance(child, dict)
        ],
    }

    if not shape_only:
        canonical.update(
            {
                "cost": node.get("cost"),
                "rows": node.get("rows"),
                "properties": {
                    key: props[key]
                    for key in sorted(props)
                    if key not in {"Parent-Relationship", "Subplan-Name"}
                },
            }
        )

    return canonical
