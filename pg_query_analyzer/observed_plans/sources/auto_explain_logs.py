"""Import PostgreSQL auto_explain JSON plans from log text."""

from __future__ import annotations

import datetime
import hashlib
import json
import re
from typing import Any, Dict, List, Optional

from pg_query_analyzer.analysis.plan_parser import parse_plan_document
from pg_query_analyzer.observed_plans.fingerprints import (
    compute_plan_hash,
    compute_query_fingerprint,
)


def journal_entries_from_auto_explain_log(
    log_content: str,
    *,
    source_name: str = "auto_explain",
    captured_at: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Extract JSON plans from auto_explain logs as legacy journal entries.

    Supported inputs:
    - raw ``EXPLAIN (FORMAT JSON)`` document;
    - text logs containing ``duration: ... ms plan:`` followed by optional
      ``Query Text: ...`` and a JSON plan array/object.
    """

    content = log_content or ""
    if not content.strip():
        return []

    captured = captured_at or datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    raw_plan = _raw_plan_document(content)
    if raw_plan:
        return [_journal_entry(raw_plan, "", source_name, captured, 0, None)]

    entries: List[Dict[str, Any]] = []
    markers = list(_iter_plan_markers(content))
    for idx, marker in enumerate(markers):
        block_end = markers[idx + 1].start() if idx + 1 < len(markers) else len(content)
        block = content[marker.end() : block_end]
        query_text = _extract_query_text(block)
        plan_doc = _extract_plan_document_from_block(block)
        if not plan_doc:
            continue

        duration_ms = _duration_from_marker(marker.group(0))
        entries.append(
            _journal_entry(
                plan_doc,
                query_text,
                source_name,
                captured,
                idx,
                duration_ms,
            )
        )
    return entries


def auto_explain_dedup_key(entry: Dict[str, Any]) -> str:
    """Stable key for avoiding duplicate auto_explain imports."""

    query_fingerprint = compute_query_fingerprint(str(entry.get("query") or ""))
    plan_doc = str(entry.get("xml_content") or "")
    try:
        plan_hash = compute_plan_hash(plan_doc)
    except Exception:
        plan_hash = hashlib.sha256(plan_doc.encode("utf-8")).hexdigest()
    duration = entry.get("auto_explain_duration_ms")
    raw = "|".join(["auto_explain", query_fingerprint, plan_hash, str(duration or "")])
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def append_auto_explain_entries_deduped(
    existing_entries: List[Dict[str, Any]],
    new_entries: List[Dict[str, Any]],
) -> tuple[List[Dict[str, Any]], int]:
    """Append auto_explain entries, skipping records with the same import key."""

    result = list(existing_entries)
    seen = {
        str(entry.get("auto_explain_import_key") or auto_explain_dedup_key(entry))
        for entry in result
        if entry.get("plan_origin") == "auto_explain"
    }
    added = 0
    for entry in new_entries:
        key = str(entry.get("auto_explain_import_key") or auto_explain_dedup_key(entry))
        if key in seen:
            continue
        entry = dict(entry)
        entry["auto_explain_import_key"] = key
        result.append(entry)
        seen.add(key)
        added += 1
    return result, added


def _raw_plan_document(content: str) -> str:
    stripped = content.strip()
    if not stripped or stripped[0] not in "[{":
        return ""
    try:
        parse_plan_document(stripped)
    except Exception:
        return ""
    return stripped


def _iter_plan_markers(content: str):
    return re.finditer(r"duration:\s*[\d.]+\s*ms\s+plan:", content, flags=re.IGNORECASE)


def _extract_query_text(block: str) -> str:
    match = re.search(r"(?im)^\s*Query Text:\s*(?P<query>.+?)\s*$", block)
    return match.group("query").strip() if match else ""


def _find_json_start(block: str) -> Optional[int]:
    candidates = [idx for idx in (block.find("["), block.find("{")) if idx >= 0]
    return min(candidates) if candidates else None


def _extract_plan_document_from_block(block: str) -> str:
    for idx, ch in enumerate(block):
        if ch not in "[{":
            continue
        candidate = _extract_balanced_json(block[idx:])
        if not candidate:
            continue
        try:
            parse_plan_document(candidate)
        except Exception:
            continue
        return candidate
    return ""


def _extract_balanced_json(text: str) -> str:
    if not text:
        return ""

    opener = text[0]
    closer = "]" if opener == "[" else "}"
    depth = 0
    in_string = False
    escape = False

    for idx, ch in enumerate(text):
        if in_string:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_string = False
            continue

        if ch == '"':
            in_string = True
        elif ch == opener:
            depth += 1
        elif ch == closer:
            depth -= 1
            if depth == 0:
                candidate = text[: idx + 1].strip()
                try:
                    json.loads(candidate)
                except json.JSONDecodeError:
                    return ""
                return candidate

    return ""


def _duration_from_marker(marker_text: str) -> Optional[float]:
    match = re.search(r"duration:\s*(?P<duration>[\d.]+)\s*ms", marker_text, flags=re.IGNORECASE)
    if not match:
        return None
    try:
        return float(match.group("duration"))
    except ValueError:
        return None


def _journal_entry(
    plan_doc: str,
    query_text: str,
    source_name: str,
    captured_at: str,
    index: int,
    duration_ms: Optional[float],
) -> Dict[str, Any]:
    suffix = f" #{index + 1}" if index else ""
    entry: Dict[str, Any] = {
        "timestamp": captured_at if index == 0 else f"{captured_at}.{index:03d}",
        "execution_time": captured_at[-8:] if len(captured_at) >= 8 else captured_at,
        "source_type": "file",
        "source_name": source_name,
        "query_parts": ["Источник: auto_explain", f"Файл: {source_name}{suffix}"],
        "xml_content": plan_doc,
        "query": query_text,
        "custom_name": f"auto_explain{suffix}",
        "description": "",
        "plan_origin": "auto_explain",
    }
    if duration_ms is not None:
        entry["auto_explain_duration_ms"] = duration_ms
    entry["auto_explain_import_key"] = auto_explain_dedup_key(entry)
    return entry
