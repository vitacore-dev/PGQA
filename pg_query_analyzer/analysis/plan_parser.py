"""Pure helpers for parsing PostgreSQL EXPLAIN plans."""

from __future__ import annotations

import json
import xml.etree.ElementTree as ET

POSTGRES_EXPLAIN_NS = {"ns": "http://www.postgresql.org/2009/explain"}


def looks_like_plan_json(text: str) -> bool:
    """Heuristic: PostgreSQL JSON EXPLAIN is a JSON array or object."""
    s = text.lstrip()
    return s.startswith(("[", "{"))


def parse_plan_document(content: str):
    """Parse PostgreSQL EXPLAIN output as XML or JSON into the internal plan-tree structure."""
    if not content or not content.strip():
        raise ValueError("Пустой документ плана")
    if looks_like_plan_json(content):
        return parse_json_plan(content)
    return parse_xml_plan(content)


def journal_preview_parts_from_plan_doc(plan_doc: str) -> list[str]:
    """Metadata lines for journal entries (тип / стоимость корня плана)."""
    tree = parse_plan_document(plan_doc)
    return [
        f"Тип: {tree['type']}",
        f"Стоимость: {tree['cost']}",
    ]


def accumulate_plan_statistics_from_tree(plan_tree: dict) -> dict:
    """Build journal-style stats dict from an internal plan tree (XML or JSON source)."""
    stats: dict = {
        "total_cost": plan_tree["cost"],
        "total_rows": plan_tree["rows"],
        "operations": {},
        "seq_scans": 0,
    }

    def walk(node: dict) -> None:
        nt = node["type"]
        stats["operations"][nt] = stats["operations"].get(nt, 0) + 1
        if nt == "Seq Scan":
            stats["seq_scans"] += 1
        for child in node.get("children", []):
            walk(child)

    walk(plan_tree)
    return stats


def parse_xml_plan(xml_content):
    """Parse PostgreSQL EXPLAIN XML into the internal plan-tree structure."""
    try:
        xml_content = xml_content.strip()
        if xml_content.startswith("<?xml"):
            xml_content = xml_content.split("?>", 1)[1].strip()

        root = ET.fromstring(xml_content)
    except ET.ParseError as e:
        raise ValueError(f"Ошибка разбора XML: {e}") from e

    query = root.find("ns:Query", POSTGRES_EXPLAIN_NS)
    if query is None:
        raise ValueError("Не найден элемент Query в XML")

    plan = query.find("ns:Plan", POSTGRES_EXPLAIN_NS)
    if plan is None:
        raise ValueError("Не найден элемент Plan в XML")

    return build_plan_tree(plan, POSTGRES_EXPLAIN_NS)


def _extract_plan_root_from_json(raw: object) -> dict:
    """Return the JSON object under Plan (PostgreSQL EXPLAIN FORMAT JSON)."""
    if isinstance(raw, list):
        for item in raw:
            if isinstance(item, dict) and "Plan" in item:
                return item["Plan"]
        raise ValueError("Не найден ключ Plan в JSON EXPLAIN")
    if isinstance(raw, dict):
        if "Plan" in raw:
            return raw["Plan"]
        if "Node Type" in raw:
            return raw
    raise ValueError("Не удалось распознать структуру JSON EXPLAIN")


def _json_scalar_to_property_text(val: object) -> str:
    if isinstance(val, bool):
        return "true" if val else "false"
    if val is None:
        return ""
    return str(val)


def _json_key_to_internal_property_key(key: str) -> str:
    """PostgreSQL JSON uses Title Case With Spaces; internal tree matches XML hyphen keys."""
    return key.replace(" ", "-")


def parse_json_plan(json_content: str):
    """Parse PostgreSQL EXPLAIN JSON into the same internal plan-tree structure as XML."""
    try:
        raw = json.loads(json_content.strip())
    except json.JSONDecodeError as e:
        raise ValueError(f"Ошибка разбора JSON: {e}") from e

    plan_root = _extract_plan_root_from_json(raw)
    return build_plan_tree_from_json(plan_root, depth=0)


def build_plan_tree_from_json(plan_obj: dict, depth: int = 0, parent=None):
    """Build internal tree dict from one JSON Plan object (recursive)."""
    node_type = plan_obj.get("Node Type")
    if not node_type:
        raise ValueError("В JSON плане отсутствует Node Type")

    properties = {}
    for key, val in plan_obj.items():
        if key in ("Plans", "Node Type"):
            continue
        hk = _json_key_to_internal_property_key(key)
        if isinstance(val, (dict, list)):
            properties[hk] = json.dumps(val, ensure_ascii=False)
        else:
            properties[hk] = _json_scalar_to_property_text(val)

    total_cost_raw = plan_obj.get("Total Cost", properties.get("Total-Cost", 0))
    try:
        total_cost = float(total_cost_raw)
    except (TypeError, ValueError):
        total_cost = 0.0

    plan_rows_raw = plan_obj.get("Plan Rows", properties.get("Plan-Rows", 0))
    try:
        plan_rows = int(float(plan_rows_raw))
    except (TypeError, ValueError):
        plan_rows = 0

    plan_node = {
        "id": id(plan_obj),
        "type": node_type,
        "properties": properties,
        "children": [],
        "cost": total_cost,
        "rows": plan_rows,
        "depth": depth,
    }

    subplans = plan_obj.get("Plans") or []
    for child in subplans:
        if isinstance(child, dict):
            child_node = build_plan_tree_from_json(child, depth + 1, plan_node)
            if child_node:
                plan_node["children"].append(child_node)

    return plan_node


def build_plan_tree(node, ns=POSTGRES_EXPLAIN_NS, parent=None, depth=0):
    """Build a nested dictionary tree from a PostgreSQL XML Plan element."""
    node_type = node.find("ns:Node-Type", ns)
    if node_type is None:
        return None

    properties = {
        child.tag.split("}")[1]: child.text
        for child in node
        if not child.tag.endswith("Plans") and child.text and child.text.strip()
    }

    plan_node = {
        "id": id(node),
        "type": node_type.text,
        "properties": properties,
        "children": [],
        "cost": float(properties.get("Total-Cost", 0)),
        "rows": int(float(properties.get("Plan-Rows", 0))),
        "depth": depth,
    }

    plans = node.find("ns:Plans", ns)
    if plans is not None:
        for plan in plans.findall("ns:Plan", ns):
            child_node = build_plan_tree(plan, ns, plan_node, depth + 1)
            if child_node:
                plan_node["children"].append(child_node)

    return plan_node
