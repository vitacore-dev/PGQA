"""PostgreSQL SQL helpers backed by pglast (extract tables, predicates, ORDER BY columns, JOIN pairs)."""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

from pglast import parse_sql
from pglast.ast import (
    A_Const,
    A_Expr,
    BoolExpr,
    ColumnRef,
    Node,
    NullTest,
    String,
    TypeCast,
)
from pglast.enums import A_Expr_Kind, BoolExprType, NullTestType
from pglast.parser import ParseError
from pglast.visitors import referenced_relations


def referenced_tables(sql: str) -> List[str]:
    """Return sorted bare relation names referenced in SQL (tables/views). Empty if parse fails."""
    if not sql or not sql.strip():
        return []
    try:
        rels = referenced_relations(parse_sql(sql.strip()))
        return sorted(rels)
    except ParseError:
        return []


def sort_key_columns(sort_key_property: str) -> List[str]:
    """Extract ORDER BY column identifiers from EXPLAIN ``Sort Key`` text. Empty if parse fails."""
    sk = (sort_key_property or "").strip()
    if not sk:
        return []
    try:
        stmts = parse_sql(f"SELECT 1 ORDER BY {sk}")
    except ParseError:
        return []

    stmt = stmts[0].stmt
    sort_clause = getattr(stmt, "sortClause", None)
    if not sort_clause:
        return []

    out: List[str] = []
    for sb in sort_clause:
        out.extend(_column_strings_from_sort_expr(sb.node))
    return out


def _column_strings_from_sort_expr(node: Node) -> List[str]:
    if isinstance(node, ColumnRef):
        s = _column_ref_sql(node)
        return [s] if s else []
    return []


def _column_ref_sql(cr: ColumnRef) -> str:
    parts: List[str] = []
    for f in cr.fields:
        if isinstance(f, String):
            parts.append(f.sval)
    return ".".join(parts)


def _bare_column_name(node: Optional[Node]) -> Optional[str]:
    if isinstance(node, ColumnRef):
        parts: List[str] = []
        for f in node.fields:
            if isinstance(f, String):
                parts.append(f.sval)
        return parts[-1] if parts else None
    return None


def _const_string(node: Optional[Node]) -> Optional[str]:
    if isinstance(node, A_Const) and not node.isnull and node.val is not None:
        val = node.val
        if hasattr(val, "sval"):
            return val.sval
        if hasattr(val, "ival"):
            return str(val.ival)
    return None


def extract_predicate_fields_from_filter(filter_condition: str) -> Optional[Dict[str, Any]]:
    """Parse Seq Scan ``Filter`` property into buckets compatible with plan_analyzer regex output.

    Returns ``None`` if the fragment cannot be parsed as SQL WHERE (fallback to regex).
    """
    fc = (filter_condition or "").strip()
    if not fc:
        return None
    try:
        stmts = parse_sql(f"SELECT 1 WHERE {fc}")
    except ParseError:
        return None

    wc = stmts[0].stmt.whereClause
    if wc is None:
        return None

    buckets: Dict[str, Any] = {
        "equality_fields": [],
        "range_fields": [],
        "like_fields": [],
        "in_fields": [],
        "between_fields": [],
        "neq_fields": [],
        "is_null_fields": [],
        "is_not_null_fields": [],
    }
    _walk_where_predicate(wc, buckets)

    return buckets


def _walk_where_predicate(expr: Optional[Node], buckets: Dict[str, Any]) -> None:
    if expr is None:
        return
    if isinstance(expr, BoolExpr):
        if expr.boolop == BoolExprType.NOT_EXPR and expr.args:
            inner = expr.args[0]
            if isinstance(inner, NullTest):
                col = _bare_column_name(inner.arg)
                if inner.nulltesttype == NullTestType.IS_NULL and col:
                    buckets.setdefault("is_not_null_fields", []).append(col)
                    return
                if inner.nulltesttype == NullTestType.IS_NOT_NULL and col:
                    buckets.setdefault("is_null_fields", []).append(col)
                    return
            if isinstance(inner, A_Expr):
                ik = inner.kind
                ble = _bare_column_name(inner.lexpr)
                if ik == A_Expr_Kind.AEXPR_OP and inner.name:
                    opi = inner.name[0].sval if inner.name else ""
                    if opi == "=" and ble:
                        buckets.setdefault("neq_fields", []).append(ble)
                        return
            _walk_where_predicate(inner, buckets)
            return
        for arg in expr.args:
            _walk_where_predicate(arg, buckets)
        return

    if isinstance(expr, NullTest):
        col = _bare_column_name(expr.arg)
        if col:
            if expr.nulltesttype == NullTestType.IS_NULL:
                buckets.setdefault("is_null_fields", []).append(col)
            elif expr.nulltesttype == NullTestType.IS_NOT_NULL:
                buckets.setdefault("is_not_null_fields", []).append(col)
        return

    if not isinstance(expr, A_Expr):
        return

    kind = expr.kind
    lexpr = expr.lexpr
    rexpr = expr.rexpr

    bare_left = _bare_column_name(lexpr)

    if kind == A_Expr_Kind.AEXPR_OP:
        op = expr.name[0].sval if expr.name else ""
        if bare_left and op == "=":
            buckets.setdefault("equality_fields", []).append(bare_left)
        elif bare_left and op in (">", "<", ">=", "<="):
            buckets.setdefault("range_fields", []).append(bare_left)
        elif bare_left and op in ("<>", "!="):
            buckets.setdefault("neq_fields", []).append(bare_left)
        return

    if kind in (A_Expr_Kind.AEXPR_LIKE, A_Expr_Kind.AEXPR_ILIKE):
        pat = _const_string(rexpr)
        if bare_left and pat is not None:
            buckets.setdefault("like_fields", []).append({"field": bare_left, "pattern": pat})
        return

    if kind == A_Expr_Kind.AEXPR_IN:
        if bare_left:
            buckets.setdefault("in_fields", []).append(bare_left)
        return

    if kind in (
        A_Expr_Kind.AEXPR_BETWEEN,
        A_Expr_Kind.AEXPR_NOT_BETWEEN,
        A_Expr_Kind.AEXPR_BETWEEN_SYM,
        A_Expr_Kind.AEXPR_NOT_BETWEEN_SYM,
    ):
        if bare_left:
            buckets.setdefault("between_fields", []).append(bare_left)
        return


def _column_expr_sql(node: Optional[Node]) -> Optional[str]:
    """Return dotted column SQL for equality join sides (unwraps casts to a single column ref)."""
    if node is None:
        return None
    if isinstance(node, ColumnRef):
        s = _column_ref_sql(node)
        return s if s else None
    if isinstance(node, TypeCast):
        return _column_expr_sql(node.arg)
    return None


def _walk_join_equalities(expr: Optional[Node], pairs: List[Tuple[str, str]]) -> None:
    if expr is None:
        return
    if isinstance(expr, BoolExpr):
        for arg in expr.args:
            _walk_join_equalities(arg, pairs)
        return
    if not isinstance(expr, A_Expr):
        return

    kind = expr.kind
    if kind != A_Expr_Kind.AEXPR_OP:
        return
    op = expr.name[0].sval if expr.name else ""
    if op != "=":
        return
    ls = _column_expr_sql(expr.lexpr)
    rs = _column_expr_sql(expr.rexpr)
    if ls and rs:
        pairs.append((ls, rs))


def extract_join_equality_pairs(join_fragment: str) -> Optional[List[Tuple[str, str]]]:
    """Parse EXPLAIN ``Hash/Merge Cond`` or ``Join-Filter`` text as SQL equalities between column refs.

    Returns ``None`` if the fragment is not valid as a ``WHERE`` clause (caller may use regex).
    Returns an empty list when parsed but no ``col = col`` pairs were found.
    """
    jc = (join_fragment or "").strip()
    if not jc:
        return []
    try:
        stmts = parse_sql(f"SELECT 1 WHERE {jc}")
    except ParseError:
        return None

    wc = stmts[0].stmt.whereClause
    if wc is None:
        return []

    pairs: List[Tuple[str, str]] = []
    _walk_join_equalities(wc, pairs)
    return pairs


def _bare_ident_from_qualified(qualified: str) -> str:
    parts = [p.strip() for p in qualified.split(".")]
    return parts[-1].strip('"') if parts else qualified


def _column_matches_relation(col_sql: str, relation_name: str, alias: Optional[str]) -> bool:
    col_sql = col_sql.strip()
    rel_l = relation_name.lower().strip('"')
    al = alias.lower().strip('"') if alias else ""
    parts = [p.strip('"') for p in col_sql.split(".")]
    if len(parts) >= 2:
        q0 = parts[0].lower()
        return q0 == rel_l or (bool(al) and q0 == al)
    if len(parts) == 1:
        bare = parts[0].lower()
        return bare == rel_l or (bool(al) and bare == al)
    return False


def _join_regex_fallback(join_fragment: str, relation_name: str, alias: Optional[str]) -> List[str]:
    """Legacy ``word = word`` extraction; keep for fragments that do not parse as SQL."""
    rel_l = relation_name.lower()
    al = alias.lower() if alias else ""
    out: List[str] = []

    def side_matches(side: str) -> bool:
        sl = side.lower()
        return rel_l in sl or (bool(al) and al in sl)

    for match in re.finditer(r"(\w+)\s*=\s*(\w+)", join_fragment, re.IGNORECASE):
        g1, g2 = match.group(1), match.group(2)
        if side_matches(g1) or side_matches(g2):
            pick = g1 if side_matches(g1) else g2
            out.append(pick)
    return out


def join_columns_for_relation(
    join_conditions: List[str],
    relation_name: str,
    alias: Optional[str] = None,
) -> List[str]:
    """Bare column names from join strings that belong to ``relation_name`` (or ``alias``).

    Uses :func:`extract_join_equality_pairs` first; if parsing fails for a fragment (``None``), falls back
    to the legacy regex matcher for that fragment only.
    """
    rel = relation_name.strip()
    al = alias.strip() if alias else None
    collected: List[str] = []

    for jc in join_conditions:
        pairs = extract_join_equality_pairs(jc)
        matched_here = False
        if pairs:
            for left, right in pairs:
                if _column_matches_relation(left, rel, al):
                    collected.append(_bare_ident_from_qualified(left))
                    matched_here = True
                elif _column_matches_relation(right, rel, al):
                    collected.append(_bare_ident_from_qualified(right))
                    matched_here = True
        if matched_here:
            continue
        if pairs is None or pairs == []:
            collected.extend(_join_regex_fallback(jc, rel, al))

    return collected
