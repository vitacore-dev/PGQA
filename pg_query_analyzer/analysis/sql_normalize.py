"""SQL normalization for journaling / grouping using pglast."""

from __future__ import annotations

import re
from typing import Optional

try:
    from pglast import fingerprint as pglast_fingerprint
    from pglast.parser import ParseError
except ImportError:  # pragma: no cover - runtime guard if pglast missing
    pglast_fingerprint = None  # type: ignore[misc, assignment]
    ParseError = SyntaxError  # type: ignore[misc, assignment]


def normalize_query_text(query: Optional[str]) -> str:
    """Stable key for grouping similar queries in the journal.

    When ``pglast`` is available and the text parses as SQL, uses
    :func:`pglast.fingerprint` — ignores literals, whitespace, and comments.

    Otherwise falls back to the legacy regex-based normalization (lowercased).
    """
    if not query:
        return ""

    stripped = query.strip()
    if not stripped:
        return ""

    if pglast_fingerprint is not None:
        try:
            fp = pglast_fingerprint(stripped)
            return fp if isinstance(fp, str) else str(fp)
        except ParseError:
            pass

    return _normalize_query_regex_fallback(stripped.lower())


def _normalize_query_regex_fallback(normalized: str) -> str:
    """Legacy normalization used when SQL cannot be parsed by pglast."""
    normalized = re.sub(r"--.*$", "", normalized, flags=re.MULTILINE)
    normalized = re.sub(r"/\*.*?\*/", "", normalized, flags=re.DOTALL)
    normalized = re.sub(r"\s+", " ", normalized)
    normalized = re.sub(r"\s*\(\s*", "(", normalized)
    normalized = re.sub(r"\s*\)\s*", ")", normalized)
    normalized = re.sub(r"\b\d+\b", "?", normalized)
    normalized = re.sub(r"'[^']*'", "?", normalized)
    normalized = re.sub(r'"[^"]*"', "?", normalized)
    return normalized.strip()
