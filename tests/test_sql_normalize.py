"""Tests for pglast-backed SQL normalization."""

import unittest

from pg_query_analyzer.analysis.sql_normalize import (
    normalize_query_text,
    _normalize_query_regex_fallback,
)


class SqlNormalizeTest(unittest.TestCase):
    def test_fingerprint_same_for_changed_literals(self):
        a = normalize_query_text("SELECT * FROM users WHERE id = 1")
        b = normalize_query_text("SELECT * FROM users WHERE id = 999")
        self.assertEqual(a, b)
        self.assertTrue(len(a) > 8)

    def test_fingerprint_ignores_whitespace_and_case(self):
        a = normalize_query_text("SELECT  *\nFROM   Users")
        b = normalize_query_text("select * from users")
        self.assertEqual(a, b)

    def test_fallback_invalid_sql(self):
        sql = "NOT VALID SQL ;;"
        out = normalize_query_text(sql)
        legacy = _normalize_query_regex_fallback(sql.lower())
        self.assertEqual(out, legacy)

    def test_empty_and_none(self):
        self.assertEqual(normalize_query_text(""), "")
        self.assertEqual(normalize_query_text(None), "")
        self.assertEqual(normalize_query_text("   "), "")


if __name__ == "__main__":
    unittest.main()
