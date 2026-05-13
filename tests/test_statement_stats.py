"""Tests for pg_stat_statements helper module (mocked cursor)."""

import unittest

from pg_query_analyzer.db.statement_stats import (
    StatementStatsError,
    fetch_top_statements,
    lookup_queryid_for_executed_statement,
    reset_pg_stat_statements,
)


class FakeCursor:
    """Minimal cursor mock for fetch_top_statements."""

    def __init__(self, extension_installed=True, modern_timing=True):
        self.extension_installed = extension_installed
        self.modern_timing = modern_timing
        self._sql = ""

    def execute(self, sql, params=None):
        self._sql = sql.strip()
        self._params = params

    def fetchone(self):
        if "pg_extension" in self._sql:
            return (self.extension_installed,)
        if "pg_attribute" in self._sql:
            return (self.modern_timing,)
        return None

    def fetchall(self):
        return [
            (
                "42",
                "SELECT 1",
                3,
                3,
                0.1234,
                0.9876,
            )
        ]

    @property
    def description(self):
        return [
            ("queryid",),
            ("query_text",),
            ("calls",),
            ("rows_sum",),
            ("mean_ms",),
            ("total_ms",),
        ]


class StatementStatsTest(unittest.TestCase):
    def test_raises_when_extension_missing(self):
        cur = FakeCursor(extension_installed=False)
        with self.assertRaises(StatementStatsError):
            fetch_top_statements(cur, limit=10)

    def test_fetch_modern_columns_use_exec_time_names(self):
        cur = FakeCursor(extension_installed=True, modern_timing=True)
        fetch_top_statements(cur, limit=5, sort_key="calls")
        self.assertIn("total_exec_time", cur._sql)
        self.assertIn("mean_exec_time", cur._sql)
        self.assertIn("ORDER BY calls", cur._sql)

    def test_fetch_legacy_columns_when_flag_false(self):
        cur = FakeCursor(extension_installed=True, modern_timing=False)
        fetch_top_statements(cur, limit=5, sort_key="total_time")
        self.assertIn("total_time", cur._sql)
        self.assertIn("mean_time", cur._sql)

    def test_returns_rows_as_dicts(self):
        cur = FakeCursor()
        rows = fetch_top_statements(cur, limit=2)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["query_text"], "SELECT 1")
        self.assertEqual(rows[0]["calls"], 3)

    def test_lookup_queryid_requires_exact_sql(self):
        class C:
            def execute(self, sql, params=None):
                self._sql = sql.strip()
                self._params = params

            def fetchone(self):
                if "pg_extension" in self._sql:
                    return (True,)
                if "FROM pg_stat_statements" in self._sql:
                    return ("314159",)
                return None

        cur = C()
        qid = lookup_queryid_for_executed_statement(cur, "EXPLAIN (FORMAT JSON) SELECT 1")
        self.assertEqual(qid, "314159")
        self.assertEqual(cur._params, ("EXPLAIN (FORMAT JSON) SELECT 1",))

    def test_lookup_returns_none_without_extension(self):
        class C:
            def execute(self, sql, params=None):
                self._sql = sql.strip()

            def fetchone(self):
                if "pg_extension" in self._sql:
                    return (False,)
                return None

        cur = C()
        self.assertIsNone(lookup_queryid_for_executed_statement(cur, "SELECT 1"))

    def test_reset_invokes_pg_function(self):
        calls = []

        class C:
            def execute(self, sql, params=None):
                calls.append(sql.strip())

            def fetchone(self):
                return (True,)

        cur = C()
        reset_pg_stat_statements(cur)
        self.assertTrue(any("pg_stat_statements_reset" in c for c in calls))


if __name__ == "__main__":
    unittest.main()
