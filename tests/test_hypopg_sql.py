"""Tests for HypoPG helper module."""

import unittest

from pg_query_analyzer.db.hypopg_sql import (
    HypoPGError,
    explain_json_with_hypothetical_indexes,
    extract_hypopg_create_index_ddls,
    normalize_statement_for_hypopg,
)


class HypoPGSqlTest(unittest.TestCase):
    def test_empty_query_raises(self):
        class C:
            pass

        with self.assertRaises(HypoPGError):
            explain_json_with_hypothetical_indexes(
                C(), query_sql="  ", create_index_ddls=["CREATE INDEX ON t (i)"]
            )

    def test_empty_ddl_raises_without_touching_extension(self):
        class C:
            def execute(self, sql, params=None):
                raise AssertionError("extension check should not run without DDL lines")

        with self.assertRaises(HypoPGError):
            explain_json_with_hypothetical_indexes(
                C(),
                query_sql="SELECT 1",
                create_index_ddls=["-- skip", "", " "],
            )

    def test_extension_missing_raises(self):
        class C:
            def execute(self, sql, params=None):
                self._sql = sql.strip()

            def fetchone(self):
                return (False,)

        cur = C()
        with self.assertRaisesRegex(HypoPGError, "hypopg"):
            explain_json_with_hypothetical_indexes(
                cur,
                query_sql="SELECT 1",
                create_index_ddls=["CREATE INDEX ON pg_catalog.pg_class USING btree (oid)"],
            )


class HypoPGExtractTest(unittest.TestCase):
    def test_extract_strips_tags_and_concurrent(self):
        blob = """
        [table]CREATE INDEX CONCURRENTLY idx_o ON orders[/table]
        [table](user_id);[/table]
        """
        ddls = extract_hypopg_create_index_ddls(blob)
        self.assertEqual(len(ddls), 1)
        self.assertNotIn("CONCURRENTLY", ddls[0].upper())
        self.assertIn("orders", ddls[0].lower())

    def test_normalize_drops_concurrent(self):
        s = normalize_statement_for_hypopg("CREATE INDEX CONCURRENTLY i ON t (a);")
        self.assertNotIn("CONCURRENTLY", s.upper())

    def test_extract_deduplicates_identical_statements(self):
        t = "CREATE INDEX a ON t (x); CREATE INDEX a ON t (x);"
        self.assertEqual(len(extract_hypopg_create_index_ddls(t)), 1)


if __name__ == "__main__":
    unittest.main()
