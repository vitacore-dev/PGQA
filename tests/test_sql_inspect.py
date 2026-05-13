"""Tests for pglast-backed sql_inspect helpers."""

import unittest

from pg_query_analyzer.analysis.sql_inspect import (
    extract_join_equality_pairs,
    extract_predicate_fields_from_filter,
    join_columns_for_relation,
    referenced_tables,
    sort_key_columns,
)


class SqlInspectTest(unittest.TestCase):
    def test_referenced_tables_sorted(self):
        sql = "SELECT o.id FROM orders o JOIN users u ON u.id = o.user_id"
        self.assertEqual(referenced_tables(sql), ["orders", "users"])

    def test_referenced_tables_invalid_returns_empty(self):
        self.assertEqual(referenced_tables(";;;"), [])

    def test_sort_key_columns_basic(self):
        self.assertEqual(sort_key_columns("users.created_at DESC"), ["users.created_at"])

    def test_extract_predicate_filters(self):
        pred = extract_predicate_fields_from_filter("(id = 42 AND email LIKE 'a%')")
        self.assertIsNotNone(pred)
        assert pred is not None
        self.assertIn("id", pred["equality_fields"])
        self.assertTrue(any(e["field"] == "email" for e in pred["like_fields"]))

    def test_extract_join_equality_pairs_qualified(self):
        pairs = extract_join_equality_pairs("(orders.user_id = users.id)")
        self.assertEqual(pairs, [("orders.user_id", "users.id")])

    def test_extract_join_equality_pairs_cast(self):
        pairs = extract_join_equality_pairs("(orders.user_id = users.id::bigint)")
        self.assertEqual(pairs, [("orders.user_id", "users.id")])

    def test_extract_join_equality_pairs_invalid_returns_none(self):
        self.assertIsNone(extract_join_equality_pairs("not sql !!!"))

    def test_join_columns_for_relation_matches_alias(self):
        cols = join_columns_for_relation(
            ["((o.user_id = users.id))"],
            "orders",
            "o",
        )
        self.assertEqual(cols, ["user_id"])

    def test_join_columns_no_fallback_when_ast_has_pairs_but_other_table(self):
        cols = join_columns_for_relation(
            ["(orders.user_id = users.id)"],
            "products",
            None,
        )
        self.assertEqual(cols, [])

    def test_predicate_neq(self):
        pred = extract_predicate_fields_from_filter("status <> 'x' AND qty != 4")
        self.assertIsNotNone(pred)
        assert pred is not None
        self.assertIn("status", pred["neq_fields"])
        self.assertIn("qty", pred["neq_fields"])

    def test_predicate_null_tests(self):
        pred = extract_predicate_fields_from_filter("a IS NULL AND b IS NOT NULL")
        self.assertIsNotNone(pred)
        assert pred is not None
        self.assertIn("a", pred["is_null_fields"])
        self.assertIn("b", pred["is_not_null_fields"])

    def test_predicate_not_equals_from_not_equals_op(self):
        pred = extract_predicate_fields_from_filter("NOT id = 42")
        self.assertIsNotNone(pred)
        assert pred is not None
        self.assertIn("id", pred["neq_fields"])

    def test_predicate_not_null_is_not_wrapped(self):
        pred = extract_predicate_fields_from_filter("NOT x IS NULL")
        self.assertIsNotNone(pred)
        assert pred is not None
        self.assertIn("x", pred["is_not_null_fields"])


if __name__ == "__main__":
    unittest.main()
