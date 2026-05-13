import unittest

from pg_query_analyzer.db.explain_sql import (
    ExplainSqlError,
    explain_format_json_sql,
    has_pg_bind_placeholders,
    pg_bind_placeholders,
    substitute_pg_bind_placeholders,
    validate_single_statement_sql,
)


class ExplainSqlTest(unittest.TestCase):
    def test_allows_single_statement_with_trailing_semicolon(self):
        self.assertEqual(validate_single_statement_sql("SELECT 1;"), "SELECT 1;")

    def test_rejects_multiple_statements(self):
        with self.assertRaisesRegex(ExplainSqlError, "ровно один"):
            validate_single_statement_sql("SELECT 1; SELECT 2;")

    def test_rejects_pg_stat_statements_placeholders(self):
        with self.assertRaisesRegex(ExplainSqlError, "плейсхолдеры"):
            validate_single_statement_sql("SELECT pg_database_size($1)")

    def test_rejects_non_explainable_utility_statement(self):
        with self.assertRaisesRegex(ExplainSqlError, "не поддерживает"):
            validate_single_statement_sql("SET application_name = 'PostgreSQL JDBC Driver'")

    def test_allows_dml_that_postgresql_explain_supports(self):
        self.assertEqual(
            validate_single_statement_sql("UPDATE users SET name = 'x' WHERE id = 1"),
            "UPDATE users SET name = 'x' WHERE id = 1",
        )

    def test_detects_placeholders_without_treating_dollar_quotes_as_bind_params(self):
        self.assertTrue(has_pg_bind_placeholders("SELECT pg_database_size($1)"))
        self.assertFalse(has_pg_bind_placeholders("SELECT $$1$$"))

    def test_lists_distinct_placeholders_by_number(self):
        self.assertEqual(
            pg_bind_placeholders("SELECT $2, $1, $2"),
            ["$1", "$2"],
        )

    def test_substitutes_placeholders_as_sql_literals(self):
        self.assertEqual(
            substitute_pg_bind_placeholders(
                "SELECT pg_database_size($1) WHERE name ~ $2",
                {"$1": "postgres", "$2": "prod.*"},
            ),
            "SELECT pg_database_size('postgres') WHERE name ~ 'prod.*'",
        )

    def test_substitution_supports_null_literal(self):
        self.assertEqual(
            substitute_pg_bind_placeholders("SELECT $1", {"$1": "NULL"}),
            "SELECT NULL",
        )

    def test_builds_explain_after_validation(self):
        self.assertEqual(
            explain_format_json_sql("SELECT 1"),
            "EXPLAIN (FORMAT JSON) SELECT 1",
        )


if __name__ == "__main__":
    unittest.main()
