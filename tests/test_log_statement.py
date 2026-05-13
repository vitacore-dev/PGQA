"""Tests for PostgreSQL log_statement log parsing and aggregation."""

from __future__ import annotations

import unittest

from pg_query_analyzer.analysis.log_statement import (
    aggregate_log_statements,
    is_transaction_control_sql,
    looks_like_csvlog_header,
    parse_log_statement_records,
)


class LogStatementParseTests(unittest.TestCase):
    def test_stderr_single_line(self):
        log = (
            "2025-05-13 10:00:00.123 UTC [12345]: user=u,db=d LOG:  statement: SELECT 1;\n"
        )
        recs = parse_log_statement_records(log)
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0].sql.strip(), "SELECT 1;")
        self.assertEqual(recs[0].line_start, 1)

    def test_stderr_multiline_tab_continuation(self):
        log = (
            "2025-05-13 10:00:00 UTC [1]: user=u,db=d LOG:  statement: SELECT a,\n"
            "\tb FROM t WHERE id = 1;\n"
        )
        recs = parse_log_statement_records(log)
        self.assertEqual(len(recs), 1)
        self.assertIn("SELECT a,", recs[0].sql)
        self.assertIn("b FROM t", recs[0].sql)

    def test_stderr_detail_captured(self):
        log = (
            "2025-05-13 10:00:00 UTC [1]: LOG:  statement: EXECUTE foo(1);\n"
            "DETAIL:  parameters: $1 = 'x'\n"
        )
        recs = parse_log_statement_records(log)
        self.assertEqual(len(recs), 1)
        self.assertIn("parameters", recs[0].detail)

    def test_csvlog_query_column(self):
        log = (
            "log_time,user_name,database_name,message,query\n"
            "2025-01-01 12:00:00 UTC,alice,mydb,,SELECT 3;\n"
        )
        self.assertTrue(looks_like_csvlog_header(log.split("\n")[0]))
        recs = parse_log_statement_records(log)
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0].sql.strip(), "SELECT 3;")

    def test_csvlog_message_statement(self):
        log = (
            "log_time,user_name,database_name,message,query\n"
            '2025-01-01 12:00:00 UTC,u,d,"LOG:  statement: SELECT 4",\n'
        )
        recs = parse_log_statement_records(log)
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0].sql.strip(), "SELECT 4")

    def test_hide_transaction_commands_in_aggregate(self):
        log = (
            "2025-05-13 10:00:00 UTC [1]: LOG:  statement: BEGIN;\n"
            "2025-05-13 10:00:00 UTC [1]: LOG:  statement: SELECT 1;\n"
            "2025-05-13 10:00:00 UTC [1]: LOG:  statement: COMMIT;\n"
        )
        recs = parse_log_statement_records(log)
        agg, meta = aggregate_log_statements(recs, hide_transaction_commands=True)
        self.assertEqual(meta["skipped_transaction_commands"], 2)
        self.assertEqual(len(agg), 1)
        self.assertEqual(agg[0].count, 1)

    def test_aggregate_counts_repeats(self):
        log = (
            "2025-05-13 10:00:00 UTC [1]: LOG:  statement: SELECT 1;\n"
            "2025-05-13 10:00:00 UTC [1]: LOG:  statement: SELECT 1;\n"
        )
        recs = parse_log_statement_records(log)
        agg, meta = aggregate_log_statements(recs, hide_transaction_commands=True)
        self.assertEqual(meta["unique_fingerprints"], 1)
        self.assertEqual(agg[0].count, 2)


class TransactionNoiseTests(unittest.TestCase):
    def test_tx_detection(self):
        self.assertTrue(is_transaction_control_sql("BEGIN"))
        self.assertTrue(is_transaction_control_sql("COMMIT;"))
        self.assertTrue(is_transaction_control_sql("SAVEPOINT x"))
        self.assertFalse(is_transaction_control_sql("SELECT 1"))


if __name__ == "__main__":
    unittest.main()
