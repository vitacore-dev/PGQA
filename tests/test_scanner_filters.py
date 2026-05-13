import unittest

from pg_query_analyzer.db.scanner_filters import apply_scanner_filters


class ScannerFiltersTest(unittest.TestCase):
    def test_filters_by_state_active(self):
        queries = [
            {"state": "active", "query": "SELECT 1"},
            {"state": "idle", "query": "SELECT 2"},
        ]
        filters = {"state": "active"}
        result = apply_scanner_filters(queries, filters)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["query"], "SELECT 1")

    def test_filters_by_query_text_substring(self):
        queries = [
            {"state": "active", "query": "SELECT * FROM users"},
            {"state": "active", "query": "UPDATE foo SET x=1"},
        ]
        filters = {"query_text": "users"}
        result = apply_scanner_filters(queries, filters)
        self.assertEqual(len(result), 1)
        self.assertIn("users", result[0]["query"].lower())

    def test_filters_by_client_exact_match(self):
        queries = [
            {
                "state": "active",
                "query": "SELECT 1",
                "client_addr": "127.0.0.1",
                "client_port": 5432,
            },
            {
                "state": "active",
                "query": "SELECT 2",
                "client_addr": "10.0.0.1",
                "client_port": 5432,
            },
        ]
        filters = {"client": "127.0.0.1:5432"}
        result = apply_scanner_filters(queries, filters)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["query"], "SELECT 1")


if __name__ == "__main__":
    unittest.main()
