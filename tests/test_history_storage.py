import tempfile
import unittest
from pathlib import Path

from pg_query_analyzer.storage.history import QueryHistory


class QueryHistoryTest(unittest.TestCase):
    def test_add_query_persists_executed_query(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            history_file = Path(temp_dir) / "query_history.json"
            history = QueryHistory(str(history_file))

            history.add_query("SELECT 1", plan_data={"plan": "ok"}, analysis_result="fine")
            reloaded = QueryHistory(str(history_file))

            self.assertEqual(len(reloaded.queries), 1)
            self.assertEqual(reloaded.queries[0]["query"], "SELECT 1")
            self.assertEqual(reloaded.queries[0]["type"], "executed")

    def test_add_active_query_deduplicates_by_pid(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            history = QueryHistory(str(Path(temp_dir) / "query_history.json"))

            history.add_active_query({"pid": "123", "query": "SELECT 1"})
            history.add_active_query({"pid": "123", "query": "SELECT 2"})

            active_queries = history.get_active_queries()
            self.assertEqual(len(active_queries), 1)
            self.assertEqual(active_queries[0]["query"], "SELECT 1")

    def test_clear_history_persists_empty_list(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            history_file = Path(temp_dir) / "query_history.json"
            history = QueryHistory(str(history_file))

            history.add_query("SELECT 1")
            history.clear_history()
            reloaded = QueryHistory(str(history_file))

            self.assertEqual(reloaded.queries, [])


if __name__ == "__main__":
    unittest.main()
