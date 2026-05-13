"""Query history persistence."""

import json
import threading
import time

from pg_query_analyzer.storage.json_io import atomic_write_json


class QueryHistory:
    def __init__(self, history_file="query_history.json"):
        self.history_file = history_file
        self.queries = self._load_history()
        self.lock = threading.RLock()

    def _load_history(self):
        try:
            with open(self.history_file, "r", encoding="utf-8") as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return []

    def save_history(self):
        with self.lock:
            atomic_write_json(self.history_file, self.queries, indent=2, ensure_ascii=False)

    def add_query(self, query_text, plan_data=None, analysis_result=None):
        with self.lock:
            self.queries.append(
                {
                    "timestamp": time.time(),
                    "query": query_text,
                    "plan": plan_data,
                    "analysis": analysis_result,
                    "type": "executed",
                }
            )
            self.save_history()

    def add_active_query(self, query_data):
        with self.lock:
            existing_query = next(
                (
                    q
                    for q in self.queries
                    if q.get("type") == "active" and q.get("pid") == query_data.get("pid")
                ),
                None,
            )
            if not existing_query:
                self.queries.append(
                    {
                        "timestamp": time.time(),
                        **query_data,
                        "type": "active",
                    }
                )
                self.save_history()

    def get_recent_queries(self, limit=50):
        with self.lock:
            return sorted(self.queries, key=lambda x: x["timestamp"], reverse=True)[:limit]

    def get_active_queries(self):
        with self.lock:
            return [q for q in self.queries if q.get("type") == "active"]

    def clear_history(self):
        with self.lock:
            self.queries = []
            self.save_history()
