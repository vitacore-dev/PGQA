import json
import tempfile
import unittest
from pathlib import Path

from pg_query_analyzer.observed_plans.exporters.clickhouse import (
    CLICKHOUSE_OBSERVED_PLANS_DDL,
    snapshot_to_clickhouse_row,
    snapshots_to_json_each_row,
)
from pg_query_analyzer.observed_plans.diff import diff_snapshots
from pg_query_analyzer.observed_plans.fingerprints import (
    compute_plan_hash,
    compute_plan_shape_hash,
)
from pg_query_analyzer.observed_plans.repository import ObservedPlanRepository
from pg_query_analyzer.observed_plans.sources.journal import (
    load_observed_snapshots_from_journal,
    observed_snapshots_from_journal_entries,
)
from pg_query_analyzer.observed_plans.sources.auto_explain_logs import (
    append_auto_explain_entries_deduped,
    auto_explain_dedup_key,
    journal_entries_from_auto_explain_log,
)
from pg_query_analyzer.observed_plans.sources.pg_stat_statements import (
    workload_candidates_from_pg_stat_rows,
)
from pg_query_analyzer.observed_plans.storage.sqlite import (
    load_snapshots,
    sync_journal_to_sqlite,
    upsert_snapshots,
)
from pg_query_analyzer.storage.journal import save_journal_entries


def _plan(node_type, *, cost=10.0, relation=None, children=None):
    plan = {
        "Node Type": node_type,
        "Total Cost": cost,
        "Plan Rows": 5,
    }
    if relation:
        plan["Relation Name"] = relation
    if children:
        plan["Plans"] = children
    return json.dumps([{"Plan": plan}])


class ObservedPlansTest(unittest.TestCase):
    def test_journal_entries_are_normalized_to_snapshots(self):
        entries = [
            {
                "timestamp": "2026-01-01 12:00:00",
                "source_name": "Ручной запрос",
                "source_type": "manual",
                "plan_origin": "explain",
                "statement_queryid": "123",
                "query": "SELECT * FROM users WHERE id = 1",
                "xml_content": _plan("Seq Scan", relation="users"),
            }
        ]

        snapshots = observed_snapshots_from_journal_entries(entries)

        self.assertEqual(len(snapshots), 1)
        snapshot = snapshots[0]
        self.assertEqual(snapshot.queryid, "123")
        self.assertEqual(snapshot.source, "explain")
        self.assertEqual(snapshot.summary.top_node_type, "Seq Scan")
        self.assertEqual(snapshot.summary.seq_scan_count, 1)
        self.assertTrue(snapshot.plan_hash)
        self.assertTrue(snapshot.plan_shape_hash)
        self.assertTrue(snapshot.query_fingerprint)

    def test_plan_shape_hash_ignores_cost_changes(self):
        first = _plan("Seq Scan", cost=10.0, relation="users")
        second = _plan("Seq Scan", cost=99.0, relation="users")

        self.assertNotEqual(compute_plan_hash(first), compute_plan_hash(second))
        self.assertEqual(compute_plan_shape_hash(first), compute_plan_shape_hash(second))

    def test_repository_finds_groups_with_changed_plan_shape(self):
        entries = [
            {
                "timestamp": "2026-01-01 12:00:00",
                "source_name": "a",
                "statement_queryid": "42",
                "query": "SELECT * FROM users WHERE id = 1",
                "xml_content": _plan("Seq Scan", relation="users"),
            },
            {
                "timestamp": "2026-01-01 12:05:00",
                "source_name": "b",
                "statement_queryid": "42",
                "query": "SELECT * FROM users WHERE id = 2",
                "xml_content": _plan("Index Scan", relation="users"),
            },
        ]
        repo = ObservedPlanRepository(observed_snapshots_from_journal_entries(entries))

        changed = repo.changed_plan_groups()

        self.assertEqual(list(changed), ["queryid:42"])
        self.assertEqual(len(changed["queryid:42"]), 2)

    def test_diff_reports_shape_and_cost_changes(self):
        snapshots = observed_snapshots_from_journal_entries(
            [
                {
                    "timestamp": "2026-01-01 12:00:00",
                    "source_name": "a",
                    "query": "SELECT * FROM users",
                    "xml_content": _plan("Seq Scan", cost=50.0, relation="users"),
                },
                {
                    "timestamp": "2026-01-01 12:05:00",
                    "source_name": "b",
                    "query": "SELECT * FROM users",
                    "xml_content": _plan("Index Scan", cost=5.0, relation="users"),
                },
            ]
        )

        diff = diff_snapshots(snapshots[0], snapshots[1])
        titles = [item.title for item in diff]

        self.assertIn("Изменилась форма плана", titles)
        self.assertIn("Изменилась общая стоимость", titles)

    def test_load_snapshots_from_existing_journal_file(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            journal_file = str(Path(temp_dir) / "journal.json")
            save_journal_entries(
                [
                    {
                        "timestamp": "2026-01-01 12:00:00",
                        "source_name": "HypoPG",
                        "plan_origin": "hypopg",
                        "hypopg_pair_group_id": "gid",
                        "hypopg_pair_role": "hypopg",
                        "xml_content": _plan("Index Scan", relation="users"),
                    }
                ],
                journal_file,
            )

            snapshots = load_observed_snapshots_from_journal(journal_file)

        self.assertEqual(len(snapshots), 1)
        self.assertEqual(snapshots[0].source, "hypopg")
        self.assertEqual(snapshots[0].hypopg_pair_group_id, "gid")
        self.assertEqual(snapshots[0].hypopg_pair_role, "hypopg")

    def test_pg_stat_rows_become_capture_candidates(self):
        snapshots = observed_snapshots_from_journal_entries(
            [
                {
                    "timestamp": "2026-01-01 12:00:00",
                    "source_name": "manual",
                    "statement_queryid": "42",
                    "query": "SELECT * FROM users WHERE id = 1",
                    "xml_content": _plan("Index Scan", relation="users"),
                }
            ]
        )
        rows = [
            {
                "queryid": "42",
                "query_text": "SELECT * FROM users WHERE id = 2",
                "calls": 10,
                "rows_sum": 10,
                "mean_ms": 1.2,
                "total_ms": 12.0,
            },
            {
                "queryid": "77",
                "query_text": "SELECT * FROM orders WHERE status = 'new'",
                "calls": 3,
                "rows_sum": 30,
                "mean_ms": 5.0,
                "total_ms": 15.0,
            },
        ]

        candidates = workload_candidates_from_pg_stat_rows(rows, snapshots)

        self.assertEqual([candidate.queryid for candidate in candidates], ["77", "42"])
        self.assertTrue(candidates[0].needs_plan_snapshot)
        self.assertFalse(candidates[1].needs_plan_snapshot)
        self.assertEqual(candidates[1].journal_matches, 1)
        self.assertTrue(candidates[1].saved_queryid_match)

    def test_repository_creates_workload_candidates(self):
        repo = ObservedPlanRepository([])
        candidates = repo.workload_candidates_from_pg_stat_rows(
            [
                {
                    "queryid": "1",
                    "query_text": "SELECT 1",
                    "calls": 1,
                    "rows_sum": 1,
                    "mean_ms": 0.1,
                    "total_ms": 0.1,
                }
            ]
        )

        self.assertEqual(len(candidates), 1)
        self.assertTrue(candidates[0].needs_plan_snapshot)

    def test_clickhouse_export_row_contains_plan_metrics(self):
        snapshot = observed_snapshots_from_journal_entries(
            [
                {
                    "timestamp": "2026-01-01 12:00:00",
                    "source_name": "manual",
                    "statement_queryid": "42",
                    "query": "SELECT * FROM users",
                    "xml_content": _plan("Seq Scan", relation="users"),
                }
            ]
        )[0]

        row = snapshot_to_clickhouse_row(snapshot)

        self.assertIn(
            "CREATE TABLE IF NOT EXISTS observed_plan_snapshots", CLICKHOUSE_OBSERVED_PLANS_DDL
        )
        self.assertEqual(row["queryid"], "42")
        self.assertEqual(row["top_node_type"], "Seq Scan")
        self.assertEqual(row["seq_scan_count"], 1)
        self.assertTrue(row["plan_hash"])

    def test_clickhouse_json_each_row_is_line_delimited_json(self):
        snapshots = observed_snapshots_from_journal_entries(
            [
                {
                    "timestamp": "2026-01-01 12:00:00",
                    "source_name": "manual",
                    "query": "SELECT * FROM users",
                    "xml_content": _plan("Seq Scan", relation="users"),
                }
            ]
        )

        payload = snapshots_to_json_each_row(snapshots)
        decoded = json.loads(payload.strip())

        self.assertTrue(payload.endswith("\n"))
        self.assertEqual(decoded["top_node_type"], "Seq Scan")

    def test_sqlite_storage_round_trip_and_upsert(self):
        snapshots = observed_snapshots_from_journal_entries(
            [
                {
                    "timestamp": "2026-01-01 12:00:00",
                    "source_name": "manual",
                    "statement_queryid": "42",
                    "query": "SELECT * FROM users",
                    "xml_content": _plan("Seq Scan", relation="users"),
                }
            ]
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = Path(temp_dir) / "observed.sqlite"

            first_count = upsert_snapshots(db_path, snapshots)
            second_count = upsert_snapshots(db_path, snapshots)
            loaded = load_snapshots(db_path)

        self.assertEqual(first_count, 1)
        self.assertEqual(second_count, 1)
        self.assertEqual(len(loaded), 1)
        self.assertEqual(loaded[0].snapshot_id, snapshots[0].snapshot_id)
        self.assertEqual(loaded[0].summary.top_node_type, "Seq Scan")
        self.assertEqual(loaded[0].queryid, "42")

    def test_repository_can_load_from_sqlite_backend(self):
        snapshots = observed_snapshots_from_journal_entries(
            [
                {
                    "timestamp": "2026-01-01 12:00:00",
                    "source_name": "manual",
                    "statement_queryid": "42",
                    "query": "SELECT * FROM users WHERE id = 1",
                    "xml_content": _plan("Seq Scan", relation="users"),
                },
                {
                    "timestamp": "2026-01-01 12:05:00",
                    "source_name": "manual",
                    "statement_queryid": "42",
                    "query": "SELECT * FROM users WHERE id = 2",
                    "xml_content": _plan("Index Scan", relation="users"),
                },
            ]
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = Path(temp_dir) / "observed.sqlite"
            upsert_snapshots(db_path, snapshots)

            repo = ObservedPlanRepository.from_sqlite(str(db_path))

        self.assertEqual(len(repo.list_snapshots()), 2)
        self.assertEqual(list(repo.group_by_query_identity()), ["queryid:42"])
        self.assertEqual(list(repo.changed_plan_groups()), ["queryid:42"])

    def test_sync_journal_to_sqlite(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            journal_file = Path(temp_dir) / "journal.json"
            db_path = Path(temp_dir) / "observed.sqlite"
            save_journal_entries(
                [
                    {
                        "timestamp": "2026-01-01 12:00:00",
                        "source_name": "manual",
                        "statement_queryid": "42",
                        "query": "SELECT * FROM users",
                        "xml_content": _plan("Seq Scan", relation="users"),
                    }
                ],
                str(journal_file),
            )

            count = sync_journal_to_sqlite(journal_file, db_path)
            loaded = load_snapshots(db_path)

        self.assertEqual(count, 1)
        self.assertEqual(len(loaded), 1)
        self.assertEqual(loaded[0].queryid, "42")

    def test_auto_explain_raw_json_imports_as_journal_entry(self):
        entries = journal_entries_from_auto_explain_log(
            _plan("Seq Scan", relation="users"),
            source_name="sample.log",
            captured_at="2026-01-01 12:00:00",
        )

        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["plan_origin"], "auto_explain")
        self.assertEqual(entries[0]["source_name"], "sample.log")
        snapshots = observed_snapshots_from_journal_entries(entries)
        self.assertEqual(snapshots[0].source, "auto_explain")
        self.assertEqual(snapshots[0].summary.top_node_type, "Seq Scan")

    def test_auto_explain_log_block_imports_query_and_duration(self):
        log = """
2026-01-01 12:00:00 UTC [123] LOG:  duration: 12.345 ms  plan:
Query Text: SELECT * FROM users WHERE id = 1
[
  {
    "Plan": {
      "Node Type": "Index Scan",
      "Relation Name": "users",
      "Total Cost": 4.2,
      "Plan Rows": 1
    }
  }
]
"""

        entries = journal_entries_from_auto_explain_log(
            log,
            source_name="postgresql.log",
            captured_at="2026-01-01 12:00:00",
        )

        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["query"], "SELECT * FROM users WHERE id = 1")
        self.assertEqual(entries[0]["auto_explain_duration_ms"], 12.345)
        snapshots = observed_snapshots_from_journal_entries(entries)
        self.assertEqual(snapshots[0].summary.top_node_type, "Index Scan")

    def test_auto_explain_query_text_does_not_leak_from_next_block(self):
        log = f"""
2026-01-01 12:00:00 UTC [123] LOG:  duration: 10.000 ms  plan:
{_plan("Seq Scan", relation="users")}
2026-01-01 12:01:00 UTC [123] LOG:  duration: 20.000 ms  plan:
Query Text: SELECT * FROM orders
{_plan("Index Scan", relation="orders")}
"""

        entries = journal_entries_from_auto_explain_log(
            log,
            source_name="postgresql.log",
            captured_at="2026-01-01 12:00:00",
        )

        self.assertEqual(len(entries), 2)
        self.assertEqual(entries[0]["query"], "")
        self.assertEqual(entries[1]["query"], "SELECT * FROM orders")

    def test_auto_explain_ignores_log_prefix_brackets_before_json(self):
        log = f"""
2026-01-01 12:00:00 UTC [123] LOG:  duration: 12.345 ms  plan:
2026-01-01 12:00:00 UTC [123] DETAIL: prefix before JSON
Query Text: SELECT * FROM users
2026-01-01 12:00:00 UTC [123] { _plan("Seq Scan", relation="users") }
"""

        entries = journal_entries_from_auto_explain_log(
            log,
            source_name="postgresql.log",
            captured_at="2026-01-01 12:00:00",
        )

        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["query"], "SELECT * FROM users")

    def test_auto_explain_import_key_is_stable_for_same_plan(self):
        first = journal_entries_from_auto_explain_log(
            _plan("Seq Scan", relation="users"),
            source_name="a.log",
            captured_at="2026-01-01 12:00:00",
        )[0]
        second = journal_entries_from_auto_explain_log(
            _plan("Seq Scan", relation="users"),
            source_name="b.log",
            captured_at="2026-01-01 12:05:00",
        )[0]

        self.assertEqual(auto_explain_dedup_key(first), auto_explain_dedup_key(second))

    def test_auto_explain_dedup_skips_repeated_imports(self):
        entries = journal_entries_from_auto_explain_log(
            _plan("Seq Scan", relation="users"),
            source_name="sample.log",
            captured_at="2026-01-01 12:00:00",
        )

        first, first_added = append_auto_explain_entries_deduped([], entries)
        second, second_added = append_auto_explain_entries_deduped(first, entries)

        self.assertEqual(first_added, 1)
        self.assertEqual(second_added, 0)
        self.assertEqual(len(second), 1)


if __name__ == "__main__":
    unittest.main()
