import unittest

from pg_query_analyzer.analysis.plan_analyzer import analyze_plan_structure

DEFAULT_SETTINGS = {
    "thresholds": {
        "high_cost_absolute": 10000.0,
        "high_cost_percent": 10.0,
        "seq_scan_warning_cost": 150.0,
        "nested_loop_warning_cost": 500.0,
        "expensive_operation_percent": 15.0,
        "rows_estimate_ratio_warn": 10.0,
        "rows_estimate_min_rows": 1.0,
        "buffers_shared_read_warn_blocks": 64,
        "temp_spill_warning_blocks": 1,
    },
    "analysis": {
        "enable_index_recommendations": True,
        "enable_join_optimization": True,
        "enable_parallel_recommendations": True,
        "enable_vacuum_recommendations": True,
        "enable_row_estimate_analysis": True,
        "enable_buffers_io_analysis": True,
        "enable_spill_problems": True,
        "max_expensive_indexes_display": 5,
        "max_expensive_operations_display": 5,
        "max_row_estimate_mismatch_nodes": 8,
        "max_buffers_io_nodes": 8,
        "max_index_fields": 5,
        "enable_stale_statistics_analysis": True,
        "enable_confidence_scores": True,
        "max_stale_statistics_relations": 12,
    },
}


class PlanAnalyzerTest(unittest.TestCase):
    def test_detects_seq_scan_problem_above_threshold(self):
        plan_tree = {
            "type": "Seq Scan",
            "cost": 200.0,
            "rows": 1,
            "properties": {"Relation-Name": "users"},
            "children": [],
        }
        analysis, meta = analyze_plan_structure(plan_tree, DEFAULT_SETTINGS)

        self.assertIn("Отсутствие индекса для таблицы users", "".join(analysis["problems"]))
        self.assertEqual(meta["total_cost"], 200.0)

    def test_detects_external_sort_problem(self):
        plan_tree = {
            "type": "Sort",
            "cost": 10.0,
            "rows": 1,
            "properties": {"Sort-Method": "external"},
            "children": [],
        }
        analysis, _ = analyze_plan_structure(plan_tree, DEFAULT_SETTINGS)

        problems_text = "".join(analysis["problems"])
        self.assertIn("временных файлов", problems_text)

    def test_lists_referenced_tables_when_sql_provided(self):
        plan_tree = {
            "type": "Seq Scan",
            "cost": 50.0,
            "rows": 1,
            "properties": {"Relation-Name": "orders"},
            "children": [],
        }
        sql = "SELECT * FROM orders o JOIN users u ON o.user_id = u.id"
        analysis, _ = analyze_plan_structure(plan_tree, DEFAULT_SETTINGS, sql_query=sql)

        self.assertIn("Объекты в тексте SQL", analysis["general"])
        self.assertIn("orders", analysis["general"])
        self.assertIn("users", analysis["general"])

    def test_join_fields_from_qualified_hash_cond(self):
        """AST join extraction picks ``user_id`` from qualified Hash/Merge-style cond text."""
        plan_tree = {
            "type": "Hash Join",
            "cost": 1000.0,
            "rows": 1,
            "properties": {"Hash-Cond": "((orders.user_id = users.id))"},
            "children": [
                {
                    "type": "Seq Scan",
                    "cost": 500.0,
                    "rows": 1,
                    "properties": {"Relation-Name": "orders"},
                    "children": [],
                },
                {
                    "type": "Seq Scan",
                    "cost": 10.0,
                    "rows": 1,
                    "properties": {"Relation-Name": "users"},
                    "children": [],
                },
            ],
        }
        analysis, _ = analyze_plan_structure(plan_tree, DEFAULT_SETTINGS)

        self.assertIn("JOIN поля:", analysis["optimization"])
        self.assertIn("user_id", analysis["optimization"])

    def test_row_estimate_mismatch_section_explain_analyze(self):
        plan_tree = {
            "type": "Seq Scan",
            "cost": 50.0,
            "rows": 500,
            "properties": {
                "Relation-Name": "big_tbl",
                "Plan-Rows": "10",
                "Actual-Rows": "500",
            },
            "children": [],
        }
        analysis, _ = analyze_plan_structure(plan_tree, DEFAULT_SETTINGS)

        self.assertIn("EXPLAIN ANALYZE: оценка vs факт", analysis["general"])
        self.assertIn("Seq Scan", analysis["general"])
        self.assertIn("big_tbl", analysis["general"])
        self.assertIn("500", analysis["general"])
        self.assertIn("ANALYZE", analysis["general"])

    def test_stale_statistics_signals_section_groups_by_relation(self):
        plan_tree = {
            "type": "Seq Scan",
            "cost": 50.0,
            "rows": 500,
            "properties": {
                "Relation-Name": "big_tbl",
                "Plan-Rows": "10",
                "Actual-Rows": "500",
            },
            "children": [],
        }
        analysis, _ = analyze_plan_structure(plan_tree, DEFAULT_SETTINGS)
        self.assertIn("Сигналы устаревшей", analysis["general"])
        self.assertIn("Уверенность сигнала", analysis["general"])

    def test_index_hypothesis_confidence_optional(self):
        plan_tree = {
            "type": "Seq Scan",
            "cost": 8000.0,
            "rows": 1,
            "properties": {"Relation-Name": "t", "Filter": "(id = 1)"},
            "children": [],
        }
        analysis_off, _ = analyze_plan_structure(
            plan_tree,
            {
                **DEFAULT_SETTINGS,
                "analysis": {**DEFAULT_SETTINGS["analysis"], "enable_confidence_scores": False},
            },
        )
        self.assertNotIn("Уверенность гипотезы", analysis_off["optimization"])

        analysis_on, _ = analyze_plan_structure(plan_tree, DEFAULT_SETTINGS)
        self.assertIn("Уверенность гипотезы", analysis_on["optimization"])

    def test_duplicate_index_hypothesis_collapsed_when_same_columns(self):
        plan_tree = {
            "type": "Nested Loop",
            "cost": 20000.0,
            "rows": 1,
            "properties": {},
            "children": [
                {
                    "type": "Seq Scan",
                    "cost": 9000.0,
                    "rows": 100,
                    "properties": {"Relation-Name": "merge_t", "Filter": "(pk = 1)"},
                    "children": [],
                },
                {
                    "type": "Seq Scan",
                    "cost": 3000.0,
                    "rows": 100,
                    "properties": {"Relation-Name": "merge_t", "Filter": "(pk = 1)"},
                    "children": [],
                },
            ],
        }
        analysis, _ = analyze_plan_structure(plan_tree, DEFAULT_SETTINGS)
        self.assertEqual(analysis["optimization"].count("CREATE INDEX CONCURRENTLY"), 1)

    def test_row_estimate_analysis_disabled_skips_section(self):
        plan_tree = {
            "type": "Seq Scan",
            "cost": 50.0,
            "rows": 500,
            "properties": {
                "Relation-Name": "t",
                "Plan-Rows": "1",
                "Actual-Rows": "999",
            },
            "children": [],
        }
        settings = {**DEFAULT_SETTINGS}
        settings["analysis"] = {
            **DEFAULT_SETTINGS["analysis"],
            "enable_row_estimate_analysis": False,
        }
        analysis, _ = analyze_plan_structure(plan_tree, settings)

        self.assertNotIn("EXPLAIN ANALYZE: оценка vs факт", analysis["general"])

    def test_buffers_io_section_temp_blocks(self):
        plan_tree = {
            "type": "Sort",
            "cost": 500.0,
            "rows": 1,
            "properties": {
                "Sort-Method": "external",
                "Temp-Written-Blocks": "8192",
                "Temp-Read-Blocks": "4096",
                "Shared-Hit-Blocks": "100",
                "Shared-Read-Blocks": "0",
            },
            "children": [],
        }
        analysis, _ = analyze_plan_structure(plan_tree, DEFAULT_SETTINGS)

        self.assertIn("EXPLAIN ANALYZE: буферы и ввод-вывод", analysis["general"])
        self.assertIn("Временные файлы", analysis["general"])
        self.assertIn("8192", analysis["general"])
        self.assertIn("work_mem", analysis["general"])

    def test_buffers_io_section_shared_read(self):
        plan_tree = {
            "type": "Seq Scan",
            "cost": 1000.0,
            "rows": 100000,
            "properties": {
                "Relation-Name": "heap_tbl",
                "Shared-Hit-Blocks": "100",
                "Shared-Read-Blocks": "50000",
            },
            "children": [],
        }
        analysis, _ = analyze_plan_structure(plan_tree, DEFAULT_SETTINGS)

        self.assertIn("EXPLAIN ANALYZE: буферы и ввод-вывод", analysis["general"])
        self.assertIn("Чтение shared-буферов", analysis["general"])
        self.assertIn("50000", analysis["general"])

    def test_buffers_io_analysis_disabled_skips_section(self):
        plan_tree = {
            "type": "Sort",
            "cost": 100.0,
            "rows": 1,
            "properties": {"Temp-Written-Blocks": "100"},
            "children": [],
        }
        settings = {**DEFAULT_SETTINGS}
        settings["analysis"] = {**DEFAULT_SETTINGS["analysis"], "enable_buffers_io_analysis": False}
        analysis, _ = analyze_plan_structure(plan_tree, settings)

        self.assertNotIn("EXPLAIN ANALYZE: буферы и ввод-вывод", analysis["general"])

    def test_hash_join_temp_spill_in_critical_problems(self):
        plan_tree = {
            "type": "Hash Join",
            "cost": 50.0,
            "rows": 100,
            "properties": {"Temp-Written-Blocks": "16384"},
            "children": [],
        }
        analysis, _ = analyze_plan_structure(plan_tree, DEFAULT_SETTINGS)

        joined = "\n".join(analysis["problems"])
        self.assertIn("Hash Join", joined)
        self.assertIn("16384", joined)
        self.assertIn("work_mem", joined)
        self.assertIn("Критические проблемы", analysis["general"])

    def test_spill_problems_disabled(self):
        plan_tree = {
            "type": "Hash Join",
            "cost": 50.0,
            "rows": 1,
            "properties": {"Temp-Written-Blocks": "9999"},
            "children": [],
        }
        settings = {**DEFAULT_SETTINGS}
        settings["analysis"] = {**DEFAULT_SETTINGS["analysis"], "enable_spill_problems": False}
        analysis, _ = analyze_plan_structure(plan_tree, settings)

        self.assertEqual(analysis["problems"], [])


if __name__ == "__main__":
    unittest.main()
