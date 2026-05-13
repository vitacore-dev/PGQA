import unittest
from pathlib import Path

from pg_query_analyzer.analysis.plan_parser import (
    parse_json_plan,
    parse_plan_document,
    parse_xml_plan,
)
from pg_query_analyzer.visualization.graph_builder import create_graph_data_from_plan

FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures"

SIMPLE_EXPLAIN_XML = (FIXTURE_DIR / "nested_sample.xml").read_text(encoding="utf-8")

SIMPLE_EXPLAIN_JSON = (FIXTURE_DIR / "nested_sample.json").read_text(encoding="utf-8")


class PlanParserTest(unittest.TestCase):
    def test_parse_xml_plan_builds_tree(self):
        plan = parse_xml_plan(SIMPLE_EXPLAIN_XML)

        self.assertEqual(plan["type"], "Nested Loop")
        self.assertEqual(plan["cost"], 42.5)
        self.assertEqual(plan["rows"], 3)
        self.assertEqual(len(plan["children"]), 1)
        self.assertEqual(plan["children"][0]["type"], "Seq Scan")
        self.assertEqual(plan["children"][0]["properties"]["Relation-Name"], "users")

    def test_parse_json_plan_matches_xml_structure(self):
        plan = parse_json_plan(SIMPLE_EXPLAIN_JSON)

        self.assertEqual(plan["type"], "Nested Loop")
        self.assertEqual(plan["cost"], 42.5)
        self.assertEqual(plan["rows"], 3)
        self.assertEqual(len(plan["children"]), 1)
        self.assertEqual(plan["children"][0]["type"], "Seq Scan")
        self.assertEqual(plan["children"][0]["properties"]["Relation-Name"], "users")

    def test_parse_plan_document_dispatches_json_and_xml(self):
        from_xml = parse_plan_document(SIMPLE_EXPLAIN_XML)
        from_json = parse_plan_document(SIMPLE_EXPLAIN_JSON)
        self.assertEqual(from_xml["type"], from_json["type"])
        self.assertEqual(from_xml["cost"], from_json["cost"])

    def test_create_graph_data_from_plan(self):
        plan = parse_xml_plan(SIMPLE_EXPLAIN_XML)
        graph_data = create_graph_data_from_plan(plan)

        self.assertEqual(len(graph_data["nodes"]), 2)
        self.assertEqual(len(graph_data["edges"]), 1)
        self.assertTrue(graph_data["nodes"][0]["is_main_node"])

    def test_parse_xml_plan_rejects_invalid_xml(self):
        with self.assertRaises(ValueError):
            parse_xml_plan("<not valid")

    def test_parse_json_plan_rejects_invalid_json(self):
        with self.assertRaises(ValueError):
            parse_json_plan("{not json")


if __name__ == "__main__":
    unittest.main()
