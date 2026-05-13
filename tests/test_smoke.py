"""Smoke tests: imports and parser→analyzer pipeline without launching the GUI."""

from __future__ import annotations

import unittest

MINIMAL_EXPLAIN_XML = """
<explain xmlns="http://www.postgresql.org/2009/explain">
  <Query>
    <Plan>
      <Node-Type>Seq Scan</Node-Type>
      <Relation-Name>smoke_tbl</Relation-Name>
      <Total-Cost>42</Total-Cost>
      <Plan-Rows>7</Plan-Rows>
    </Plan>
  </Query>
</explain>
"""


class SmokeTests(unittest.TestCase):
    def test_plan_parser_and_analyzer_without_gui(self):
        """Regression guard: core pipeline works without Qt main window."""
        from pg_query_analyzer.analysis.plan_analyzer import analyze_plan_structure
        from pg_query_analyzer.analysis.plan_parser import parse_plan_document

        tree = parse_plan_document(MINIMAL_EXPLAIN_XML.strip())
        self.assertEqual(tree["type"], "Seq Scan")
        analysis, meta = analyze_plan_structure(tree, {})
        self.assertEqual(meta["total_cost"], 42.0)
        self.assertIn("Основные метрики", analysis["general"])

    def test_sql_normalize_import(self):
        from pg_query_analyzer.analysis.sql_normalize import normalize_query_text

        out = normalize_query_text("SELECT 1 AS x")
        self.assertIsInstance(out, str)
        self.assertGreater(len(out), 0)

    def test_observed_plan_repository_import(self):
        from pg_query_analyzer.observed_plans.repository import ObservedPlanRepository

        repo = ObservedPlanRepository([])
        self.assertEqual(repo.list_snapshots(), [])


if __name__ == "__main__":
    unittest.main()
