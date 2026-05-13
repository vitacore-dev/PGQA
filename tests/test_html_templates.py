import unittest

from pg_query_analyzer.visualization.html_templates import (
    VIS_NETWORK_LAYOUT_OPTIONS,
    animated_status_messages_html,
    empty_performance_graph_html,
    plan_vis_network_html,
    welcome_screen_html,
)


class HtmlTemplatesTest(unittest.TestCase):
    def test_welcome_has_doctype(self):
        html = welcome_screen_html()
        self.assertIn("<!DOCTYPE html>", html)
        self.assertIn("vitacore-logo", html)

    def test_empty_graph_default_message(self):
        html = empty_performance_graph_html()
        self.assertIn("Выберите группу запросов", html)

    def test_empty_graph_custom_message(self):
        html = empty_performance_graph_html("custom")
        self.assertIn("custom", html)

    def test_animated_messages(self):
        html = animated_status_messages_html(["a", "b"], [0.1, 0.2])
        self.assertIn("a", html)
        self.assertIn("b", html)

    def test_plan_vis_network_smoke(self):
        html = plan_vis_network_html(
            [{"id": "1", "label": "x", "color": "#fff"}],
            [],
            VIS_NETWORK_LAYOUT_OPTIONS["default"],
        )
        self.assertIn("vis-network.min.js", html)
        self.assertIn("vis.DataSet", html)
        self.assertIn("viz-fit-btn", html)
        self.assertIn("viz-export-btn", html)
        self.assertIn("viz-reset-collapse-btn", html)
        self.assertIn("navigationButtons", html)
        self.assertIn("emitVisibleOutline", html)
        self.assertIn("updateVisibleOutline", html)


if __name__ == "__main__":
    unittest.main()
