import json
import tempfile
import unittest
from pathlib import Path

from pg_query_analyzer.storage.settings import (
    ANALYZER_SETTINGS_FILE,
    load_analyzer_settings,
    merge_settings,
    save_analyzer_settings,
)

DEFAULT_SETTINGS = {
    "thresholds": {
        "high_cost_absolute": 10000.0,
        "high_cost_percent": 10.0,
    },
    "visualization": {
        "max_nodes_display": 100,
    },
}


class AnalyzerSettingsStorageTest(unittest.TestCase):
    def test_merge_settings_preserves_missing_defaults(self):
        merged = merge_settings(
            DEFAULT_SETTINGS,
            {"thresholds": {"high_cost_absolute": 5000.0}},
        )

        self.assertEqual(merged["thresholds"]["high_cost_absolute"], 5000.0)
        self.assertEqual(merged["thresholds"]["high_cost_percent"], 10.0)
        self.assertEqual(merged["visualization"]["max_nodes_display"], 100)
        self.assertEqual(DEFAULT_SETTINGS["thresholds"]["high_cost_absolute"], 10000.0)

    def test_load_analyzer_settings_creates_default_file(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            settings = load_analyzer_settings(temp_dir, DEFAULT_SETTINGS)
            settings_file = Path(temp_dir) / ANALYZER_SETTINGS_FILE

            self.assertEqual(settings, DEFAULT_SETTINGS)
            self.assertTrue(settings_file.exists())

    def test_load_analyzer_settings_recovers_from_invalid_json(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            settings_file = Path(temp_dir) / ANALYZER_SETTINGS_FILE
            settings_file.write_text("{invalid", encoding="utf-8")

            settings = load_analyzer_settings(temp_dir, DEFAULT_SETTINGS)

            self.assertEqual(settings, DEFAULT_SETTINGS)
            self.assertEqual(
                json.loads(settings_file.read_text(encoding="utf-8")), DEFAULT_SETTINGS
            )

    def test_save_analyzer_settings_writes_json(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            save_analyzer_settings(temp_dir, DEFAULT_SETTINGS)
            settings_file = Path(temp_dir) / ANALYZER_SETTINGS_FILE

            self.assertEqual(
                json.loads(settings_file.read_text(encoding="utf-8")), DEFAULT_SETTINGS
            )


if __name__ == "__main__":
    unittest.main()
