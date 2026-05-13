import json
import tempfile
import unittest
from pathlib import Path

from pg_query_analyzer.storage.json_io import atomic_write_json


class JsonIOTest(unittest.TestCase):
    def test_atomic_write_json_replaces_existing_file(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "data.json"
            path.write_text('{"old": true}', encoding="utf-8")

            atomic_write_json(str(path), {"new": True})

            self.assertEqual(json.loads(path.read_text(encoding="utf-8")), {"new": True})

    def test_atomic_write_json_keeps_existing_file_on_dump_error(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "data.json"
            path.write_text('{"old": true}', encoding="utf-8")

            with self.assertRaises(TypeError):
                atomic_write_json(str(path), {"bad": object()})

            self.assertEqual(json.loads(path.read_text(encoding="utf-8")), {"old": True})
            self.assertEqual(list(Path(temp_dir).iterdir()), [path])


if __name__ == "__main__":
    unittest.main()
