import tempfile
import unittest
from pathlib import Path

from pg_query_analyzer.storage.journal import (
    append_journal_entry,
    delete_journal_entry,
    load_journal_entries,
    save_journal_entries,
    upsert_unique_journal_entry,
)


class JournalStorageTest(unittest.TestCase):
    def test_load_missing_or_invalid_journal_returns_empty_list(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            journal_file = Path(temp_dir) / "journal.json"
            self.assertEqual(load_journal_entries(str(journal_file)), [])

            journal_file.write_text("{invalid", encoding="utf-8")
            self.assertEqual(load_journal_entries(str(journal_file)), [])

    def test_append_journal_entry_trims_to_max_entries(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            journal_file = str(Path(temp_dir) / "journal.json")

            append_journal_entry({"timestamp": "1", "source_name": "a"}, 2, journal_file)
            entries = append_journal_entry({"timestamp": "2", "source_name": "b"}, 1, journal_file)

            self.assertEqual(entries, [{"timestamp": "2", "source_name": "b"}])
            self.assertEqual(load_journal_entries(journal_file), entries)

    def test_delete_journal_entry_matches_timestamp_and_source(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            journal_file = str(Path(temp_dir) / "journal.json")
            keep = {"timestamp": "1", "source_name": "keep"}
            remove = {"timestamp": "2", "source_name": "remove"}
            save_journal_entries([keep, remove], journal_file)

            entries = delete_journal_entry(remove, journal_file)

            self.assertEqual(entries, [keep])

    def test_upsert_unique_journal_entry_skips_duplicate(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            journal_file = str(Path(temp_dir) / "journal.json")
            entry = {"timestamp": "1", "source_name": "same"}

            entries, added = upsert_unique_journal_entry(entry, [], 1000, journal_file)
            duplicate_entries, duplicate_added = upsert_unique_journal_entry(
                entry,
                entries,
                1000,
                journal_file,
            )

            self.assertTrue(added)
            self.assertFalse(duplicate_added)
            self.assertEqual(duplicate_entries, [entry])

    def test_hypopg_pair_metadata_round_trip(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            journal_file = str(Path(temp_dir) / "journal.json")
            entry = {
                "timestamp": "2026-01-01 12:00:00",
                "source_name": "test",
                "hypopg_pair_group_id": "deadbeef0123456789abcdef01234567",
                "hypopg_pair_role": "baseline",
            }
            append_journal_entry(entry, 100, journal_file)
            loaded = load_journal_entries(journal_file)
            self.assertEqual(len(loaded), 1)
            self.assertEqual(loaded[0]["hypopg_pair_group_id"], entry["hypopg_pair_group_id"])
            self.assertEqual(loaded[0]["hypopg_pair_role"], "baseline")


if __name__ == "__main__":
    unittest.main()
