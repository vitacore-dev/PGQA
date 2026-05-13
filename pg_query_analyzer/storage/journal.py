"""Persistence helpers for query plan journal entries."""

import json
import logging
import os

from pg_query_analyzer.storage.json_io import atomic_write_json

JOURNAL_FILE = "query_plans_journal.json"


def load_journal_entries(journal_file=JOURNAL_FILE):
    try:
        if not os.path.exists(journal_file):
            return []

        with open(journal_file, "r", encoding="utf-8") as f:
            data = json.load(f)

        return data if isinstance(data, list) else []
    except json.JSONDecodeError:
        logging.warning("Invalid JSON in query plans journal, using empty journal")
        return []
    except Exception as e:
        logging.error(f"Error loading query plans journal: {e}")
        return []


def save_journal_entries(entries, journal_file=JOURNAL_FILE):
    atomic_write_json(journal_file, entries, indent=2, ensure_ascii=False)


def trim_journal_entries(entries, max_entries=1000):
    if max_entries is None or max_entries <= 0:
        return entries
    return entries[-max_entries:]


def append_journal_entry(entry, max_entries=1000, journal_file=JOURNAL_FILE):
    entries = load_journal_entries(journal_file)
    entries.append(entry)
    entries = trim_journal_entries(entries, max_entries)
    save_journal_entries(entries, journal_file)
    return entries


def delete_journal_entry(entry_to_delete, journal_file=JOURNAL_FILE):
    entries = load_journal_entries(journal_file)
    filtered_entries = [
        entry
        for entry in entries
        if entry.get("timestamp") != entry_to_delete.get("timestamp")
        or entry.get("source_name") != entry_to_delete.get("source_name")
    ]
    save_journal_entries(filtered_entries, journal_file)
    return filtered_entries


def upsert_unique_journal_entry(entry, entries=None, max_entries=1000, journal_file=JOURNAL_FILE):
    current_entries = list(entries) if entries is not None else load_journal_entries(journal_file)
    existing_entry = next(
        (
            existing
            for existing in current_entries
            if existing.get("timestamp") == entry.get("timestamp")
            and existing.get("source_name") == entry.get("source_name")
        ),
        None,
    )

    if existing_entry:
        return current_entries, False

    current_entries.append(entry)
    current_entries = trim_journal_entries(current_entries, max_entries)
    save_journal_entries(current_entries, journal_file)
    return current_entries, True
