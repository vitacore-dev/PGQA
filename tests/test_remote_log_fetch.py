"""Tests for SSH log fetch helpers."""

from __future__ import annotations

import stat
import unittest
from unittest.mock import MagicMock, patch

from pg_query_analyzer.db.remote_log_fetch import (
    LOG_DEFAULT_PREFIXES,
    parse_log_prefix_whitelist,
    resolve_log_directory_absolute,
)


class ParseLogPrefixTests(unittest.TestCase):
    def test_empty_uses_log_defaults(self):
        p = parse_log_prefix_whitelist("")
        self.assertEqual(p, LOG_DEFAULT_PREFIXES)
        self.assertIn("/var/log/postgresql/", p)

    def test_custom_override(self):
        p = parse_log_prefix_whitelist("/opt/pglogs/")
        self.assertEqual(p, ("/opt/pglogs/",))


class ResolveLogDirectoryTests(unittest.TestCase):
    def test_absolute_log_directory(self):
        conn = {"host": "h", "port": 5432, "dbname": "d", "user": "u", "password": "p"}

        class FakeCursor:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def execute(self, q):
                self._q = q

            def fetchone(self):
                if "data_directory" in self._q:
                    return ("/data",)
                if "log_directory" in self._q:
                    return ("/var/log/pg_log",)
                return (None,)

        class FakeConn:
            def __init__(self):
                self.autocommit = False

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def cursor(self):
                return FakeCursor()

        with patch("pg_query_analyzer.db.remote_log_fetch.psycopg2.connect", return_value=FakeConn()):
            path = resolve_log_directory_absolute(conn)
        self.assertEqual(path, "/var/log/pg_log")

    def test_relative_log_directory(self):
        conn = {"host": "h", "port": 5432, "dbname": "d", "user": "u", "password": "p"}

        seq = [("/var/lib/postgresql/16/main",), ("log",)]

        class FakeCursor:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def execute(self, q):
                self._q = q

            def fetchone(self):
                if "data_directory" in self._q:
                    return seq[0]
                return seq[1]

        class FakeConn:
            def __init__(self):
                self.autocommit = False

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def cursor(self):
                return FakeCursor()

        with patch("pg_query_analyzer.db.remote_log_fetch.psycopg2.connect", return_value=FakeConn()):
            path = resolve_log_directory_absolute(conn)
        self.assertEqual(path, "/var/lib/postgresql/16/main/log")


class FetchRemoteLogTests(unittest.TestCase):
    def test_small_file_sftp(self):
        from pg_query_analyzer.db import remote_log_fetch as mod

        conn = {"ssh": {"enabled": True, "host": "h", "user": "u", "password": "p"}}
        prefixes = ("/var/lib/postgresql/",)

        st = MagicMock()
        st.st_mode = stat.S_IFREG | 0o644
        st.st_size = 10

        fake_file = MagicMock()
        fake_file.__enter__.return_value = fake_file
        fake_file.__exit__.return_value = False
        fake_file.read.return_value = b"hello log\n"

        sftp = MagicMock()
        sftp.stat.return_value = st
        sftp.open.return_value = fake_file

        client = MagicMock()
        client.open_sftp.return_value = sftp

        with patch.object(mod, "connect_ssh_client", return_value=client):
            text, info = mod.fetch_remote_postgresql_log_text(
                conn,
                "/var/lib/postgresql/log/file.log",
                prefixes,
                max_bytes=1024 * 1024,
            )
        self.assertEqual(text, "hello log\n")
        self.assertIn("SFTP", info)
        client.close.assert_called_once()
        sftp.close.assert_called_once()


if __name__ == "__main__":
    unittest.main()
