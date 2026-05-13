"""Tests for remote server-side pg_dump path validation and script builder."""

import pytest

from pg_query_analyzer.db.remote_pg_dump import (
    build_remote_pg_dump_script,
    parse_prefix_whitelist,
    validate_remote_dump_path,
)


def test_parse_prefix_custom():
    t = parse_prefix_whitelist("/opt/pg/,/tmp/")
    assert "/opt/pg/" in t
    assert "/tmp/" in t


def test_parse_prefix_empty_defaults():
    t = parse_prefix_whitelist("")
    assert "/var/backups/" in t


def test_validate_allows_under_prefix():
    prefixes = ("/tmp/pgqa_backup/",)
    validate_remote_dump_path("/tmp/pgqa_backup/x.dump", prefixes)


def test_validate_rejects_escape():
    prefixes = ("/tmp/pgqa_backup/",)
    with pytest.raises(ValueError, match="разреш"):
        validate_remote_dump_path("/tmp/pgqa_backup/../etc/passwd", prefixes)


def test_validate_rejects_non_absolute():
    with pytest.raises(ValueError, match="абсолют"):
        validate_remote_dump_path("relative.dump", ("/tmp/",))


def test_build_remote_script_safe_summary_has_no_password_literal():
    kw = {
        "host": "db.internal",
        "port": 5432,
        "user": "u",
        "dbname": "d",
        "password": "SECRET_SHOULD_NOT_APPEAR_IN_SUMMARY",
        "sslmode": "prefer",
        "gssencmode": "prefer",
    }
    script, safe = build_remote_pg_dump_script(
        kw,
        remote_path="/tmp/pgqa_backup/out.dump",
        fmt="custom",
        pg_dump_bin="pg_dump",
        schema_only=False,
        data_only=False,
        no_owner=False,
        no_privileges=False,
    )
    assert "SECRET_SHOULD_NOT_APPEAR_IN_SUMMARY" not in safe
    assert "SECRET_SHOULD_NOT_APPEAR_IN_SUMMARY" not in safe.upper()
    assert "pg_dump" in script
    assert "SECRET_SHOULD_NOT_APPEAR_IN_SUMMARY" in script
    assert "PGPASSWORD=" in script
