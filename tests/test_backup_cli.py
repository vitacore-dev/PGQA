"""Unit tests for pg_dump / pg_restore argv builders."""

from __future__ import annotations

import os
import stat
import sys

import pytest

from pg_query_analyzer.db.backup_cli import (
    build_pg_dump_command,
    build_pg_restore_command,
    build_pg_restore_list_command,
)


def _touch_pg_dump(bindir: str) -> str:
    name = "pg_dump.exe" if sys.platform == "win32" else "pg_dump"
    path = os.path.join(bindir, name)
    with open(path, "w", encoding="utf-8") as f:
        f.write("# stub\n")
    os.chmod(path, stat.S_IRWXU)
    return path


def _touch_pg_restore(bindir: str) -> str:
    name = "pg_restore.exe" if sys.platform == "win32" else "pg_restore"
    path = os.path.join(bindir, name)
    with open(path, "w", encoding="utf-8") as f:
        f.write("# stub\n")
    os.chmod(path, stat.S_IRWXU)
    return path


def test_build_pg_dump_custom(tmp_path):
    bindir = tmp_path / "b"
    bindir.mkdir()
    _touch_pg_dump(str(bindir))
    kw = {
        "host": "h.example",
        "port": 5433,
        "user": "u1",
        "dbname": "db1",
        "password": "s3cret",
        "sslmode": "require",
        "gssencmode": "disable",
    }
    prog, args, env = build_pg_dump_command(
        bin_dir=str(bindir),
        connect_kwargs=kw,
        output_path="/tmp/out.dump",
        fmt="custom",
        schema_only=False,
        data_only=False,
        no_owner=True,
        no_privileges=True,
    )
    assert "pg_dump" in os.path.basename(prog).lower()
    assert "-w" in args
    assert any(a.startswith("-F") and a.endswith("c") for a in args)
    assert args[args.index("-h") + 1] == "h.example"
    assert args[args.index("-p") + 1] == "5433"
    assert args[args.index("-U") + 1] == "u1"
    assert args[args.index("-d") + 1] == "db1"
    assert "-f" in args
    assert args[args.index("-f") + 1] == "/tmp/out.dump"
    assert "--no-owner" in args
    assert "--no-acl" in args
    assert env["PGPASSWORD"] == "s3cret"
    assert env["PGSSLMODE"] == "require"


def test_build_pg_dump_rejects_schema_and_data_only(tmp_path):
    bindir = tmp_path / "b2"
    bindir.mkdir()
    _touch_pg_dump(str(bindir))
    kw = {"host": "127.0.0.1", "port": 5432, "user": "u", "dbname": "d", "password": ""}
    with pytest.raises(ValueError, match="схема"):
        build_pg_dump_command(
            bin_dir=str(bindir),
            connect_kwargs=kw,
            output_path="/x.dump",
            fmt="custom",
            schema_only=True,
            data_only=True,
            no_owner=False,
            no_privileges=False,
        )


def test_build_pg_restore_parallel(tmp_path):
    bindir = tmp_path / "b3"
    bindir.mkdir()
    _touch_pg_restore(str(bindir))
    kw = {"host": "127.0.0.1", "port": 5432, "user": "u", "dbname": "postgres", "password": "p"}
    prog, args, env = build_pg_restore_command(
        bin_dir=str(bindir),
        connect_kwargs=kw,
        input_path="/dump/custom.dump",
        target_db="restore_target",
        jobs=4,
        no_owner=True,
        no_privileges=False,
        clean_if_exists=True,
    )
    assert "pg_restore" in os.path.basename(prog).lower()
    assert "-j" in args
    assert args[args.index("-j") + 1] == "4"
    assert args[args.index("-d") + 1] == "restore_target"
    assert "--clean" in args
    assert "--if-exists" in args
    assert args[-1] == "/dump/custom.dump"


def test_build_pg_restore_list(tmp_path):
    bindir = tmp_path / "b4"
    bindir.mkdir()
    _touch_pg_restore(str(bindir))
    prog, args, env = build_pg_restore_list_command(bin_dir=str(bindir), input_path="/a.dump")
    assert args == ["--list", "/a.dump"]
    assert env == {}
