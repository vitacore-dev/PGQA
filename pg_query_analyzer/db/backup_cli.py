"""Build argv and env for pg_dump / pg_restore (client tools, not SQL BACKUP)."""

from __future__ import annotations

import os
import shutil
import sys
from typing import Any, Dict, List, Literal, Mapping, Optional, Tuple

DumpFormat = Literal["custom", "directory", "plain"]

DUMP_FORMAT_TO_FLAG: Dict[DumpFormat, str] = {
    "custom": "c",
    "directory": "d",
    "plain": "p",
}


def find_pg_tool(tool_base: str, bin_dir: Optional[str]) -> Optional[str]:
    """Resolve path to pg_dump / pg_restore. ``bin_dir`` is optional directory containing binaries."""
    is_win = sys.platform == "win32"
    exe_name = f"{tool_base}.exe" if is_win else tool_base
    if bin_dir and str(bin_dir).strip():
        root = os.path.expanduser(str(bin_dir).strip())
        cand = os.path.join(root, exe_name)
        if os.path.isfile(cand):
            return cand
    w = shutil.which(tool_base)
    if w:
        return w
    if is_win:
        return shutil.which(exe_name)
    return None


def _connect_env(connect_kwargs: Mapping[str, Any]) -> Dict[str, str]:
    pwd = str(connect_kwargs.get("password") or "")
    sslmode = str(connect_kwargs.get("sslmode") or "prefer").strip() or "prefer"
    gss = str(connect_kwargs.get("gssencmode") or "prefer").strip() or "prefer"
    env: Dict[str, str] = {
        "PGPASSWORD": pwd,
        "PGSSLMODE": sslmode,
        "PGGSSENCMODE": gss,
        "PGCLIENTENCODING": "UTF8",
    }
    return env


def build_pg_dump_command(
    *,
    bin_dir: Optional[str],
    connect_kwargs: Mapping[str, Any],
    output_path: str,
    fmt: DumpFormat,
    schema_only: bool,
    data_only: bool,
    no_owner: bool,
    no_privileges: bool,
) -> Tuple[str, List[str], Dict[str, str]]:
    """Return ``(program, argv, extra_env)`` for ``pg_dump`` (password via env, ``-w``)."""
    prog = find_pg_tool("pg_dump", bin_dir)
    if not prog:
        raise FileNotFoundError(
            "Не найден pg_dump. Установите клиент PostgreSQL или укажите каталог bin в настройках окна."
        )

    host = str(connect_kwargs.get("host") or "127.0.0.1").strip()
    port = int(connect_kwargs.get("port") or 5432)
    user = str(connect_kwargs.get("user") or "").strip()
    dbname = str(connect_kwargs.get("dbname") or "postgres").strip()
    if not user:
        raise ValueError("Не задан пользователь PostgreSQL")

    flag = DUMP_FORMAT_TO_FLAG[fmt]
    args: List[str] = [
        "-w",
        "-h",
        host,
        "-p",
        str(port),
        "-U",
        user,
        "-d",
        dbname,
        f"-F{flag}",
    ]

    if fmt == "directory":
        args.extend(["-f", output_path])
    else:
        args.extend(["-f", output_path])

    if schema_only:
        args.append("--schema-only")
    if data_only:
        args.append("--data-only")
    if schema_only and data_only:
        raise ValueError("Нельзя одновременно «только схема» и «только данные»")
    if no_owner:
        args.append("--no-owner")
    if no_privileges:
        args.append("--no-acl")

    return prog, args, _connect_env(connect_kwargs)


def build_pg_restore_command(
    *,
    bin_dir: Optional[str],
    connect_kwargs: Mapping[str, Any],
    input_path: str,
    target_db: str,
    jobs: int,
    no_owner: bool,
    no_privileges: bool,
    clean_if_exists: bool,
) -> Tuple[str, List[str], Dict[str, str]]:
    """Return ``(program, argv, extra_env)`` for ``pg_restore`` into ``target_db``."""
    prog = find_pg_tool("pg_restore", bin_dir)
    if not prog:
        raise FileNotFoundError(
            "Не найден pg_restore. Установите клиент PostgreSQL или укажите каталог bin в настройках окна."
        )

    host = str(connect_kwargs.get("host") or "127.0.0.1").strip()
    port = int(connect_kwargs.get("port") or 5432)
    user = str(connect_kwargs.get("user") or "").strip()
    if not user:
        raise ValueError("Не задан пользователь PostgreSQL")
    tdb = (target_db or "").strip() or str(connect_kwargs.get("dbname") or "postgres").strip()

    args: List[str] = [
        "-w",
        "-h",
        host,
        "-p",
        str(port),
        "-U",
        user,
        "-d",
        tdb,
    ]

    if jobs > 1:
        args.extend(["-j", str(jobs)])

    if no_owner:
        args.append("--no-owner")
    if no_privileges:
        args.append("--no-acl")
    if clean_if_exists:
        args.append("--clean")
        args.append("--if-exists")

    args.append(input_path)
    return prog, args, _connect_env(connect_kwargs)


def build_pg_restore_list_command(
    *,
    bin_dir: Optional[str],
    input_path: str,
) -> Tuple[str, List[str], Dict[str, str]]:
    """``pg_restore --list`` (без подключения к серверу для custom; для directory — тот же синтаксис)."""
    prog = find_pg_tool("pg_restore", bin_dir)
    if not prog:
        raise FileNotFoundError("Не найден pg_restore.")

    args = ["--list", input_path]
    return prog, args, {}
