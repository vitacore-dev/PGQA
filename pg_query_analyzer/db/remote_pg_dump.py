"""Run pg_dump on the SSH host (server-side file), with path prefix whitelist."""

from __future__ import annotations

import logging
import os
import shlex
import time
from typing import Any, Callable, Mapping, Optional

import paramiko

from pg_query_analyzer.db.backup_cli import DUMP_FORMAT_TO_FLAG, DumpFormat
from pg_query_analyzer.db.ssh_hardware import connect_ssh_client
from pg_query_analyzer.storage.connections import ConnectionSettings

LogFn = Callable[[str], None]
CancelFn = Callable[[], bool]

DEFAULT_PATH_PREFIXES: tuple[str, ...] = (
    "/var/backups/",
    "/tmp/pgqa_backup/",
    "/var/lib/postgresql/",
)


def parse_prefix_whitelist(text: str) -> tuple[str, ...]:
    """Comma- or newline-separated absolute directory prefixes (trailing ``/`` normalized)."""
    if not text or not str(text).strip():
        return DEFAULT_PATH_PREFIXES
    parts = []
    for raw in str(text).replace("\n", ",").split(","):
        p = raw.strip()
        if not p:
            continue
        if not p.startswith("/"):
            continue
        if not p.endswith("/"):
            p = p + "/"
        parts.append(os.path.normpath(p) + "/")
    return tuple(parts) if parts else DEFAULT_PATH_PREFIXES


def validate_remote_dump_path(remote_path: str, prefixes: tuple[str, ...]) -> None:
    """Require absolute path under one of the allowed prefixes (no ``..`` tricks)."""
    path = (remote_path or "").strip()
    if not path:
        raise ValueError("Укажите абсолютный путь на сервере.")
    if not path.startswith("/"):
        raise ValueError("Путь на сервере должен быть абсолютным (начинаться с /).")
    norm = os.path.normpath(path)
    if ".." in norm.split(os.sep):
        raise ValueError("Недопустимые компоненты пути (..).")
    ok = False
    for pref in prefixes:
        pnorm = os.path.normpath(str(pref).rstrip("/"))
        if norm == pnorm or norm.startswith(pnorm + os.sep):
            ok = True
            break
    if not ok:
        allowed = ", ".join(prefixes)
        raise ValueError(f"Путь должен начинаться с одного из разрешённых префиксов: {allowed}")


def build_remote_pg_dump_script(
    connect_kwargs: Mapping[str, Any],
    *,
    remote_path: str,
    fmt: DumpFormat,
    pg_dump_bin: str,
    schema_only: bool,
    data_only: bool,
    no_owner: bool,
    no_privileges: bool,
) -> tuple[str, str]:
    """Return ``(bash_script, safe_one_line_summary)`` for ``bash -c`` (password only inside quoted exports)."""
    if schema_only and data_only:
        raise ValueError("Нельзя одновременно «только схема» и «только данные»")

    flag = DUMP_FORMAT_TO_FLAG[fmt]
    host = str(connect_kwargs.get("host") or "127.0.0.1").strip()
    port = int(connect_kwargs.get("port") or 5432)
    user = str(connect_kwargs.get("user") or "").strip()
    dbname = str(connect_kwargs.get("dbname") or "postgres").strip()
    if not user:
        raise ValueError("Не задан пользователь PostgreSQL")

    pwd = str(connect_kwargs.get("password") or "")
    sslmode = str(connect_kwargs.get("sslmode") or "prefer").strip() or "prefer"
    gss = str(connect_kwargs.get("gssencmode") or "prefer").strip() or "prefer"

    bin_q = shlex.quote((pg_dump_bin or "pg_dump").strip() or "pg_dump")
    rp = shlex.quote(remote_path)

    if fmt == "directory":
        prep = f"mkdir -p {rp}"
    else:
        parent = os.path.dirname(remote_path)
        prep = f"mkdir -p {shlex.quote(parent)}" if parent and parent != "/" else "true"

    parts: list[str] = [
        prep,
        f"export PGPASSWORD={shlex.quote(pwd)}",
        f"export PGSSLMODE={shlex.quote(sslmode)}",
        f"export PGGSSENCMODE={shlex.quote(gss)}",
        "export PGCLIENTENCODING=UTF8",
    ]
    dump_args = [
        bin_q,
        "-w",
        "-h",
        shlex.quote(host),
        "-p",
        str(port),
        "-U",
        shlex.quote(user),
        "-d",
        shlex.quote(dbname),
        f"-F{flag}",
        "-f",
        rp,
    ]
    if schema_only:
        dump_args.append("--schema-only")
    if data_only:
        dump_args.append("--data-only")
    if no_owner:
        dump_args.append("--no-owner")
    if no_privileges:
        dump_args.append("--no-acl")

    parts.append(" ".join(dump_args))
    script = " && ".join(parts)
    safe = (
        f"{bin_q} -w -h {shlex.quote(host)} -p {port} -U {shlex.quote(user)} -d {shlex.quote(dbname)} "
        f"-F{flag} -f {rp} …"
    )
    return script, safe


def run_remote_pg_dump(
    connection: dict,
    *,
    remote_path: str,
    fmt: DumpFormat,
    prefixes: tuple[str, ...],
    pg_dump_bin: str,
    schema_only: bool,
    data_only: bool,
    no_owner: bool,
    no_privileges: bool,
    log: LogFn,
    cancelled: CancelFn,
) -> int:
    """SSH to profile host, run ``pg_dump`` writing to ``remote_path``. Returns exit code or -1 if cancelled."""
    validate_remote_dump_path(remote_path, prefixes)
    kw = dict(ConnectionSettings.connect_kwargs(connection))
    script, safe_summary = build_remote_pg_dump_script(
        kw,
        remote_path=remote_path,
        fmt=fmt,
        pg_dump_bin=pg_dump_bin,
        schema_only=schema_only,
        data_only=data_only,
        no_owner=no_owner,
        no_privileges=no_privileges,
    )
    log(f"\n--- pg_dump на узле SSH (без вывода пароля) ---\n{safe_summary}\n\n")

    client: Optional[paramiko.SSHClient] = None
    try:
        client = connect_ssh_client(connection)
        stdin, stdout, stderr = client.exec_command(
            f"bash --noprofile --norc -c {shlex.quote(script)}",
            get_pty=False,
        )
        _ = stdin
        ch = stdout.channel
        st = time.monotonic()
        while not ch.exit_status_ready():
            if cancelled():
                try:
                    ch.close()
                except Exception:
                    pass
                log("\n[остановлено пользователем]\n")
                return -1
            if stderr.channel.recv_stderr_ready():
                chunk = stderr.channel.recv_stderr(65536)
                if chunk:
                    log(chunk.decode("utf-8", errors="replace"))
            if ch.recv_ready():
                chunk = ch.recv(65536)
                if chunk:
                    log(chunk.decode("utf-8", errors="replace"))
            if time.monotonic() - st > 86400:
                log("\n[превышен лимит времени 24 ч]\n")
                ch.close()
                return 124
            time.sleep(0.05)

        while stderr.channel.recv_stderr_ready():
            chunk = stderr.channel.recv_stderr(65536)
            if chunk:
                log(chunk.decode("utf-8", errors="replace"))
        while ch.recv_ready():
            chunk = ch.recv(65536)
            if chunk:
                log(chunk.decode("utf-8", errors="replace"))

        code = ch.recv_exit_status()
        return int(code)
    except (paramiko.SSHException, OSError, ValueError) as e:
        logging.exception("remote pg_dump failed")
        log(f"\n[ошибка SSH/pg_dump] {e}\n")
        return 1
    finally:
        if client is not None:
            try:
                client.close()
            except Exception:
                pass
