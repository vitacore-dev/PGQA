"""Fetch PostgreSQL log files from the SSH host (whitelist paths, size cap)."""

from __future__ import annotations

import logging
import os
import shlex
import stat as statmod
from typing import Optional, Tuple

import paramiko
import psycopg2

from pg_query_analyzer.db.remote_pg_dump import parse_prefix_whitelist, validate_remote_dump_path
from pg_query_analyzer.db.ssh_hardware import connect_ssh_client
from pg_query_analyzer.storage.connections import ConnectionSettings

LOG_DEFAULT_PREFIXES: tuple[str, ...] = (
    "/var/lib/postgresql/",
    "/var/log/postgresql/",
    "/var/backups/",
    "/tmp/pgqa_backup/",
)

logger = logging.getLogger(__name__)


def parse_log_prefix_whitelist(text: str) -> tuple[str, ...]:
    """Like :func:`parse_prefix_whitelist`, but empty input → log-friendly defaults."""
    if not (text or "").strip():
        return LOG_DEFAULT_PREFIXES
    return parse_prefix_whitelist(text)


def resolve_log_directory_absolute(connection: dict) -> str:
    """Return absolute ``log_directory`` (relative paths are resolved against ``data_directory``)."""

    kw = dict(ConnectionSettings.connect_kwargs(connection))
    with psycopg2.connect(**kw) as conn:
        conn.autocommit = True
        with conn.cursor() as cur:
            cur.execute("SHOW data_directory")
            row_dd = cur.fetchone()
            cur.execute("SHOW log_directory")
            row_ld = cur.fetchone()

    dd = (row_dd[0] if row_dd else "") or ""
    ld = (row_ld[0] if row_ld else "") or ""
    dd = str(dd).strip()
    ld = str(ld).strip()
    if not dd:
        raise ValueError("SHOW data_directory вернул пустое значение.")
    if not ld:
        raise ValueError("SHOW log_directory вернул пустое значение.")
    if ld.startswith("/"):
        return os.path.normpath(ld)
    return os.path.normpath(os.path.join(dd, ld))


def fetch_remote_postgresql_log_text(
    connection: dict,
    remote_path: str,
    prefixes: tuple[str, ...],
    *,
    max_bytes: int,
) -> Tuple[str, str]:
    """Download log file via SSH.

    Small files: SFTP read. Larger than ``max_bytes``: ``tail -c`` on the server (last *max_bytes* bytes).

    Returns ``(text, info_line)`` where *info_line* is a short status for the UI (UTF-8, errors replaced).
    """

    path = (remote_path or "").strip()
    validate_remote_dump_path(path, prefixes)

    cap = int(max_bytes)
    if cap < 64 * 1024:
        raise ValueError("Минимальный лимит размера — 64 KiB.")
    if cap > 512 * 1024 * 1024:
        raise ValueError("Максимальный лимит размера — 512 MiB.")

    client: Optional[paramiko.SSHClient] = None
    sftp: Optional[paramiko.SFTPClient] = None
    try:
        client = connect_ssh_client(connection)
        sftp = client.open_sftp()
        st = sftp.stat(path)
        if statmod.S_ISDIR(st.st_mode):
            raise ValueError("Укажите файл лога, а не каталог.")

        size = int(getattr(st, "st_size", 0) or 0)
        truncated = False

        if size <= cap:
            with sftp.open(path, "rb") as rf:
                raw = rf.read()
            info = f"SFTP: {path} ({len(raw)} B из {size} B)"
        else:
            truncated = True
            cmd = f"tail -c {cap} {shlex.quote(path)}"
            stdin, stdout, stderr = client.exec_command(cmd, get_pty=False)
            _ = stdin
            raw = stdout.read()
            err_b = stderr.read()
            code = stdout.channel.recv_exit_status()
            if code != 0:
                err_t = err_b.decode("utf-8", errors="replace").strip()
                raise OSError(f"tail завершился с кодом {code}: {err_t or 'нет текста stderr'}")
            info = f"tail -c {cap}: {path} (файл ~{size} B, загружен хвост)"

        text = raw.decode("utf-8", errors="replace")
        if truncated:
            info += " · обрезано по лимиту"
        return text, info
    except (paramiko.SSHException, OSError, ValueError) as e:
        logger.exception("remote log fetch failed")
        raise
    finally:
        if sftp is not None:
            try:
                sftp.close()
            except Exception:
                pass
        if client is not None:
            try:
                client.close()
            except Exception:
                pass
