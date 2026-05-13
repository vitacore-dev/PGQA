"""Helpers for SSH tunnels used by PostgreSQL connections."""

from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
from typing import Iterator, Optional

from sshtunnel import SSHTunnelForwarder


def _to_int(value, default: int) -> int:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return default


@contextmanager
def open_ssh_tunnel_if_needed(connection: dict) -> Iterator[Optional[SSHTunnelForwarder]]:
    """Open SSH tunnel for a connection profile when SSH is enabled."""
    ssh_cfg = connection.get("ssh") or {}
    if not ssh_cfg.get("enabled"):
        yield None
        return

    ssh_host = (ssh_cfg.get("host") or "").strip()
    ssh_user = (ssh_cfg.get("user") or "").strip()
    if not ssh_host or not ssh_user:
        raise ValueError("SSH включен, но не задан host или user")

    remote_host = (connection.get("host") or "").strip()
    if not remote_host:
        raise ValueError("Не задан PostgreSQL host для SSH-туннеля")

    ssh_port = _to_int(ssh_cfg.get("port"), 22)
    remote_port = _to_int(connection.get("port"), 5432)
    ssh_password = ssh_cfg.get("password") or None
    private_key = (ssh_cfg.get("private_key_path") or "").strip()
    private_key_file = str(Path(private_key).expanduser()) if private_key else None

    tunnel = SSHTunnelForwarder(
        (ssh_host, ssh_port),
        ssh_username=ssh_user,
        ssh_password=ssh_password,
        ssh_pkey=private_key_file,
        remote_bind_address=(remote_host, remote_port),
        local_bind_address=("127.0.0.1", 0),
    )
    tunnel.start()
    try:
        yield tunnel
    finally:
        tunnel.stop()
