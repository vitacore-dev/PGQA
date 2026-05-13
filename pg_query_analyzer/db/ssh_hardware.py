"""Сбор профиля «железа» по SSH (те же учётные данные, что и для туннеля)."""

from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import paramiko

logger = logging.getLogger(__name__)

_CMD_TIMEOUT = 18


def _to_int(value, default: int) -> int:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return default


def _load_private_key(key_path: str) -> Optional[paramiko.PKey]:
    path = str(Path(key_path).expanduser())
    if not path or not Path(path).is_file():
        return None
    for key_cls in (
        paramiko.RSAKey,
        paramiko.Ed25519Key,
        paramiko.ECDSAKey,
    ):
        try:
            return key_cls.from_private_key_file(path)
        except Exception:
            continue
    return None


def _connect_client(connection: dict) -> paramiko.SSHClient:
    ssh_cfg = connection.get("ssh") or {}
    if not ssh_cfg.get("enabled"):
        raise ValueError(
            "В сохранённом подключении не включён SSH (нужен тот же профиль, что и для туннеля)."
        )

    host = (ssh_cfg.get("host") or "").strip()
    user = (ssh_cfg.get("user") or "").strip()
    if not host or not user:
        raise ValueError("Для SSH не заданы host или user.")

    port = _to_int(ssh_cfg.get("port"), 22)
    password = (ssh_cfg.get("password") or None) or None
    if password == "":
        password = None

    key_path = (ssh_cfg.get("private_key_path") or "").strip()
    pkey = _load_private_key(key_path) if key_path else None

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    kwargs: dict[str, Any] = {
        "hostname": host,
        "port": port,
        "username": user,
        "timeout": 25,
        "banner_timeout": 30,
        "allow_agent": False,
        "look_for_keys": False,
    }
    if pkey is not None:
        kwargs["pkey"] = pkey
    if password:
        kwargs["password"] = password
    if pkey is None and not password:
        raise ValueError("Задайте SSH-пароль (или сохраните его) либо путь к приватному ключу.")

    client.connect(**kwargs)
    return client


def connect_ssh_client(connection: dict) -> paramiko.SSHClient:
    """Открыть SSH-сессию по тем же правилам, что туннель и сбор профиля железа."""
    return _connect_client(connection)


def _exec(client: paramiko.SSHClient, command: str) -> tuple[int, str, str]:
    stdin, stdout, stderr = client.exec_command(command, timeout=_CMD_TIMEOUT)
    _ = stdin
    code = stdout.channel.recv_exit_status()
    out = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace")
    return code, out, err


def _parse_linux_meminfo_kb(text: str) -> dict[str, Any]:
    mem_total_kb = None
    mem_avail_kb = None
    swap_total_kb = None
    for line in text.splitlines():
        if line.startswith("MemTotal:"):
            m = re.search(r"MemTotal:\s+(\d+)", line)
            if m:
                mem_total_kb = int(m.group(1))
        elif line.startswith("MemAvailable:"):
            m = re.search(r"MemAvailable:\s+(\d+)", line)
            if m:
                mem_avail_kb = int(m.group(1))
        elif line.startswith("SwapTotal:"):
            m = re.search(r"SwapTotal:\s+(\d+)", line)
            if m:
                swap_total_kb = int(m.group(1))
    out: dict[str, Any] = {}
    if mem_total_kb is not None:
        out["mem_total_kb"] = mem_total_kb
        out["mem_total_gb_rounded"] = round(mem_total_kb / (1024 * 1024), 2)
    if mem_avail_kb is not None:
        out["mem_available_kb"] = mem_avail_kb
    if swap_total_kb is not None:
        out["swap_total_kb"] = swap_total_kb
    return out


def _parse_nproc(text: str) -> int | None:
    t = text.strip().split()
    if not t:
        return None
    try:
        return int(t[0])
    except ValueError:
        return None


def collect_hardware_via_ssh(connection: dict) -> dict[str, Any]:
    """
    Выполняет только read-only команды на SSH-хосте из профиля.

    Важно: это узел, к которому подключается SSH (часто совпадает с PG, но не всегда —
    см. поле caveat в результате).
    """
    ssh_cfg = connection.get("ssh") or {}
    ssh_host = (ssh_cfg.get("host") or "").strip()
    pg_host = (connection.get("host") or "").strip()

    caveat = (
        "Данные сняты на SSH-хосте «{ssh}». Хост PostgreSQL в профиле: «{pg}». "
        "Если PostgreSQL работает на другом сервере (jump/bastion), этот профиль относится к bastion, а не к БД."
    ).format(ssh=ssh_host or "?", pg=pg_host or "?")

    result: dict[str, Any] = {
        "collected_at_utc": datetime.now(timezone.utc).isoformat(),
        "ssh_endpoint": {
            "host": ssh_host,
            "user": (ssh_cfg.get("user") or "").strip(),
            "port": _to_int(ssh_cfg.get("port"), 22),
        },
        "postgres_profile_host": pg_host,
        "caveat": caveat,
        "os": {},
        "cpu": {},
        "memory": {},
        "storage": {},
        "raw_excerpts": {},
        "warnings": [],
    }

    client = _connect_client(connection)
    try:
        _, uname_out, _ = _exec(client, "uname -srm 2>/dev/null || uname -a")
        result["os"]["uname"] = uname_out.strip()

        _, kern_out, _ = _exec(client, "uname -s 2>/dev/null")
        kernel_name = kern_out.strip()
        if kernel_name == "Darwin":
            _, mem_sz, _ = _exec(client, "sysctl -n hw.memsize 2>/dev/null")
            _, ncpu_sz, _ = _exec(client, "sysctl -n hw.ncpu 2>/dev/null")
            _, phys_sz, _ = _exec(client, "sysctl -n hw.physicalcpu 2>/dev/null")
            _, brand_sz, _ = _exec(client, "sysctl -n machdep.cpu.brand_string 2>/dev/null")
            mem_bytes = None
            try:
                mem_bytes = int(mem_sz.strip())
            except ValueError:
                pass
            ncpu = _parse_nproc(ncpu_sz)
            phys = _parse_nproc(phys_sz)
            brand = brand_sz.strip() or None
            result["memory"]["mem_total_bytes"] = mem_bytes
            if mem_bytes is not None:
                result["memory"]["mem_total_gb_rounded"] = round(mem_bytes / (1024**3), 2)
            if ncpu is not None:
                result["cpu"]["cpus_online"] = ncpu
            if phys is not None:
                result["cpu"]["physical_cpus"] = phys
            if brand:
                result["cpu"]["model_name"] = brand
            _, df_out, _ = _exec(client, "df -h / 2>/dev/null | tail -n 1")
            result["storage"]["root_df_line"] = df_out.strip()
        else:
            # Linux и прочие UNIX с /proc
            _, mem_raw, mem_err = _exec(client, "cat /proc/meminfo 2>/dev/null | head -n 40")
            if mem_raw.strip():
                parsed = _parse_linux_meminfo_kb(mem_raw)
                result["memory"].update(parsed)
            elif mem_err.strip():
                result["warnings"].append(f"meminfo: {mem_err.strip()[:120]}")

            _, nproc_out, _ = _exec(
                client, "getconf _NPROCESSORS_ONLN 2>/dev/null || nproc 2>/dev/null || echo 0"
            )
            nproc = _parse_nproc(nproc_out)
            if nproc is not None and nproc > 0:
                result["cpu"]["cpus_online"] = nproc

            _, lscpu_out, _ = _exec(client, "lscpu 2>/dev/null | head -n 60")
            if lscpu_out.strip():
                result["raw_excerpts"]["lscpu"] = lscpu_out.strip()[:4000]
                for line in lscpu_out.splitlines():
                    if line.strip().startswith("Model name:"):
                        result["cpu"]["model_name"] = line.split(":", 1)[-1].strip()
                        break

            _, lsblk_out, _ = _exec(
                client, "lsblk -d -o NAME,ROTA,TYPE,SIZE,MODEL 2>/dev/null | head -n 40"
            )
            if lsblk_out.strip():
                result["raw_excerpts"]["lsblk"] = lsblk_out.strip()[:4000]

            _, df_out, _ = _exec(client, "df -hT / 2>/dev/null | tail -n 1")
            if df_out.strip():
                result["storage"]["root_df_line"] = df_out.strip()

        if not result["memory"] and kernel_name != "Darwin":
            result["warnings"].append(
                "Не удалось разобрать память (возможно, не Linux или нет доступа к /proc)."
            )

        return result
    except Exception as e:
        logger.exception("SSH hardware collection failed")
        raise RuntimeError(f"Ошибка SSH-сбора профиля железа: {e}") from e
    finally:
        try:
            client.close()
        except Exception:
            pass
