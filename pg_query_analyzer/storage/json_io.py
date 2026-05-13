"""Shared JSON persistence helpers."""

from __future__ import annotations

import json
import os
import tempfile
from typing import Any


def atomic_write_json(path: str, data: Any, *, indent: int = 2, ensure_ascii: bool = False) -> None:
    """Write JSON via a same-directory temporary file and atomic replace."""

    directory = os.path.dirname(os.path.abspath(path)) or "."
    os.makedirs(directory, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(
        prefix=f".{os.path.basename(path)}.",
        suffix=".tmp",
        dir=directory,
        text=True,
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=indent, ensure_ascii=ensure_ascii)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, path)
    except Exception:
        try:
            os.unlink(tmp_path)
        except FileNotFoundError:
            pass
        raise
