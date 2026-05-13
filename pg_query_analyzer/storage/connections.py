"""Connection settings storage with passwords kept outside JSON files."""

import json
import logging
import os
import shutil
import urllib.parse

from pg_query_analyzer.storage.json_io import atomic_write_json

try:
    import keyring
except ImportError:  # pragma: no cover - exercised when optional dependency is absent.
    keyring = None


class ConnectionSettings:
    """JSON file name; full path is built from the package root (stable regardless of process cwd)."""

    SETTINGS_FILE = "pg_connections.json"
    KEYRING_SERVICE = "PSQLQA"
    SSH_KEYRING_SERVICE = "PSQLQA_SSH"
    keyring_backend = keyring

    @classmethod
    def _settings_path(cls) -> str:
        # .../pg_query_analyzer/storage/connections.py -> package root pg_query_analyzer/
        pkg_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        return os.path.join(pkg_root, cls.SETTINGS_FILE)

    @classmethod
    def _read_connections_file(cls):
        path = cls._settings_path()
        if not os.path.isfile(path):
            legacy = os.path.join(os.getcwd(), cls.SETTINGS_FILE)
            if os.path.isfile(legacy) and os.path.abspath(legacy) != os.path.abspath(path):
                try:
                    os.makedirs(os.path.dirname(path), exist_ok=True)
                    shutil.copy2(legacy, path)
                    logging.info(
                        "Скопирован %s из рабочей директории в %s (стабильное расположение)",
                        cls.SETTINGS_FILE,
                        path,
                    )
                except OSError as e:
                    logging.warning("Не удалось скопировать legacy %s: %s", legacy, e)
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except FileNotFoundError:
            return {}
        except json.JSONDecodeError:
            logging.error("Повреждён JSON в %s", path)
            return {}

    @classmethod
    def _write_connections_file(cls, connections):
        path = cls._settings_path()
        atomic_write_json(path, connections, indent=4, ensure_ascii=False)

    @classmethod
    def _keyring_account(cls, name):
        return f"connection:{name}"

    @classmethod
    def _ssh_keyring_account(cls, name):
        return f"ssh-connection:{name}"

    @classmethod
    def _get_password(cls, name):
        if cls.keyring_backend is None:
            logging.warning("Системное хранилище паролей недоступно")
            return ""

        try:
            return (
                cls.keyring_backend.get_password(cls.KEYRING_SERVICE, cls._keyring_account(name))
                or ""
            )
        except Exception as e:
            logging.error(f"Не удалось получить пароль из системного хранилища для '{name}': {e}")
            return ""

    @classmethod
    def _get_ssh_password(cls, name):
        if cls.keyring_backend is None:
            logging.warning("Системное хранилище паролей недоступно")
            return ""

        try:
            return (
                cls.keyring_backend.get_password(
                    cls.SSH_KEYRING_SERVICE, cls._ssh_keyring_account(name)
                )
                or ""
            )
        except Exception as e:
            logging.error(
                "Не удалось получить SSH пароль из системного хранилища для '%s': %s",
                name,
                e,
            )
            return ""

    @classmethod
    def _set_password(cls, name, password, raise_on_error=True):
        if cls.keyring_backend is None:
            if raise_on_error:
                raise RuntimeError("Системное хранилище паролей недоступно")
            return False

        try:
            cls.keyring_backend.set_password(
                cls.KEYRING_SERVICE,
                cls._keyring_account(name),
                password or "",
            )
            return True
        except Exception as e:
            logging.error(f"Не удалось сохранить пароль в системном хранилище для '{name}': {e}")
            if raise_on_error:
                raise RuntimeError("Не удалось сохранить пароль в системном хранилище") from e
            return False

    @classmethod
    def _set_ssh_password(cls, name, password, raise_on_error=True):
        if cls.keyring_backend is None:
            if raise_on_error:
                raise RuntimeError("Системное хранилище паролей недоступно")
            return False

        try:
            cls.keyring_backend.set_password(
                cls.SSH_KEYRING_SERVICE,
                cls._ssh_keyring_account(name),
                password or "",
            )
            return True
        except Exception as e:
            logging.error(
                "Не удалось сохранить SSH пароль в системном хранилище для '%s': %s",
                name,
                e,
            )
            if raise_on_error:
                raise RuntimeError("Не удалось сохранить SSH пароль в системном хранилище") from e
            return False

    @classmethod
    def _delete_password(cls, name):
        if cls.keyring_backend is None:
            return

        try:
            cls.keyring_backend.delete_password(cls.KEYRING_SERVICE, cls._keyring_account(name))
        except Exception as e:
            password_delete_error = getattr(
                getattr(cls.keyring_backend, "errors", None),
                "PasswordDeleteError",
                None,
            )
            if password_delete_error and isinstance(e, password_delete_error):
                return
            logging.warning(f"Не удалось удалить пароль из системного хранилища для '{name}': {e}")

    @classmethod
    def _delete_ssh_password(cls, name):
        if cls.keyring_backend is None:
            return

        try:
            cls.keyring_backend.delete_password(
                cls.SSH_KEYRING_SERVICE, cls._ssh_keyring_account(name)
            )
        except Exception as e:
            password_delete_error = getattr(
                getattr(cls.keyring_backend, "errors", None),
                "PasswordDeleteError",
                None,
            )
            if password_delete_error and isinstance(e, password_delete_error):
                return
            logging.warning(
                "Не удалось удалить SSH пароль из системного хранилища для '%s': %s",
                name,
                e,
            )

    @classmethod
    def load_connections(cls):
        connections = cls._read_connections_file()
        migrated = False

        for name, conn in connections.items():
            if "password" in conn:
                plaintext_password = conn.get("password", "")
                if cls._set_password(name, plaintext_password, raise_on_error=False):
                    del conn["password"]
                    conn["password"] = cls._get_password(name)
                    migrated = True
                else:
                    logging.warning(
                        "Пароль для '%s' пока оставлен в файле подключений: системное хранилище недоступно",
                        name,
                    )
                continue

            conn["password"] = cls._get_password(name)
            ssh = conn.get("ssh") or {}
            if "password" in ssh:
                plaintext_ssh_password = ssh.get("password", "")
                if cls._set_ssh_password(name, plaintext_ssh_password, raise_on_error=False):
                    ssh.pop("password", None)
                    migrated = True
            if ssh:
                ssh["password"] = cls._get_ssh_password(name)
                conn["ssh"] = ssh

        if migrated:
            cls.save_connections(connections)

        return connections

    @classmethod
    def connect_kwargs(cls, conn: dict) -> dict:
        """Normalize host/port/dbname for :func:`psycopg2.connect` (int port, timeouts)."""
        if not conn:
            raise ValueError("connection dict is empty")
        port_raw = conn.get("port", 5432)
        try:
            port = int(str(port_raw).strip())
        except (TypeError, ValueError):
            port = 5432
        dbn = (conn.get("dbname") or "").strip() or "postgres"
        sslmode = (conn.get("sslmode") or "").strip() or "prefer"
        gssencmode = (conn.get("gssencmode") or "").strip() or "prefer"
        ct = 15
        try:
            ct = int(conn.get("connect_timeout", 15))
        except (TypeError, ValueError):
            ct = 15

        return {
            "host": conn["host"],
            "port": port,
            "dbname": dbn,
            "user": conn["user"],
            "password": conn.get("password") or "",
            "connect_timeout": ct,
            "sslmode": sslmode,
            "gssencmode": gssencmode,
        }

    @classmethod
    def connection_uri(cls, conn: dict) -> str:
        """Один libpq connection URI (для повторной попытки :func:`psycopg2.connect` при ``OperationalError()``)."""

        kw = cls.connect_kwargs(conn)
        user = urllib.parse.quote(str(kw["user"]), safe="")
        passwd = urllib.parse.quote(str(kw["password"]), safe="")
        dbn = urllib.parse.quote(str(kw["dbname"]), safe="")
        host = str(kw["host"]).strip()
        port = int(kw["port"])
        sslmode_q = urllib.parse.quote(str(kw.get("sslmode") or "prefer"), safe="")
        gssencmode_q = urllib.parse.quote(str(kw.get("gssencmode") or "prefer"), safe="")
        ct = int(kw.get("connect_timeout") or 15)
        return (
            f"postgresql://{user}:{passwd}@{host}:{port}/{dbn}"
            f"?connect_timeout={ct}&sslmode={sslmode_q}&gssencmode={gssencmode_q}"
        )

    @classmethod
    def save_connections(cls, connections):
        sanitized = cls.sanitize_connections(connections)
        cls._write_connections_file(sanitized)

    @staticmethod
    def sanitize_connections(connections):
        sanitized = {}
        for name, conn in connections.items():
            clean = {k: v for k, v in conn.items() if k != "password"}
            ssh = clean.get("ssh")
            if isinstance(ssh, dict):
                clean["ssh"] = {k: v for k, v in ssh.items() if k != "password"}
            sanitized[name] = clean
        return sanitized

    @classmethod
    def add_connection(cls, name, host, port, dbname, user, password):
        connections = cls.load_connections()
        cls._set_password(name, password)
        connections[name] = {
            "host": host,
            "port": port,
            "dbname": dbname,
            "user": user,
        }
        cls.save_connections(connections)

    @classmethod
    def upsert_connection(cls, data: dict):
        name = data["name"]
        connections = cls.load_connections()
        cls._set_password(name, data.get("password", ""))
        ssh = data.get("ssh") or {}
        cls._set_ssh_password(name, ssh.get("password", ""))
        connections[name] = {
            "host": data["host"],
            "port": data["port"],
            "dbname": data["dbname"],
            "user": data["user"],
            "ssh": {
                "enabled": bool(ssh.get("enabled")),
                "host": ssh.get("host", ""),
                "port": ssh.get("port", "22"),
                "user": ssh.get("user", ""),
                "private_key_path": ssh.get("private_key_path", ""),
            },
        }
        cls.save_connections(connections)

    @classmethod
    def remove_connection(cls, name):
        connections = cls.load_connections()
        if name in connections:
            del connections[name]
            cls.save_connections(connections)
            cls._delete_password(name)
            cls._delete_ssh_password(name)
            return True
        return False
