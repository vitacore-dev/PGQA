import json
import tempfile
import unittest
from pathlib import Path

from pg_query_analyzer.storage.connections import ConnectionSettings


class FakeKeyring:
    class errors:
        class PasswordDeleteError(Exception):
            pass

    def __init__(self):
        self.passwords = {}

    def get_password(self, service, account):
        return self.passwords.get((service, account))

    def set_password(self, service, account, password):
        self.passwords[(service, account)] = password

    def delete_password(self, service, account):
        try:
            del self.passwords[(service, account)]
        except KeyError as e:
            raise self.errors.PasswordDeleteError() from e


class TestConnectionSettings(ConnectionSettings):
    keyring_backend = FakeKeyring()


class ConnectionSettingsTest(unittest.TestCase):
    def test_sanitize_connections_removes_passwords(self):
        sanitized = ConnectionSettings.sanitize_connections(
            {
                "local": {
                    "host": "localhost",
                    "port": "5432",
                    "dbname": "postgres",
                    "user": "postgres",
                    "password": "secret",
                    "ssh": {
                        "enabled": True,
                        "host": "ssh.local",
                        "user": "root",
                        "password": "ssh-secret",
                    },
                }
            }
        )

        self.assertNotIn("password", sanitized["local"])
        self.assertNotIn("password", sanitized["local"]["ssh"])

    def test_load_connections_migrates_plaintext_password(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            settings_file = Path(temp_dir) / "pg_connections.json"
            settings_file.write_text(
                json.dumps(
                    {
                        "local": {
                            "host": "localhost",
                            "port": "5432",
                            "dbname": "postgres",
                            "user": "postgres",
                            "password": "secret",
                        }
                    }
                ),
                encoding="utf-8",
            )

            class TempConnectionSettings(TestConnectionSettings):
                SETTINGS_FILE = str(settings_file)

            connections = TempConnectionSettings.load_connections()
            saved_connections = json.loads(settings_file.read_text(encoding="utf-8"))

            self.assertEqual(connections["local"]["password"], "secret")
            self.assertNotIn("password", saved_connections["local"])


if __name__ == "__main__":
    unittest.main()
