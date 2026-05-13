"""Тесты разбора вывода ОС для SSH-профиля железа."""

import unittest

from pg_query_analyzer.db.ssh_hardware import _parse_linux_meminfo_kb


class TestMeminfoParse(unittest.TestCase):
    def test_basic(self):
        text = """MemTotal:       16304780 kB
MemAvailable:    8123456 kB
SwapTotal:       1048572 kB
"""
        d = _parse_linux_meminfo_kb(text)
        self.assertEqual(d["mem_total_kb"], 16304780)
        self.assertEqual(d["mem_available_kb"], 8123456)
        self.assertEqual(d["swap_total_kb"], 1048572)
        self.assertIn("mem_total_gb_rounded", d)


if __name__ == "__main__":
    unittest.main()
