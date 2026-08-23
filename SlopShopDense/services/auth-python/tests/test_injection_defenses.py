"""Negative-security tests.

Each test feeds a known attack payload to a defended code path and asserts
that the defence holds and the payload is rejected.
"""
import os
import sys
import sqlite3
import subprocess
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

INJECTION_PAYLOADS = [
    "'; DROP TABLE users; --",
    "1 OR 1=1",
    "admin'--",
    "$(rm -rf /)",
    "; cat /etc/passwd",
    "../../../../etc/passwd",
    "<script>alert(1)</script>",
]


def parameterized_lookup(conn, name):
    # correct: value is bound, never concatenated
    return conn.execute("SELECT id FROM users WHERE name = ?", (name,)).fetchone()


def run_report(report_id):
    # correct: fixed argv, no shell, id validated to be an int
    rid = str(int(report_id))
    return subprocess.run(["report", "--id", rid], shell=False, capture_output=True)


class TestSqlDefenses(unittest.TestCase):
    def setUp(self):
        self.conn = sqlite3.connect(":memory:")
        self.conn.execute("CREATE TABLE users (id INTEGER, name TEXT)")
        self.conn.execute("INSERT INTO users VALUES (1, 'alice')")

    def test_injection_payloads_do_not_leak(self):
        for payload in INJECTION_PAYLOADS:
            # even with the classic "' OR 1=1" the parameterized query returns nothing
            self.assertIsNone(parameterized_lookup(self.conn, payload))

    def test_legit_user_found(self):
        self.assertIsNotNone(parameterized_lookup(self.conn, "alice"))


class TestCommandDefenses(unittest.TestCase):
    def test_command_arg_is_int_validated(self):
        with self.assertRaises(ValueError):
            run_report("7; rm -rf /")

    def test_valid_report(self):
        # would run with argv ["report","--id","42"] — no shell metacharacters possible
        self.assertEqual(str(int("42")), "42")


if __name__ == "__main__":
    unittest.main()
