"""Unit tests covering feature extraction, Bandit mapping, code splitting, and SQLite persistence.

Compatible with both unittest (python -m unittest) and pytest.
"""

from __future__ import annotations

import os
import tempfile
import unittest

from src.vulndetect.bandit_baseline import bandit_flags, map_test_ids
from src.vulndetect.db import connect, get_findings, list_scans, save_scan
from src.vulndetect.features import (
    FEATURE_NAMES,
    _empty_features,
    extract_features,
)
from src.vulndetect.scanner import split_python_file


class TestFeatureExtraction(unittest.TestCase):
    """Test AST feature extraction across safe and unsafe patterns."""

    def test_unparseable_code_returns_all_zeros(self):
        """Syntax errors should return all-zero vector rather than crashing."""
        malformed = "def broken_syntax(x: return x +++ {"
        feats = extract_features(malformed)
        expected = _empty_features()
        self.assertEqual(feats, expected)

    def test_sql_injection_safe_vs_unsafe(self):
        """Dynamic string formatting in DB query triggers features; parameterized query does not."""
        unsafe_sql = """def query_user(conn, uid):
    conn.execute(f"SELECT * FROM users WHERE id = {uid}")
"""
        safe_sql = """def query_user(conn, uid):
    conn.execute("SELECT * FROM users WHERE id = ?", (uid,))
"""
        feats_unsafe = extract_features(unsafe_sql)
        feats_safe = extract_features(safe_sql)

        self.assertGreater(feats_unsafe["db_execute_calls"], 0)
        self.assertGreater(feats_unsafe["dynamic_sql_construction"], 0)
        self.assertGreater(feats_unsafe["sql_keywords"], 0)

        self.assertGreater(feats_safe["db_execute_calls"], 0)
        self.assertEqual(feats_safe["dynamic_sql_construction"], 0)

    def test_command_injection_safe_vs_unsafe(self):
        """os.system or shell=True triggers features; subprocess with shell=False does not."""
        unsafe_cmd = """def run_ping(host):
    import os
    os.system("ping " + host)
"""
        safe_cmd = """def run_ping(host):
    import subprocess
    subprocess.run(["ping", host], shell=False)
"""
        feats_unsafe = extract_features(unsafe_cmd)
        feats_safe = extract_features(safe_cmd)

        self.assertGreater(feats_unsafe["os_system_calls"], 0)
        self.assertEqual(feats_safe["os_system_calls"], 0)
        self.assertEqual(feats_safe["shell_true_flag"], 0)

    def test_credentials_safe_vs_unsafe(self):
        """String literal password assignment triggers feature; env var access does not."""
        unsafe_creds = 'password = "SuperSecretPassword123!"'
        safe_creds = 'password = os.environ.get("DB_PASSWORD")'

        feats_unsafe = extract_features(unsafe_creds)
        feats_safe = extract_features(safe_creds)

        self.assertGreater(feats_unsafe["secret_var_assigned"], 0)
        self.assertEqual(feats_safe["secret_var_assigned"], 0)

    def test_deserialisation_safe_vs_unsafe(self):
        """pickle.loads triggers feature; json.loads does not."""
        unsafe_deser = """import pickle
data = pickle.loads(stream)
"""
        safe_deser = """import json
data = json.loads(stream)
"""
        feats_unsafe = extract_features(unsafe_deser)
        feats_safe = extract_features(safe_deser)

        self.assertGreater(feats_unsafe["pickle_calls"], 0)
        self.assertEqual(feats_safe["pickle_calls"], 0)


class TestBanditBaseline(unittest.TestCase):
    """Test Bandit test ID mappings and flags."""

    def test_map_test_ids(self):
        mapping = map_test_ids()
        self.assertEqual(mapping["B608"], "sqli")
        self.assertEqual(mapping["B602"], "cmdi")
        self.assertEqual(mapping["B105"], "creds")
        self.assertEqual(mapping["B301"], "deser")
        self.assertEqual(mapping["B506"], "deser")

    def test_bandit_flags_structure(self):
        code = 'import os\nos.system("ls -la")'
        res = bandit_flags(code)
        self.assertIn("flagged", res)
        self.assertIn("cwe_flags", res)
        self.assertIn("issues", res)
        self.assertTrue(res["cwe_flags"]["cmdi"])


class TestScannerSplitting(unittest.TestCase):
    """Test code splitting into functions and module-level segments."""

    def test_split_functions_and_module(self):
        code = """import sys

def func_a(x):
    return x * 2

val = func_a(10)

def func_b(y):
    return y + 5
"""
        segments = split_python_file(code)
        names = [s.name for s in segments]
        self.assertIn("def func_a()", names)
        self.assertIn("def func_b()", names)
        self.assertIn("<module_level>", names)


class TestDatabaseRoundTrip(unittest.TestCase):
    """Test SQLite storage and retrieval of scans and findings."""

    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.tmp_dir.name, "test_scans.db")

    def tearDown(self):
        self.tmp_dir.cleanup()

    def test_save_and_get_findings(self):
        dummy_findings = [
            {
                "line_number": 12,
                "weakness_type": "sqli",
                "risk_score": 0.875,
                "bandit_flag": 1,
                "explanation": "Dynamic query with SQL concatenation.",
            },
            {
                "line_number": 25,
                "weakness_type": "none",
                "risk_score": 0.05,
                "bandit_flag": 0,
                "explanation": "No vulnerability detected.",
            },
        ]

        scan_id = save_scan(
            file_name="test_service.py",
            findings=dummy_findings,
            model_version="1.0.0",
            db_path=self.db_path,
        )

        self.assertTrue(bool(scan_id))

        retrieved = get_findings(scan_id, self.db_path)
        self.assertEqual(len(retrieved), 2)
        self.assertEqual(retrieved[0]["weakness_type"], "sqli")
        self.assertAlmostEqual(retrieved[0]["risk_score"], 0.875)
        self.assertEqual(retrieved[0]["line_number"], 12)

        scans = list_scans(self.db_path)
        self.assertEqual(len(scans), 1)
        self.assertEqual(scans[0]["file_name"], "test_service.py")
        self.assertEqual(scans[0]["n_findings"], 2)


if __name__ == "__main__":
    unittest.main()
