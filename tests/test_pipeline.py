"""Pipeline integration tests covering cleaning, project splitting, metrics, McNemar, and smoke training.

Compatible with both unittest (python -m unittest) and pytest.
"""

from __future__ import annotations

import os
import tempfile
import unittest
import numpy as np
import pandas as pd

from scripts.make_sample_data import generate_sample_dataset
from src.vulndetect.data import clean, split_by_project
from src.vulndetect.evaluate import mcnemar, metrics
from src.vulndetect.features import FEATURE_NAMES, extract_features
from src.vulndetect.model import (
    predict_binary,
    predict_cwe,
    predict_scores,
    train_and_tune,
)
from src.vulndetect.scanner import scan_code


class TestDataCleaningAndSplit(unittest.TestCase):
    """Test dataset deduplication, conflict resolution, and project-aware partitioning."""

    def test_cleaning_drops_empty_and_normalises_duplicates(self):
        data = {
            "id": ["1", "2", "3", "4", "5"],
            "project": ["p1", "p1", "p2", "p2", "p3"],
            "code": [
                "def func():\n    return 42",
                "def func():  # trailing comment\n    return 42",  # Duplicate of 1 after normalization
                "",  # Empty
                "   \n  \t  ",  # Whitespace only
                "def other():\n    return 100",
            ],
            "label": [0, 0, 0, 0, 0],
            "cwe": ["none", "none", "none", "none", "none"],
        }
        df = pd.DataFrame(data)
        cleaned_df, report = clean(df)

        self.assertEqual(report["empty_removed"], 2)
        self.assertEqual(report["duplicates_removed"], 1)
        self.assertEqual(len(cleaned_df), 2)

    def test_cleaning_removes_conflicting_labels(self):
        """Identical normalised code with contradictory labels must be pruned."""
        data = {
            "id": ["1", "2"],
            "project": ["p1", "p2"],
            "code": [
                "def do_query(uid):\n    conn.execute(uid)",
                "def do_query(uid): # comment\n    conn.execute(uid)",
            ],
            "label": [1, 0],  # Conflicting labels
            "cwe": ["sqli", "none"],
        }
        df = pd.DataFrame(data)
        cleaned_df, report = clean(df)

        self.assertEqual(report["conflicting_removed"], 2)
        self.assertEqual(len(cleaned_df), 0)

    def test_split_by_project_disjoint(self):
        """Verify GroupShuffleSplit prevents project overlap between partitions."""
        projects = [f"proj_{i}" for i in range(10)]
        data = []
        for p in projects:
            for s in range(5):
                data.append({
                    "id": f"{p}_{s}",
                    "project": p,
                    "code": f"def func_{p}_{s}(): return {s}",
                    "label": s % 2,
                    "cwe": "sqli" if s % 2 == 1 else "none",
                })
        df = pd.DataFrame(data)

        train_df, test_df = split_by_project(df, test_size=0.3, random_state=42)
        train_projects = set(train_df["project"])
        test_projects = set(test_df["project"])

        self.assertTrue(len(train_projects) > 0)
        self.assertTrue(len(test_projects) > 0)
        # Strict zero-leakage check
        self.assertEqual(len(train_projects.intersection(test_projects)), 0)


class TestEvaluationAndMcNemar(unittest.TestCase):
    """Test evaluation metrics and McNemar paired significance testing."""

    def test_metrics_calculation(self):
        y_true = [1, 1, 0, 0, 1, 0, 1, 0]
        y_pred = [1, 0, 0, 0, 1, 1, 1, 0]

        res = metrics(y_true, y_pred)
        self.assertEqual(res["tp"], 3)
        self.assertEqual(res["fn"], 1)
        self.assertEqual(res["fp"], 1)
        self.assertEqual(res["tn"], 3)
        self.assertEqual(res["accuracy"], 0.75)
        self.assertAlmostEqual(res["precision"], 3 / 4)
        self.assertAlmostEqual(res["recall"], 3 / 4)
        self.assertAlmostEqual(res["F1"], 0.75)
        self.assertAlmostEqual(res["false_positive_rate"], 1 / 4)

    def test_mcnemar_exact_binomial_known_pvalue(self):
        """Test McNemar test when discordant pairs < 25 using known exact binomial p-value.

        Construct predictions where:
        b = 3 (A correct, B incorrect)
        c = 10 (A incorrect, B correct)
        Discordant n = 13.
        Exact two-sided binomial p-value for k=3, n=13, p=0.5:
        P(X <= 3) = (1 + 13 + 78 + 286) / 8192 = 378 / 8192 = 0.046142578125
        Two-sided = 2 * 0.046142578125 = 0.09228515625
        """
        # 10 cases both correct (y_true=1, A=1, B=1)
        # 3 cases A correct, B incorrect (y_true=1, A=1, B=0) -> b = 3
        # 10 cases A incorrect, B correct (y_true=1, A=0, B=1) -> c = 10
        # 5 cases both incorrect (y_true=1, A=0, B=0)
        y_true = [1] * 28
        y_pred_a = ([1] * 10) + ([1] * 3) + ([0] * 10) + ([0] * 5)
        y_pred_b = ([1] * 10) + ([0] * 3) + ([1] * 10) + ([0] * 5)

        res = mcnemar(y_true, y_pred_a, y_pred_b)

        self.assertEqual(res["method"], "exact_binomial")
        self.assertEqual(res["contingency_table"]["b"], 3)
        self.assertEqual(res["contingency_table"]["c"], 10)
        self.assertEqual(res["discordant_pairs"], 13)
        self.assertAlmostEqual(res["p_value"], 0.092285, places=4)
        self.assertFalse(res["significant"])

    def test_mcnemar_chi2_continuity_large_sample(self):
        """Test McNemar test with >= 25 discordant pairs triggers continuity correction."""
        # b = 10, c = 30 -> discordant = 40 >= 25
        # stat = (|10 - 30| - 1)^2 / 40 = 19^2 / 40 = 361 / 40 = 9.025
        y_true = [1] * 50
        y_pred_a = ([1] * 10) + ([0] * 30) + ([1] * 10)
        y_pred_b = ([0] * 10) + ([1] * 30) + ([1] * 10)

        res = mcnemar(y_true, y_pred_a, y_pred_b)
        self.assertEqual(res["method"], "chi2_continuity")
        self.assertAlmostEqual(res["statistic"], 9.025, places=3)
        self.assertTrue(res["significant"])


class TestEndToEndPipeline(unittest.TestCase):
    """End-to-end smoke test verifying pipeline integration on toy data."""

    def test_toy_data_training_and_scanning(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            csv_path = os.path.join(tmp_dir, "test_dataset.csv")
            generate_sample_dataset(csv_path)

            raw_df = pd.read_csv(csv_path)
            cleaned_df, _ = clean(raw_df)
            train_df, test_df = split_by_project(cleaned_df, test_size=0.25, random_state=42)

            # Feature vectors
            X_train = np.array([
                [float(extract_features(str(code)).get(col, 0.0)) for col in FEATURE_NAMES]
                for code in train_df["code"]
            ])
            y_train = train_df["cwe"].values
            groups_train = train_df["project"].values

            artifacts = train_and_tune(
                X_train,
                y_train,
                groups_train,
                param_grid={"n_estimators": [30], "max_depth": [5]},
                n_splits=2,
            )

            # Test inference
            sample_code = """def fetch(user):
    import os
    os.system(f"cat /home/{user}/data")
"""
            findings = scan_code(
                sample_code,
                artifacts,
                file_name="test_snippet.py",
                enable_bandit=True,
            )

            self.assertGreaterEqual(len(findings), 1)
            first = findings[0]
            self.assertIn("risk_score", first)
            self.assertIn("weakness_type", first)
            self.assertIn("explanation", first)
            self.assertIn("fix_suggestion", first)


if __name__ == "__main__":
    unittest.main()
