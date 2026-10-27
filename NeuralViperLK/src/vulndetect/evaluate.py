"""Evaluation metrics and McNemar's paired statistical significance testing.

Computes classification metrics:
- TP, FP, TN, FN
- Precision, Recall, F1-score
- False Positive Rate (FPR)
- Accuracy

Implements McNemar's test for comparing paired classifier predictions:
- Exact two-sided binomial test when discordant pairs (b + c) < 25
- Chi-square test with Edward's continuity correction when (b + c) >= 25.
"""

from __future__ import annotations

import math
from typing import Any
import numpy as np

try:
    from scipy import stats as scipy_stats
except ImportError:
    scipy_stats = None


def metrics(
    y_true: np.ndarray | list[int] | list[bool],
    y_pred: np.ndarray | list[int] | list[bool],
) -> dict[str, float | int]:
    """Compute binary classification metrics for vulnerability detection.

    Args:
        y_true: Ground truth binary labels (0 = safe, 1 = vulnerable).
        y_pred: Predicted binary labels (0 = safe, 1 = vulnerable).

    Returns:
        Dictionary containing tp, fp, tn, fn, precision, recall, F1, false_positive_rate, accuracy.
    """
    y_t = np.asarray(y_true).astype(int)
    y_p = np.asarray(y_pred).astype(int)

    if len(y_t) != len(y_p):
        raise ValueError(f"Length mismatch: len(y_true)={len(y_t)} vs len(y_pred)={len(y_p)}")

    tp = int(np.sum((y_t == 1) & (y_p == 1)))
    fp = int(np.sum((y_t == 0) & (y_p == 1)))
    tn = int(np.sum((y_t == 0) & (y_p == 0)))
    fn = int(np.sum((y_t == 1) & (y_p == 0)))

    precision = float(tp / (tp + fp)) if (tp + fp) > 0 else 0.0
    recall = float(tp / (tp + fn)) if (tp + fn) > 0 else 0.0
    f1 = float(2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
    total = tp + fp + tn + fn
    accuracy = float((tp + tn) / total) if total > 0 else 0.0

    return {
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "F1": round(f1, 4),
        "false_positive_rate": round(fpr, 4),
        "accuracy": round(accuracy, 4),
    }


def _exact_binomial_pvalue(n: int, k: int) -> float:
    """Calculate exact two-sided binomial p-value for n trials with null p=0.5."""
    if n == 0:
        return 1.0

    # Two-sided p-value: sum of probabilities for outcomes as or more extreme than min(k, n-k)
    extreme_k = min(k, n - k)
    cumulative_p = 0.0
    for i in range(extreme_k + 1):
        cumulative_p += math.comb(n, i) * (0.5**n)

    # Multiply by 2 for two-sided test, bounded at 1.0
    p_val = min(1.0, 2.0 * cumulative_p)
    return p_val


def _chi2_sf_df1(x: float) -> float:
    """Survival function (p-value) for Chi-Square distribution with 1 degree of freedom."""
    if x <= 0:
        return 1.0
    # For df=1, Chi2(1) is equivalent to standard normal Z^2
    # sf = 2 * (1 - Phi(sqrt(x))) = erfc(sqrt(x/2))
    return math.erfc(math.sqrt(x / 2.0))


def mcnemar(
    y_true: np.ndarray | list[int],
    y_pred_a: np.ndarray | list[int],
    y_pred_b: np.ndarray | list[int],
) -> dict[str, Any]:
    """Execute McNemar's paired test comparing classifier A and classifier B.

    Contingency matrix structure:
    - a: both A and B correct
    - b: A correct, B incorrect
    - c: A incorrect, B correct
    - d: both A and B incorrect

    Discordant pairs = b + c.
    Uses exact binomial test when (b + c) < 25.
    Uses chi-square with Edwards' continuity correction when (b + c) >= 25:
        statistic = (|b - c| - 1)^2 / (b + c)

    Args:
        y_true: Ground truth binary labels.
        y_pred_a: Predictions from model A.
        y_pred_b: Predictions from model B.

    Returns:
        Dictionary containing statistic, p_value, method, contingency_table, significant.
    """
    yt = np.asarray(y_true).astype(int)
    pa = np.asarray(y_pred_a).astype(int)
    pb = np.asarray(y_pred_b).astype(int)

    if not (len(yt) == len(pa) == len(pb)):
        raise ValueError("y_true, y_pred_a, and y_pred_b must have identical lengths.")

    corr_a = (pa == yt)
    corr_b = (pb == yt)

    a = int(np.sum(corr_a & corr_b))
    b = int(np.sum(corr_a & (~corr_b)))
    c = int(np.sum((~corr_a) & corr_b))
    d = int(np.sum((~corr_a) & (~corr_b)))

    discordant = b + c
    contingency = {"a": a, "b": b, "c": c, "d": d}

    if discordant == 0:
        return {
            "statistic": 0.0,
            "p_value": 1.0,
            "method": "exact_binomial",
            "contingency_table": contingency,
            "discordant_pairs": 0,
            "significant": False,
        }

    if discordant < 25:
        # Exact binomial test
        k = min(b, c)
        if scipy_stats is not None and hasattr(scipy_stats, "binomtest"):
            res = scipy_stats.binomtest(k, n=discordant, p=0.5, alternative="two-sided")
            p_val = float(res.pvalue)
        else:
            p_val = _exact_binomial_pvalue(discordant, k)

        stat = float(abs(b - c))
        method = "exact_binomial"
    else:
        # Chi-square with continuity correction: (|b - c| - 1)^2 / (b + c)
        stat = float((abs(b - c) - 1.0) ** 2 / discordant)
        if scipy_stats is not None:
            p_val = float(scipy_stats.chi2.sf(stat, df=1))
        else:
            p_val = _chi2_sf_df1(stat)
        method = "chi2_continuity"

    return {
        "statistic": round(stat, 4),
        "p_value": round(p_val, 6),
        "method": method,
        "contingency_table": contingency,
        "discordant_pairs": discordant,
        "significant": p_val < 0.05,
    }
