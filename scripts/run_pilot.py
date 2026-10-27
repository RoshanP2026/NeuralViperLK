"""Pilot experiment runner evaluating ML, Bandit, and Hybrid strategies.

Workflow:
1. Loads and validates the pilot dataset (generates toy data if absent).
2. Cleans data via AST normalization and deduplication.
3. Partitions data via GroupShuffleSplit to enforce project-level isolation.
4. Trains and tunes multiclass Random Forest with GroupKFold cross-validation on train set only.
5. Runs evaluations on held-out test set for:
   - Machine Learning (Random Forest)
   - Bandit Static Baseline
   - Hybrid Agreement (flags only when ML AND Bandit agree)
   - Hybrid Union / Either (flags when ML OR Bandit fires)
6. Computes classification metrics and McNemar's paired significance tests.
7. Outputs results to results/pilot_metrics.csv and results/pilot_run.json.
"""

from __future__ import annotations

import json
import os
import sys
from typing import Any
import numpy as np
import pandas as pd

# Add project root to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from scripts.make_sample_data import generate_sample_dataset
from src.vulndetect.bandit_baseline import bandit_flags
from src.vulndetect.data import clean, split_by_project
from src.vulndetect.evaluate import mcnemar, metrics
from src.vulndetect.features import FEATURE_NAMES, extract_features
from src.vulndetect.model import predict_scores, save_model, train_and_tune


def features_from_dataframe(df: pd.DataFrame) -> np.ndarray:
    """Extract feature matrix for all code snippets in DataFrame."""
    rows = []
    for code in df["code"]:
        f_dict = extract_features(str(code))
        rows.append([float(f_dict.get(col, 0.0)) for col in FEATURE_NAMES])
    return np.array(rows, dtype=float)


def run_pilot(data_path: str = "data/sample_dataset.csv") -> dict[str, Any]:
    """Execute complete pilot benchmark and persist metrics."""
    os.makedirs("results", exist_ok=True)

    if not os.path.exists(data_path):
        print(f"[*] Dataset not found at {data_path}. Generating synthetic toy samples...")
        generate_sample_dataset(data_path)

    raw_df = pd.read_csv(data_path)
    print(f"[1/6] Raw dataset loaded: {len(raw_df)} samples across {raw_df['project'].nunique()} projects.")

    # 1. Clean
    cleaned_df, clean_report = clean(raw_df)
    print(
        f"[2/6] Cleaning complete: {len(cleaned_df)} samples retained "
        f"(removed {clean_report['empty_removed']} empty, {clean_report['duplicates_removed']} duplicates, "
        f"{clean_report['conflicting_removed']} conflicting)."
    )

    # 2. Split by project
    train_df, test_df = split_by_project(cleaned_df, test_size=0.25, random_state=42)
    print(
        f"[3/6] Project-aware split: Train={len(train_df)} ({train_df['project'].nunique()} projects), "
        f"Test={len(test_df)} ({test_df['project'].nunique()} projects)."
    )

    # 3. Extract Features
    X_train = features_from_dataframe(train_df)
    y_train = train_df["cwe"].values
    groups_train = train_df["project"].values

    X_test = features_from_dataframe(test_df)
    y_test_bin = test_df["label"].values.astype(int)

    # 4. Train Model
    print("[4/6] Training & tuning multiclass Random Forest with GroupKFold...")
    # Fast grid for pilot
    pilot_param_grid = {
        "n_estimators": [50, 100],
        "max_depth": [6, 10, None],
        "min_samples_split": [2, 4],
    }
    model_artifacts = train_and_tune(
        X_train,
        y_train,
        groups_train,
        param_grid=pilot_param_grid,
        n_splits=3,
    )
    model_save_path = "results/pilot_model.joblib"
    save_model(model_artifacts, model_save_path)
    print(f"      Best model saved to {model_save_path} with CV macro-F1: {model_artifacts['best_score']:.4f}")

    # 5. Evaluate Approaches on Test Set
    print("[5/6] Generating predictions on held-out test partition...")
    # A. ML predictions
    ml_scores = predict_scores(model_artifacts, X_test)
    ml_pred = (ml_scores >= 0.5).astype(int)

    # B. Bandit baseline
    bandit_preds_list: list[int] = []
    for code in test_df["code"]:
        b_res = bandit_flags(str(code))
        bandit_preds_list.append(1 if b_res.get("flagged", False) else 0)
    b_pred = np.array(bandit_preds_list, dtype=int)

    # C. Hybrid 1: Agreement (ML == 1 AND Bandit == 1)
    hybrid_agree = (ml_pred & b_pred).astype(int)

    # D. Hybrid 2: Either / Union (ML == 1 OR Bandit == 1)
    hybrid_either = (ml_pred | b_pred).astype(int)

    # 6. Compute Metrics
    metrics_ml = metrics(y_test_bin, ml_pred)
    metrics_bandit = metrics(y_test_bin, b_pred)
    metrics_hybrid_agree = metrics(y_test_bin, hybrid_agree)
    metrics_hybrid_either = metrics(y_test_bin, hybrid_either)

    # McNemar's Paired Significance Tests
    mcnemar_ml_vs_bandit = mcnemar(y_test_bin, ml_pred, b_pred)
    mcnemar_agree_vs_bandit = mcnemar(y_test_bin, hybrid_agree, b_pred)
    mcnemar_agree_vs_ml = mcnemar(y_test_bin, hybrid_agree, ml_pred)

    # Formulate tabular metrics
    methods_data = [
        {"Method": "Machine Learning (RF)", **metrics_ml},
        {"Method": "Bandit Baseline", **metrics_bandit},
        {"Method": "Hybrid (Agreement: ML & Bandit)", **metrics_hybrid_agree},
        {"Method": "Hybrid (Either: ML | Bandit)", **metrics_hybrid_either},
    ]
    metrics_df = pd.DataFrame(methods_data)
    metrics_df.to_csv("results/pilot_metrics.csv", index=False)

    pilot_summary: dict[str, Any] = {
        "dataset_meta": {
            "source": data_path,
            "raw_samples": len(raw_df),
            "cleaned_samples": len(cleaned_df),
            "train_samples": len(train_df),
            "test_samples": len(test_df),
            "train_projects": list(train_df["project"].unique()),
            "test_projects": list(test_df["project"].unique()),
        },
        "model_meta": {
            "algorithm": "RandomForestClassifier(multiclass)",
            "best_params": model_artifacts["best_params"],
            "cv_f1_macro": model_artifacts["best_score"],
            "top_features": list(model_artifacts["feature_importances"].items())[:5],
        },
        "evaluation_metrics": methods_data,
        "mcnemar_significance": {
            "ml_vs_bandit": mcnemar_ml_vs_bandit,
            "hybrid_agree_vs_bandit": mcnemar_agree_vs_bandit,
            "hybrid_agree_vs_ml": mcnemar_agree_vs_ml,
        },
    }

    with open("results/pilot_run.json", "w", encoding="utf-8") as f:
        json.dump(pilot_summary, f, indent=2)

    # 7. Print Console Summary Table
    print("\n" + "=" * 80)
    print(" PILOT EVALUATION BENCHMARK RESULTS (Held-Out Test Set)")
    print("=" * 80)
    col_fmt = "{:<32} | {:>4} | {:>4} | {:>4} | {:>4} | {:>6} | {:>6} | {:>6} | {:>6}"
    print(col_fmt.format("Method", "TP", "FP", "TN", "FN", "Prec", "Recall", "F1", "FPR"))
    print("-" * 80)
    for m in methods_data:
        print(
            col_fmt.format(
                m["Method"],
                m["tp"],
                m["fp"],
                m["tn"],
                m["fn"],
                f"{m['precision']:.3f}",
                f"{m['recall']:.3f}",
                f"{m['F1']:.3f}",
                f"{m['false_positive_rate']:.3f}",
            )
        )
    print("-" * 80)

    print("\nMcNemar's Significance Test Results:")
    print(
        f"  * ML vs Bandit: stat={mcnemar_ml_vs_bandit['statistic']}, "
        f"p-val={mcnemar_ml_vs_bandit['p_value']:.4e} ({mcnemar_ml_vs_bandit['method']}), "
        f"Significant={mcnemar_ml_vs_bandit['significant']}"
    )
    print(
        f"  * Hybrid (Agreement) vs Bandit: stat={mcnemar_agree_vs_bandit['statistic']}, "
        f"p-val={mcnemar_agree_vs_bandit['p_value']:.4e} ({mcnemar_agree_vs_bandit['method']}), "
        f"Significant={mcnemar_agree_vs_bandit['significant']}"
    )
    print(
        f"  * Hybrid (Agreement) vs ML: stat={mcnemar_agree_vs_ml['statistic']}, "
        f"p-val={mcnemar_agree_vs_ml['p_value']:.4e} ({mcnemar_agree_vs_ml['method']}), "
        f"Significant={mcnemar_agree_vs_ml['significant']}"
    )

    print("\n[+] Saved results to results/pilot_metrics.csv and results/pilot_run.json\n")
    return pilot_summary


if __name__ == "__main__":
    run_pilot()
