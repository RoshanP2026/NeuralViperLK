"""Command-line vulnerability scanner for Python source files.

Parses target Python file, scores functions and module-level code using the
explainable ML model, executes the Bandit static analyser baseline, prints
a structured findings report with plain-English rationales, and persists
the scan in SQLite.
"""

from __future__ import annotations

import argparse
import os
import sys

# Add project root to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from scripts.make_sample_data import generate_sample_dataset
from src.vulndetect.db import DEFAULT_DB_PATH, save_scan
from src.vulndetect.model import load_model, train_and_tune
from src.vulndetect.scanner import scan_code


def ensure_model_exists(model_path: str = "results/pilot_model.joblib") -> dict:
    """Load model if exists, or quickly train on sample dataset."""
    if os.path.exists(model_path):
        return load_model(model_path)

    print(f"[*] Model not found at '{model_path}'. Bootstrapping pilot model...")
    data_path = "data/sample_dataset.csv"
    if not os.path.exists(data_path):
        generate_sample_dataset(data_path)

    import pandas as pd
    from scripts.run_pilot import features_from_dataframe

    df = pd.read_csv(data_path)
    X = features_from_dataframe(df)
    y = df["cwe"].values
    groups = df["project"].values

    artifacts = train_and_tune(X, y, groups, param_grid={"n_estimators": [50], "max_depth": [6]})
    os.makedirs(os.path.dirname(model_path), exist_ok=True)
    from src.vulndetect.model import save_model

    save_model(artifacts, model_path)
    return artifacts


def main() -> None:
    parser = argparse.ArgumentParser(
        description="NeuralViperLK - Explainable Python Vulnerability Scanner",
    )
    parser.add_argument("file_path", type=str, help="Path to Python file to scan")
    parser.add_argument(
        "--threshold",
        type=float,
        default=0.5,
        help="Vulnerability risk score threshold (default: 0.5)",
    )
    parser.add_argument(
        "--no-bandit",
        action="store_true",
        help="Disable Bandit static analysis baseline execution",
    )
    parser.add_argument(
        "--model-path",
        type=str,
        default="results/pilot_model.joblib",
        help="Path to serialized ML model",
    )
    parser.add_argument(
        "--db-path",
        type=str,
        default=DEFAULT_DB_PATH,
        help="Path to SQLite database",
    )
    parser.add_argument(
        "--no-save",
        action="store_true",
        help="Do not save scan results to SQLite database",
    )

    args = parser.parse_args()

    if not os.path.exists(args.file_path):
        print(f"Error: Target file not found: {args.file_path}", file=sys.stderr)
        sys.exit(1)

    with open(args.file_path, "r", encoding="utf-8") as f:
        code_content = f.read()

    model_artifacts = ensure_model_exists(args.model_path)

    print("\n" + "=" * 78)
    print(f" NeuralViperLK Security Scanner: {args.file_path}")
    print(f" Model: RandomForest (v{model_artifacts.get('version', '1.0.0')}) | Threshold: {args.threshold}")
    print("=" * 78)

    findings = scan_code(
        code=code_content,
        model_artifacts=model_artifacts,
        file_name=args.file_path,
        risk_threshold=args.threshold,
        enable_bandit=not args.no_bandit,
    )

    if not findings:
        print("[+] No code blocks or functions identified in target file.")
        sys.exit(0)

    flagged_findings = [f for f in findings if f["is_flagged"]]
    print(f"\nDiscovered {len(findings)} block(s); {len(flagged_findings)} flagged as security concern(s).\n")

    for idx, f in enumerate(findings, start=1):
        status_tag = "[RISK DETECTED]" if f["is_flagged"] else "[PASS/SAFE]"
        print(f"--- Finding #{idx}: {f['block_name']} (Lines {f['line_number']}-{f['end_line']}) {status_tag} ---")
        print(f"  Weakness Class: {f['weakness_type'].upper()}")
        print(f"  ML Risk Score:  {f['risk_score']:.4f} (Threshold: {args.threshold})")
        print(f"  Bandit Flag:    {'TRIGGERED (1)' if f['bandit_flag'] else 'NOT TRIGGERED (0)'}")
        if f["bandit_issues"]:
            b_ids = ", ".join([f"{issue['test_id']} ({issue['test_name']})" for issue in f["bandit_issues"]])
            print(f"  Bandit Rule IDs: {b_ids}")
        print(f"  Explanation:    {f['explanation']}")
        print(f"  Mitigation:     {f['fix_suggestion']}")
        print()

    if not args.no_save:
        scan_id = save_scan(
            file_name=args.file_path,
            findings=findings,
            model_version=model_artifacts.get("version", "1.0.0"),
            db_path=args.db_path,
        )
        print(f"[+] Scan session persisted to SQLite (Scan ID: {scan_id}) at {args.db_path}")

    print("=" * 78 + "\n")


if __name__ == "__main__":
    main()
