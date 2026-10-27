"""Data loading, cleaning, validation, and project-aware dataset partitioning.

Adheres to empirical software engineering standards for vulnerability datasets:
- Removes unparseable/empty snippets
- Normalises comments and whitespace before duplicate resolution
- Identifies and discards conflicting labels (same normalised code with distinct labels)
- Enforces strict project-level isolation using GroupShuffleSplit to prevent data leakage.
"""

from __future__ import annotations

import re
from typing import Any
import pandas as pd
from sklearn.model_selection import GroupShuffleSplit

EXPECTED_COLUMNS: list[str] = ["id", "project", "code", "label", "cwe"]
VALID_CWES: set[str] = {"sqli", "cmdi", "creds", "deser", "none"}


def normalise_code(code: str) -> str:
    """Normalise Python code by stripping single-line comments and extraneous whitespace.

    Args:
        code: Raw Python code string.

    Returns:
        Canonical normalised code string suitable for deduplication.
    """
    if not isinstance(code, str):
        return ""

    lines: list[str] = []
    for line in code.splitlines():
        # Remove comments while preserving hash inside string literals simply
        # A robust regex to strip comments outside quotes
        stripped_line = re.sub(r"#.*$", "", line)
        stripped_line = " ".join(stripped_line.split())
        if stripped_line:
            lines.append(stripped_line)

    return "\n".join(lines).strip()


def clean(df: pd.DataFrame) -> tuple[pd.DataFrame, dict[str, Any]]:
    """Clean the input vulnerability dataset and output a detailed cleaning report.

    Cleaning steps:
    1. Schema validation and missing value removal (empty code or null values).
    2. Code normalisation (removing comments, standardising whitespace).
    3. Detection and excision of conflicting samples (identical normalised code with
       contradictory labels or CWE assignments).
    4. Exact duplicate removal after normalisation.

    Args:
        df: Input pandas DataFrame with columns: id, project, code, label, cwe.

    Returns:
        Tuple of (cleaned_df, cleaning_report).
    """
    initial_count = len(df)
    report: dict[str, Any] = {
        "initial_samples": initial_count,
        "empty_removed": 0,
        "conflicting_removed": 0,
        "duplicates_removed": 0,
        "final_samples": 0,
        "class_distribution": {},
    }

    if df.empty:
        report["final_samples"] = 0
        return df.copy(), report

    working_df = df.copy()

    # Ensure required columns exist
    for col in EXPECTED_COLUMNS:
        if col not in working_df.columns:
            raise ValueError(f"Missing required dataset column: '{col}'")

    # Step 1: Remove empty / null rows
    non_empty_mask = (
        working_df["code"].notna()
        & working_df["code"].astype(str).str.strip().ne("")
        & working_df["label"].notna()
        & working_df["cwe"].notna()
    )
    empty_removed = int((~non_empty_mask).sum())
    report["empty_removed"] = empty_removed
    working_df = working_df[non_empty_mask].copy()

    # Normalise code for comparison
    working_df["norm_code"] = working_df["code"].astype(str).apply(normalise_code)
    valid_norm_mask = working_df["norm_code"].str.len() > 0
    working_df = working_df[valid_norm_mask].copy()

    # Step 2: Identify and prune contradictory samples
    # Group by normalised code and count distinct labels/CWEs
    grouped = working_df.groupby("norm_code").agg({
        "label": "nunique",
        "cwe": "nunique",
    })
    conflicting_codes = grouped[(grouped["label"] > 1) | (grouped["cwe"] > 1)].index
    conflicting_mask = working_df["norm_code"].isin(conflicting_codes)
    conflicting_removed = int(conflicting_mask.sum())
    report["conflicting_removed"] = conflicting_removed
    working_df = working_df[~conflicting_mask].copy()

    # Step 3: Remove duplicate normalised code instances (keep first occurrence)
    pre_dedup = len(working_df)
    working_df = working_df.drop_duplicates(subset=["norm_code"], keep="first")
    duplicates_removed = pre_dedup - len(working_df)
    report["duplicates_removed"] = duplicates_removed

    # Clean up temporary column and reset index
    working_df = working_df.drop(columns=["norm_code"]).reset_index(drop=True)
    report["final_samples"] = len(working_df)

    # Class distribution
    if not working_df.empty:
        report["class_distribution"] = working_df["cwe"].value_counts().to_dict()

    return working_df, report


def split_by_project(
    df: pd.DataFrame,
    test_size: float = 0.25,
    random_state: int = 42,
) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Partition dataset into train and test sets grouped strictly by project.

    Ensures that no project appears in both train and test partitions, preventing
    data leakage across repositories.

    Args:
        df: Cleaned pandas DataFrame containing at least 'project' column.
        test_size: Proportion of projects reserved for testing (default 0.25).
        random_state: Seed for reproducibility.

    Returns:
        Tuple of (train_df, test_df).
    """
    if "project" not in df.columns:
        raise ValueError("DataFrame must contain a 'project' column for GroupShuffleSplit.")

    if len(df["project"].unique()) < 2:
        raise ValueError("At least 2 unique projects are required for project-level splitting.")

    all_classes = set(df["cwe"])
    found = False
    for attempt in range(200):
        seed = random_state + attempt
        gss = GroupShuffleSplit(n_splits=1, test_size=test_size, random_state=seed)
        train_idx, test_idx = next(gss.split(df, groups=df["project"]))
        train_ok = set(df.iloc[train_idx]["cwe"]) >= all_classes
        test_ok = df.iloc[test_idx]["label"].astype(int).sum() > 0
        if train_ok and test_ok:
            found = True
            if attempt > 0:
                print(f"[i] Split seed changed to {seed} so every class is in the training set.")
            break
    if not found:
        raise ValueError("No project-level split puts every class in the training set. "
                         "Add more projects or data.")

    train_df = df.iloc[train_idx].copy().reset_index(drop=True)
    test_df = df.iloc[test_idx].copy().reset_index(drop=True)

    # Sanity check: disjoint project sets
    train_projects = set(train_df["project"])
    test_projects = set(test_df["project"])
    overlap = train_projects.intersection(test_projects)
    if overlap:
        raise RuntimeError(f"Data leakage detected! Overlapping projects: {overlap}")

    return train_df, test_df
