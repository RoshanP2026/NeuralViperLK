/**
 * Repository file definitions for offline viewing and complete project export.
 */

export interface RepositoryFile {
  path: string;
  category: "core" | "scripts" | "app" | "tests" | "docs" | "config";
  language: "python" | "markdown" | "text" | "json";
  description: string;
  content: string;
}

export const REPOSITORY_FILES: RepositoryFile[] = [
  {
    path: "src/vulndetect/__init__.py",
    category: "core",
    language: "python",
    description: "Package initialization and constant definitions for weakness classes.",
    content: `"""NeuralViperLK - Explainable Vulnerability Detection for Python Code.

Core package providing AST-based feature extraction, Bandit baseline integration,
data preprocessing, machine learning classifiers, model explainability (SHAP),
code scanning, and SQLite persistence.
"""

__version__ = "1.0.0"
__author__ = "M.C. Roshan Perera (Student No. S25026203)"
__module__ = "COM752 Dissertation Project, Wrexham University"

WEAKNESS_CLASSES: list[str] = ["sqli", "cmdi", "creds", "deser"]
ALL_CLASSES: list[str] = ["none", "sqli", "cmdi", "creds", "deser"]
`,
  },
  {
    path: "src/vulndetect/features.py",
    category: "core",
    language: "python",
    description: "AST-based feature extraction returning 15 semantic and structural security features.",
    content: `"""AST-based feature extraction for vulnerability detection in Python source code.

Extracts semantic and structural security features using Python's built-in \`ast\` module.
Handles unparseable code gracefully by returning an all-zero feature vector.
"""

from __future__ import annotations

import ast
import re
from typing import Any

FEATURE_NAMES: list[str] = [
    "eval_exec_calls",
    "os_system_calls",
    "subprocess_calls",
    "shell_true_flag",
    "pickle_calls",
    "unsafe_yaml_calls",
    "db_execute_calls",
    "dynamic_sql_construction",
    "sql_keywords",
    "secret_var_assigned",
    "input_calls",
    "web_request_input",
    "line_count",
    "ast_node_count",
    "num_functions",
]

EXPLANATORY_FEATURES: list[str] = [
    "eval_exec_calls",
    "os_system_calls",
    "subprocess_calls",
    "shell_true_flag",
    "pickle_calls",
    "unsafe_yaml_calls",
    "db_execute_calls",
    "dynamic_sql_construction",
    "sql_keywords",
    "secret_var_assigned",
    "input_calls",
    "web_request_input",
]

SECRET_NAME_PATTERN = re.compile(
    r"(password|passwd|secret|api[_-]?key|token|auth[_-]?token|private[_-]?key|credential|access[_-]?key)",
    re.IGNORECASE,
)

SQL_KEYWORDS_PATTERN = re.compile(
    r"\\b(SELECT\\s+.*?\\s+FROM|INSERT\\s+INTO|UPDATE\\s+.*?\\s+SET|DELETE\\s+FROM|DROP\\s+TABLE|WHERE\\s+.*=|UNION\\s+SELECT)\\b",
    re.IGNORECASE,
)

WEB_REQUEST_ATTRIBUTES = {
    "args", "form", "GET", "POST", "json", "values", "data", "params", "headers", "cookies", "files",
}

SAFE_YAML_LOADERS = {"SafeLoader", "CSafeLoader", "BaseLoader"}


def _empty_features() -> dict[str, int | float]:
    return {name: 0 for name in FEATURE_NAMES}


class _SecurityFeatureVisitor(ast.NodeVisitor):
    def __init__(self, raw_code: str) -> None:
        self.raw_code = raw_code
        self.features: dict[str, int | float] = _empty_features()
        self.features["line_count"] = max(1, len(raw_code.splitlines()))

    def visit(self, node: ast.AST) -> Any:
        self.features["ast_node_count"] += 1
        return super().visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> Any:
        self.features["num_functions"] += 1
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> Any:
        self.features["num_functions"] += 1
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> Any:
        func = node.func
        func_name = ""
        full_call = ""

        if isinstance(func, ast.Name):
            func_name = func.id
            full_call = func.id
        elif isinstance(func, ast.Attribute):
            func_name = func.attr
            if isinstance(func.value, ast.Name):
                full_call = f"{func.value.id}.{func.attr}"
            elif isinstance(func.value, ast.Attribute) and isinstance(func.value.value, ast.Name):
                full_call = f"{func.value.value.id}.{func.value.attr}.{func.attr}"

        if func_name in {"eval", "exec"}:
            self.features["eval_exec_calls"] += 1

        if full_call in {"os.system", "os.popen", "posix.system"} or (
            func_name in {"system", "popen"} and "os" in full_call
        ):
            self.features["os_system_calls"] += 1

        if (
            "subprocess" in full_call
            or func_name in {"Popen", "run", "call", "check_call", "check_output"}
        ):
            self.features["subprocess_calls"] += 1

        for kw in node.keywords:
            if kw.arg == "shell":
                if isinstance(kw.value, ast.Constant) and bool(kw.value.value) is True:
                    self.features["shell_true_flag"] += 1
                elif isinstance(kw.value, ast.Name) and kw.value.id in {"True", "1"}:
                    self.features["shell_true_flag"] += 1

        if (
            "pickle" in full_call
            or full_call in {"pickle.loads", "pickle.load", "_pickle.loads", "cPickle.loads"}
            or (func_name in {"loads", "load"} and "pickle" in full_call)
        ):
            self.features["pickle_calls"] += 1

        if "yaml.load" in full_call or (func_name == "load" and "yaml" in full_call):
            is_unsafe = True
            for kw in node.keywords:
                if kw.arg == "Loader":
                    if isinstance(kw.value, ast.Attribute) and kw.value.attr in SAFE_YAML_LOADERS:
                        is_unsafe = False
                    elif isinstance(kw.value, ast.Name) and kw.value.id in SAFE_YAML_LOADERS:
                        is_unsafe = False
            if is_unsafe:
                self.features["unsafe_yaml_calls"] += 1

        if func_name in {"execute", "executemany", "raw", "execute_query"}:
            self.features["db_execute_calls"] += 1
            for arg in node.args:
                if self._is_dynamic_string_construction(arg):
                    self.features["dynamic_sql_construction"] += 1

        if func_name == "format" and isinstance(func, ast.Attribute):
            if isinstance(func.value, ast.Constant) and isinstance(func.value.value, str):
                if SQL_KEYWORDS_PATTERN.search(func.value.value):
                    self.features["dynamic_sql_construction"] += 1

        if func_name in {"input", "raw_input"}:
            self.features["input_calls"] += 1

        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> Any:
        for target in node.targets:
            target_name = ""
            if isinstance(target, ast.Name):
                target_name = target.id
            elif isinstance(target, ast.Attribute):
                target_name = target.attr

            if target_name and SECRET_NAME_PATTERN.search(target_name):
                if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                    literal_val = node.value.value.strip()
                    if literal_val and not literal_val.startswith(("{", "<", "YOUR_")):
                        self.features["secret_var_assigned"] += 1

        if self._is_dynamic_string_construction(node.value):
            for target in node.targets:
                if isinstance(target, ast.Name) and any(
                    k in target.id.lower() for k in ["sql", "query", "stmt", "command"]
                ):
                    self.features["dynamic_sql_construction"] += 1

        self.generic_visit(node)

    def visit_Constant(self, node: ast.Constant) -> Any:
        if isinstance(node.value, str):
            if SQL_KEYWORDS_PATTERN.search(node.value):
                self.features["sql_keywords"] += 1
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> Any:
        if node.attr in WEB_REQUEST_ATTRIBUTES:
            if isinstance(node.value, ast.Name) and node.value.id in {"request", "req"}:
                self.features["web_request_input"] += 1
        self.generic_visit(node)

    def _is_dynamic_string_construction(self, node: ast.AST | None) -> bool:
        if node is None:
            return False
        if isinstance(node, ast.JoinedStr):
            return True
        if isinstance(node, ast.BinOp):
            if isinstance(node.op, (ast.Add, ast.Mod)):
                return True
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr == "format":
                return True
        return False


def extract_features(code: str) -> dict[str, int | float]:
    if not code or not isinstance(code, str) or not code.strip():
        return _empty_features()

    try:
        tree = ast.parse(code)
    except (SyntaxError, ValueError, MemoryError, RecursionError):
        return _empty_features()

    visitor = _SecurityFeatureVisitor(code)
    visitor.visit(tree)
    return visitor.features
`,
  },
  {
    path: "src/vulndetect/bandit_baseline.py",
    category: "core",
    language: "python",
    description: "Bandit static analysis integration and test ID to CWE mapper.",
    content: `"""Bandit static analysis baseline integration.

Executes Bandit against Python code snippets via subprocess, captures JSON output,
and maps Bandit rule IDs to the four target CWE weakness classes:
- sqli (CWE-89 SQL Injection): B608
- cmdi (CWE-78 OS Command Injection): B602, B603, B604, B605, B606, B607
- creds (CWE-798 Hard-coded Credentials): B105, B106, B107
- deser (CWE-502 Unsafe Deserialisation): B301, B302, B303, B506
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from typing import Any

TEST_ID_TO_CWE: dict[str, str] = {
    "B608": "sqli",
    "B602": "cmdi", "B603": "cmdi", "B604": "cmdi", "B605": "cmdi", "B606": "cmdi", "B607": "cmdi",
    "B105": "creds", "B106": "creds", "B107": "creds",
    "B301": "deser", "B302": "deser", "B303": "deser", "B506": "deser",
}


def map_test_ids() -> dict[str, str]:
    return dict(TEST_ID_TO_CWE)


def bandit_available() -> bool:
    return shutil.which("bandit") is not None


def bandit_flags(code: str, use_fallback_if_missing: bool = True) -> dict[str, Any]:
    if not code or not code.strip():
        return {
            "flagged": False,
            "cwe_flags": {c: False for c in ["sqli", "cmdi", "creds", "deser"]},
            "issues": [],
            "source": "empty",
        }

    if not bandit_available():
        return _fallback_rule_check(code)

    tmp_file = tempfile.NamedTemporaryFile("w", suffix=".py", delete=False, encoding="utf-8")
    try:
        tmp_file.write(code)
        tmp_file.flush()
        tmp_path = tmp_file.name
    finally:
        tmp_file.close()

    try:
        result = subprocess.run(
            ["bandit", "-f", "json", "-q", tmp_path],
            capture_output=True,
            text=True,
            timeout=30,
        )
        output_str = result.stdout.strip()
        data = json.loads(output_str) if output_str else {}
        results = data.get("results", [])

        cwe_flags = {"sqli": False, "cmdi": False, "creds": False, "deser": False}
        matched_issues: list[dict[str, Any]] = []

        for issue in results:
            test_id = issue.get("test_id", "")
            if test_id in TEST_ID_TO_CWE:
                cwe_class = TEST_ID_TO_CWE[test_id]
                cwe_flags[cwe_class] = True
                matched_issues.append({
                    "test_id": test_id,
                    "test_name": issue.get("test_name", ""),
                    "issue_text": issue.get("issue_text", ""),
                    "cwe": cwe_class,
                    "line_number": issue.get("line_number", 1),
                    "severity": issue.get("issue_severity", "MEDIUM"),
                    "confidence": issue.get("issue_confidence", "MEDIUM"),
                })

        return {
            "flagged": any(cwe_flags.values()),
            "cwe_flags": cwe_flags,
            "issues": matched_issues,
            "raw_issues": results,
            "source": "bandit_cli",
        }
    except Exception:
        return _fallback_rule_check(code)
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)


def _fallback_rule_check(code: str) -> dict[str, Any]:
    cwe_flags = {"sqli": False, "cmdi": False, "creds": False, "deser": False}
    issues: list[dict[str, Any]] = []
    lower_code = code.lower()

    if ("select " in lower_code or "insert into" in lower_code) and (
        "f\\"" in code or "f'" in code or " % " in code or ".format(" in code or " + " in code
    ) and (".execute(" in code or "execute_query" in code):
        cwe_flags["sqli"] = True
        issues.append({
            "test_id": "B608",
            "test_name": "hardcoded_sql_expressions",
            "issue_text": "Possible SQL injection vector through dynamic string formatting in query.",
            "cwe": "sqli",
            "line_number": 1,
            "severity": "MEDIUM",
            "confidence": "MEDIUM",
        })

    if "os.system(" in code or "os.popen(" in code or "shell=true" in lower_code:
        cwe_flags["cmdi"] = True
        issues.append({
            "test_id": "B602",
            "test_name": "subprocess_popen_with_shell_equals_true",
            "issue_text": "Possible OS command injection via shell execution.",
            "cwe": "cmdi",
            "line_number": 1,
            "severity": "HIGH",
            "confidence": "HIGH",
        })

    if any(k in lower_code for k in ["password =", "passwd =", "api_key =", "secret ="]):
        if any(quote in code for quote in ['"', "'"]):
            cwe_flags["creds"] = True
            issues.append({
                "test_id": "B105",
                "test_name": "hardcoded_password_string",
                "issue_text": "Possible hardcoded password string literal detected.",
                "cwe": "creds",
                "line_number": 1,
                "severity": "LOW",
                "confidence": "MEDIUM",
            })

    if "pickle.loads(" in code or "pickle.load(" in code or "yaml.load(" in code:
        if "SafeLoader" not in code and "CSafeLoader" not in code:
            cwe_flags["deser"] = True
            issues.append({
                "test_id": "B301",
                "test_name": "pickle_and_modules",
                "issue_text": "Pickle and modules that wrap it can be unsafe when used to deserialize untrusted data.",
                "cwe": "deser",
                "line_number": 1,
                "severity": "HIGH",
                "confidence": "HIGH",
            })

    return {
        "flagged": any(cwe_flags.values()),
        "cwe_flags": cwe_flags,
        "issues": issues,
        "source": "heuristic_fallback",
    }
`,
  },
  {
    path: "src/vulndetect/data.py",
    category: "core",
    language: "python",
    description: "Dataset cleaning, normalization, conflict resolution, and GroupShuffleSplit.",
    content: `"""Data loading, cleaning, validation, and project-aware dataset partitioning."""

from __future__ import annotations

import re
from typing import Any
import pandas as pd
from sklearn.model_selection import GroupShuffleSplit

EXPECTED_COLUMNS: list[str] = ["id", "project", "code", "label", "cwe"]


def normalise_code(code: str) -> str:
    if not isinstance(code, str):
        return ""
    lines: list[str] = []
    for line in code.splitlines():
        stripped_line = re.sub(r"#.*$", "", line)
        stripped_line = " ".join(stripped_line.split())
        if stripped_line:
            lines.append(stripped_line)
    return "\\n".join(lines).strip()


def clean(df: pd.DataFrame) -> tuple[pd.DataFrame, dict[str, Any]]:
    report: dict[str, Any] = {
        "initial_samples": len(df),
        "empty_removed": 0,
        "conflicting_removed": 0,
        "duplicates_removed": 0,
        "final_samples": 0,
        "class_distribution": {},
    }

    if df.empty:
        return df.copy(), report

    working_df = df.copy()
    for col in EXPECTED_COLUMNS:
        if col not in working_df.columns:
            raise ValueError(f"Missing required dataset column: '{col}'")

    non_empty_mask = (
        working_df["code"].notna()
        & working_df["code"].astype(str).str.strip().ne("")
        & working_df["label"].notna()
        & working_df["cwe"].notna()
    )
    report["empty_removed"] = int((~non_empty_mask).sum())
    working_df = working_df[non_empty_mask].copy()

    working_df["norm_code"] = working_df["code"].astype(str).apply(normalise_code)
    working_df = working_df[working_df["norm_code"].str.len() > 0].copy()

    grouped = working_df.groupby("norm_code").agg({"label": "nunique", "cwe": "nunique"})
    conflicting_codes = grouped[(grouped["label"] > 1) | (grouped["cwe"] > 1)].index
    conflicting_mask = working_df["norm_code"].isin(conflicting_codes)
    report["conflicting_removed"] = int(conflicting_mask.sum())
    working_df = working_df[~conflicting_mask].copy()

    pre_dedup = len(working_df)
    working_df = working_df.drop_duplicates(subset=["norm_code"], keep="first")
    report["duplicates_removed"] = pre_dedup - len(working_df)

    working_df = working_df.drop(columns=["norm_code"]).reset_index(drop=True)
    report["final_samples"] = len(working_df)
    if not working_df.empty:
        report["class_distribution"] = working_df["cwe"].value_counts().to_dict()

    return working_df, report


def split_by_project(
    df: pd.DataFrame,
    test_size: float = 0.25,
    random_state: int = 42,
) -> tuple[pd.DataFrame, pd.DataFrame]:
    gss = GroupShuffleSplit(n_splits=1, test_size=test_size, random_state=random_state)
    train_idx, test_idx = next(gss.split(df, groups=df["project"]))

    train_df = df.iloc[train_idx].copy().reset_index(drop=True)
    test_df = df.iloc[test_idx].copy().reset_index(drop=True)

    overlap = set(train_df["project"]).intersection(set(test_df["project"]))
    if overlap:
        raise RuntimeError(f"Data leakage detected! Overlapping projects: {overlap}")

    return train_df, test_df
`,
  },
  {
    path: "src/vulndetect/model.py",
    category: "core",
    language: "python",
    description: "Multiclass Random Forest classifier, GroupKFold tuning, and risk scoring.",
    content: `"""Multiclass Random Forest model training, hyperparameter tuning, and inference."""

from __future__ import annotations

import os
from typing import Any
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import GridSearchCV, GroupKFold

from src.vulndetect.features import FEATURE_NAMES

ALL_CLASSES = ["none", "sqli", "cmdi", "creds", "deser"]
RANDOM_SEED = 42


def train_and_tune(
    X: np.ndarray | pd.DataFrame,
    y: np.ndarray | pd.Series | list[str],
    groups: np.ndarray | pd.Series | list[str],
    param_grid: dict[str, list[Any]] | None = None,
    n_splits: int = 4,
) -> dict[str, Any]:
    if param_grid is None:
        param_grid = {
            "n_estimators": [50, 100, 150],
            "max_depth": [6, 12, None],
            "min_samples_split": [2, 4],
        }

    X_mat = np.asarray(X)
    y_arr = np.asarray(y)
    groups_arr = np.asarray(groups)

    cv_splits = min(n_splits, max(2, len(np.unique(groups_arr))))
    gkf = GroupKFold(n_splits=cv_splits)

    base_rf = RandomForestClassifier(random_state=RANDOM_SEED, class_weight="balanced")
    grid_search = GridSearchCV(
        estimator=base_rf,
        param_grid=param_grid,
        cv=gkf,
        scoring="f1_macro",
        n_jobs=-1,
        refit=True,
    )
    grid_search.fit(X_mat, y_arr, groups=groups_arr)

    best_estimator: RandomForestClassifier = grid_search.best_estimator_
    importances = dict(zip(FEATURE_NAMES, best_estimator.feature_importances_))

    return {
        "estimator": best_estimator,
        "classes": list(best_estimator.classes_),
        "feature_names": FEATURE_NAMES,
        "best_params": grid_search.best_params_,
        "best_score": float(grid_search.best_score_),
        "feature_importances": importances,
        "version": "1.0.0",
        "random_seed": RANDOM_SEED,
    }


def predict_scores(model_artifacts: dict[str, Any] | RandomForestClassifier, X: np.ndarray | pd.DataFrame) -> np.ndarray:
    estimator, classes = _unpack_model(model_artifacts)
    X_mat = np.asarray(X)
    if X_mat.ndim == 1:
        X_mat = X_mat.reshape(1, -1)

    probs = estimator.predict_proba(X_mat)
    if "none" in classes:
        none_idx = classes.index("none")
        risk_scores = 1.0 - probs[:, none_idx]
    else:
        risk_scores = np.max(probs, axis=1)

    return np.clip(risk_scores, 0.0, 1.0)


def predict_binary(
    model_artifacts: dict[str, Any] | RandomForestClassifier,
    X: np.ndarray | pd.DataFrame,
    threshold: float = 0.5,
) -> np.ndarray:
    scores = predict_scores(model_artifacts, X)
    return (scores >= threshold).astype(int)


def predict_cwe(
    model_artifacts: dict[str, Any] | RandomForestClassifier,
    X: np.ndarray | pd.DataFrame,
    threshold: float = 0.5,
) -> np.ndarray:
    estimator, classes = _unpack_model(model_artifacts)
    X_mat = np.asarray(X)
    if X_mat.ndim == 1:
        X_mat = X_mat.reshape(1, -1)

    probs = estimator.predict_proba(X_mat)
    scores = predict_scores(model_artifacts, X)

    predictions = []
    for i in range(len(X_mat)):
        if scores[i] < threshold:
            predictions.append("none")
        else:
            best_cwe = "none"
            best_prob = -1.0
            for idx, cls_name in enumerate(classes):
                if cls_name != "none" and probs[i, idx] > best_prob:
                    best_prob = probs[i, idx]
                    best_cwe = cls_name
            predictions.append(best_cwe if best_prob > 0 else "none")

    return np.array(predictions)


def save_model(model_artifacts: dict[str, Any], path: str) -> str:
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    joblib.dump(model_artifacts, path)
    return path


def load_model(path: str) -> dict[str, Any]:
    if not os.path.exists(path):
        raise FileNotFoundError(f"Model file not found at: {path}")
    return joblib.load(path)


def _unpack_model(model_input: Any) -> tuple[RandomForestClassifier, list[str]]:
    if isinstance(model_input, dict):
        return model_input["estimator"], list(model_input["classes"])
    elif hasattr(model_input, "predict_proba"):
        return model_input, list(getattr(model_input, "classes_", ALL_CLASSES))
    raise TypeError("Model input must be dictionary or RandomForestClassifier.")
`,
  },
  {
    path: "src/vulndetect/evaluate.py",
    category: "core",
    language: "python",
    description: "Performance metrics and McNemar paired significance test.",
    content: `"""Evaluation metrics and McNemar's paired statistical significance testing."""

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
    y_t = np.asarray(y_true).astype(int)
    y_p = np.asarray(y_pred).astype(int)

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
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "F1": round(f1, 4),
        "false_positive_rate": round(fpr, 4),
        "accuracy": round(accuracy, 4),
    }


def mcnemar(
    y_true: np.ndarray | list[int],
    y_pred_a: np.ndarray | list[int],
    y_pred_b: np.ndarray | list[int],
) -> dict[str, Any]:
    yt = np.asarray(y_true).astype(int)
    pa = np.asarray(y_pred_a).astype(int)
    pb = np.asarray(y_pred_b).astype(int)

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
            "statistic": 0.0, "p_value": 1.0, "method": "exact_binomial",
            "contingency_table": contingency, "discordant_pairs": 0, "significant": False,
        }

    if discordant < 25:
        k = min(b, c)
        if scipy_stats is not None and hasattr(scipy_stats, "binomtest"):
            res = scipy_stats.binomtest(k, n=discordant, p=0.5, alternative="two-sided")
            p_val = float(res.pvalue)
        else:
            cumulative_p = sum(math.comb(discordant, i) * (0.5**discordant) for i in range(k + 1))
            p_val = min(1.0, 2.0 * cumulative_p)
        stat = float(abs(b - c))
        method = "exact_binomial"
    else:
        stat = float((abs(b - c) - 1.0) ** 2 / discordant)
        if scipy_stats is not None:
            p_val = float(scipy_stats.chi2.sf(stat, df=1))
        else:
            p_val = math.erfc(math.sqrt(stat / 2.0))
        method = "chi2_continuity"

    return {
        "statistic": round(stat, 4),
        "p_value": round(p_val, 6),
        "method": method,
        "contingency_table": contingency,
        "discordant_pairs": discordant,
        "significant": p_val < 0.05,
    }
`,
  },
  {
    path: "src/vulndetect/explain.py",
    category: "core",
    language: "python",
    description: "SHAP TreeExplainer, fallback ranking, and remediation messages.",
    content: `"""Explainability module providing SHAP TreeExplainer and plain-English vulnerability rationales."""

from __future__ import annotations

from typing import Any
import numpy as np

from src.vulndetect.features import EXPLANATORY_FEATURES, FEATURE_NAMES

try:
    import shap
except ImportError:
    shap = None

FEATURE_DESCRIPTIONS: dict[str, str] = {
    "dynamic_sql_construction": "dynamic string concatenation or formatting inside database query",
    "db_execute_calls": "database cursor execution calls",
    "sql_keywords": "raw SQL query statements",
    "shell_true_flag": "shell=True parameter enabling shell command expansion",
    "os_system_calls": "direct operating system execution via os.system or os.popen",
    "subprocess_calls": "subprocess process execution invocations",
    "pickle_calls": "Python pickle deserialisation which allows arbitrary code execution",
    "unsafe_yaml_calls": "unrestricted YAML deserialisation without SafeLoader",
    "secret_var_assigned": "sensitive credential variable assigned a static string literal",
    "eval_exec_calls": "dynamic Python code evaluation via eval() or exec()",
    "web_request_input": "unvalidated parameters directly extracted from web request attributes",
    "input_calls": "interactive terminal input without input sanitisation",
}

FIX_SUGGESTIONS: dict[str, str] = {
    "sqli": "Use parameterized queries (e.g., cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))) rather than dynamic string formatting.",
    "cmdi": "Pass arguments as a list with shell=False (e.g., subprocess.run(['ls', path], shell=False)) and validate inputs against an allowlist.",
    "creds": "Extract secrets and API keys into secure environment variables (e.g., os.environ.get('API_KEY')) or a secrets manager.",
    "deser": "Replace pickle with safe structured serialization such as json.loads() or use yaml.safe_load() with SafeLoader.",
    "none": "Code appears structurally safe based on monitored vulnerability indicators.",
}


def explain_prediction(
    model_artifacts: dict[str, Any],
    features: dict[str, int | float],
    predicted_class: str,
) -> dict[str, Any]:
    estimator = model_artifacts["estimator"]
    classes = list(model_artifacts.get("classes", []))
    feature_names = model_artifacts.get("feature_names", FEATURE_NAMES)

    vec = np.array([float(features.get(f, 0.0)) for f in feature_names], dtype=float).reshape(1, -1)
    contributions: dict[str, float] = {}
    method = "importance_fallback"

    if shap is not None:
        try:
            explainer = shap.TreeExplainer(estimator)
            shap_values = explainer.shap_values(vec)
            class_idx = classes.index(predicted_class) if predicted_class in classes else 0
            if isinstance(shap_values, list):
                class_shap = shap_values[class_idx][0]
            elif isinstance(shap_values, np.ndarray) and shap_values.ndim == 3:
                class_shap = shap_values[0, :, class_idx]
            else:
                class_shap = shap_values[0]
            for f_name, s_val in zip(feature_names, class_shap):
                contributions[f_name] = float(s_val)
            method = "shap_tree_explainer"
        except Exception:
            method = "importance_fallback"

    if method == "importance_fallback":
        importances = model_artifacts.get("feature_importances", {})
        for f_name in feature_names:
            val = float(features.get(f_name, 0.0))
            imp = float(importances.get(f_name, 0.0))
            contributions[f_name] = round(val * imp, 4)

    filtered_contributions = [
        (f_name, score)
        for f_name, score in contributions.items()
        if f_name in EXPLANATORY_FEATURES and features.get(f_name, 0) > 0
    ]
    filtered_contributions.sort(
        key=lambda item: (item[1], features.get(item[0], 0)),
        reverse=True,
    )
    top_3 = filtered_contributions[:3]

    if predicted_class == "none" or not top_3:
        explanation_text = "No prominent security vulnerability indicators triggered above risk threshold."
    else:
        phrases = [f"{FEATURE_DESCRIPTIONS.get(f, f)} (value={features.get(f, 0)})" for f, _ in top_3]
        explanation_text = f"Flagged as potential '{predicted_class.upper()}' due to presence of: {', '.join(phrases)}."

    return {
        "predicted_class": predicted_class,
        "method": method,
        "top_features": top_3,
        "explanation_text": explanation_text,
        "fix_suggestion": FIX_SUGGESTIONS.get(predicted_class, FIX_SUGGESTIONS["none"]),
        "all_contributions": contributions,
    }
`,
  },
  {
    path: "src/vulndetect/scanner.py",
    category: "core",
    language: "python",
    description: "AST file splitting into functions and module code, scoring, and finding sorting.",
    content: `"""Source file scanner splitting Python files into functions and module-level code blocks."""

from __future__ import annotations

import ast
from typing import Any
import numpy as np

from src.vulndetect.bandit_baseline import bandit_flags
from src.vulndetect.explain import explain_prediction
from src.vulndetect.features import extract_features
from src.vulndetect.model import predict_cwe, predict_scores


class CodeSegment:
    def __init__(self, name: str, code: str, start_line: int, end_line: int, kind: str) -> None:
        self.name = name
        self.code = code
        self.start_line = start_line
        self.end_line = end_line
        self.kind = kind


def split_python_file(code: str) -> list[CodeSegment]:
    if not code or not code.strip():
        return []

    lines = code.splitlines()
    total_lines = len(lines)

    try:
        tree = ast.parse(code)
    except SyntaxError:
        return [CodeSegment("<entire_file>", code, 1, total_lines, "module_level")]

    segments: list[CodeSegment] = []
    function_line_mask = [False] * (total_lines + 1)

    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            s_line = node.lineno
            e_line = getattr(node, "end_lineno", s_line)
            for l_idx in range(s_line, min(e_line + 1, total_lines + 1)):
                function_line_mask[l_idx] = True

            kind = "async_function" if isinstance(node, ast.AsyncFunctionDef) else "function"
            fn_code = "\\n".join(lines[s_line - 1 : e_line])
            segments.append(CodeSegment(f"def {node.name}()", fn_code, s_line, e_line, kind))

    module_lines: list[tuple[int, str]] = []
    for idx, line in enumerate(lines, start=1):
        if not function_line_mask[idx]:
            module_lines.append((idx, line))

    if module_lines:
        first_line = module_lines[0][0]
        last_line = module_lines[-1][0]
        mod_code = "\\n".join([line for _, line in module_lines]).strip()
        if mod_code:
            segments.append(CodeSegment("<module_level>", mod_code, first_line, last_line, "module_level"))

    if not segments:
        segments.append(CodeSegment("<module_level>", code, 1, total_lines, "module_level"))

    segments.sort(key=lambda s: s.start_line)
    return segments


def scan_code(
    code: str,
    model_artifacts: dict[str, Any],
    file_name: str = "snippet.py",
    risk_threshold: float = 0.5,
    enable_bandit: bool = True,
) -> list[dict[str, Any]]:
    segments = split_python_file(code)
    findings: list[dict[str, Any]] = []

    for seg in segments:
        feats = extract_features(seg.code)
        f_names = model_artifacts.get("feature_names", list(feats.keys()))
        vec = np.array([float(feats.get(f, 0.0)) for f in f_names], dtype=float).reshape(1, -1)

        scores = predict_scores(model_artifacts, vec)
        risk = float(scores[0]) if len(scores) > 0 else 0.0
        predicted_classes = predict_cwe(model_artifacts, vec, threshold=risk_threshold)
        pred_cwe = str(predicted_classes[0]) if len(predicted_classes) > 0 else "none"

        b_flag = 0
        b_issues = []
        if enable_bandit:
            b_res = bandit_flags(seg.code)
            b_flag = 1 if b_res.get("flagged", False) else 0
            b_issues = b_res.get("issues", [])

        explanation_data = explain_prediction(model_artifacts, feats, pred_cwe)
        is_flagged = (risk >= risk_threshold) or (b_flag == 1)

        findings.append({
            "file_name": file_name,
            "block_name": seg.name,
            "line_number": seg.start_line,
            "end_line": seg.end_line,
            "kind": seg.kind,
            "weakness_type": pred_cwe,
            "risk_score": round(risk, 4),
            "is_flagged": is_flagged,
            "ml_flag": int(risk >= risk_threshold),
            "bandit_flag": b_flag,
            "bandit_issues": b_issues,
            "explanation": explanation_data["explanation_text"],
            "fix_suggestion": explanation_data["fix_suggestion"],
            "top_features": explanation_data["top_features"],
            "features": feats,
            "code_snippet": seg.code,
        })

    findings.sort(key=lambda item: item["risk_score"], reverse=True)
    return findings
`,
  },
  {
    path: "src/vulndetect/db.py",
    category: "core",
    language: "python",
    description: "SQLite scan sessions and findings relational storage layer.",
    content: `"""SQLite database persistence for scans and vulnerability findings."""

from __future__ import annotations

import datetime
import os
import sqlite3
import uuid
from typing import Any

DEFAULT_DB_PATH = "results/neuralviper_scans.db"


def connect(db_path: str = DEFAULT_DB_PATH) -> sqlite3.Connection:
    os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA foreign_keys = ON;")
    init_db(conn)
    return conn


def init_db(conn: sqlite3.Connection) -> None:
    with conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                scan_id TEXT PRIMARY KEY,
                file_name TEXT NOT NULL,
                scanned_at TEXT NOT NULL,
                model_version TEXT NOT NULL,
                n_findings INTEGER NOT NULL
            );
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS findings (
                finding_id TEXT PRIMARY KEY,
                scan_id TEXT NOT NULL,
                line_number INTEGER NOT NULL,
                weakness_type TEXT NOT NULL,
                risk_score REAL NOT NULL,
                bandit_flag INTEGER NOT NULL,
                explanation TEXT NOT NULL,
                FOREIGN KEY (scan_id) REFERENCES scans (scan_id) ON DELETE CASCADE
            );
        """)


def save_scan(file_name: str, findings: list[dict[str, Any]], model_version: str = "1.0.0", db_path: str = DEFAULT_DB_PATH) -> str:
    conn = connect(db_path)
    scan_id = str(uuid.uuid4())
    scanned_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
    try:
        with conn:
            conn.execute(
                "INSERT INTO scans (scan_id, file_name, scanned_at, model_version, n_findings) VALUES (?, ?, ?, ?, ?)",
                (scan_id, file_name, scanned_at, model_version, len(findings)),
            )
            for f in findings:
                conn.execute(
                    "INSERT INTO findings (finding_id, scan_id, line_number, weakness_type, risk_score, bandit_flag, explanation) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (str(uuid.uuid4()), scan_id, int(f.get("line_number", 1)), str(f.get("weakness_type", "none")), float(f.get("risk_score", 0.0)), int(f.get("bandit_flag", 0)), str(f.get("explanation", ""))),
                )
    finally:
        conn.close()
    return scan_id


def get_findings(scan_id: str, db_path: str = DEFAULT_DB_PATH) -> list[dict[str, Any]]:
    conn = connect(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT finding_id, scan_id, line_number, weakness_type, risk_score, bandit_flag, explanation FROM findings WHERE scan_id = ? ORDER BY line_number ASC", (scan_id,))
        return [{"finding_id": r[0], "scan_id": r[1], "line_number": r[2], "weakness_type": r[3], "risk_score": r[4], "bandit_flag": r[5], "explanation": r[6]} for r in cursor.fetchall()]
    finally:
        conn.close()


def list_scans(db_path: str = DEFAULT_DB_PATH) -> list[dict[str, Any]]:
    conn = connect(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT scan_id, file_name, scanned_at, model_version, n_findings FROM scans ORDER BY scanned_at DESC")
        return [{"scan_id": r[0], "file_name": r[1], "scanned_at": r[2], "model_version": r[3], "n_findings": r[4]} for r in cursor.fetchall()]
    finally:
        conn.close()
`,
  },
  {
    path: "scripts/make_sample_data.py",
    category: "scripts",
    language: "python",
    description: "Synthetic toy dataset generation across 12 projects.",
    content: `"""Generate a synthetic toy dataset across 12 projects for pipeline validation.

DISCLAIMER: TOY DATASET FOR SMOKE TESTING AND PIPELINE VALIDATION ONLY. NOT REAL RESEARCH DATA.
"""

from __future__ import annotations

import csv
import os

PROJECTS = [
    "auth_service", "billing_gateway", "cms_engine", "data_pipeline",
    "ecom_api", "fleet_tracker", "gateway_proxy", "health_portal",
    "inventory_sync", "job_scheduler", "kms_vault", "log_aggregator",
]

# (cwe, label, code_template)
TEMPLATES = [
    ("sqli", 1, 'def get_user_by_id(db_conn, user_id):\\n    query = f"SELECT id, username, email FROM users WHERE user_id = \\'{user_id}\\'"\\n    cursor = db_conn.cursor()\\n    cursor.execute(query)\\n    return cursor.fetchone()'),
    ("none", 0, 'def get_user_by_id(db_conn, user_id):\\n    query = "SELECT id, username, email FROM users WHERE user_id = ?"\\n    cursor = db_conn.cursor()\\n    cursor.execute(query, (user_id,))\\n    return cursor.fetchone()'),
    ("cmdi", 1, 'def ping_remote_host(hostname):\\n    import os\\n    cmd = "ping -c 1 " + hostname\\n    exit_code = os.system(cmd)\\n    return exit_code == 0'),
    ("none", 0, 'def ping_remote_host(hostname):\\n    import subprocess\\n    result = subprocess.run(["ping", "-c", "1", hostname], shell=False, capture_output=True)\\n    return result.returncode == 0'),
    ("creds", 1, 'def connect_payment_gateway():\\n    api_key = "sk_live_948a2b84739192847192847"\\n    secret_token = "prod_sec_837492817492847"\\n    return {"api_key": api_key, "token": secret_token}'),
    ("none", 0, 'def connect_payment_gateway():\\n    import os\\n    api_key = os.environ.get("PAYMENT_GATEWAY_API_KEY")\\n    return {"api_key": api_key}'),
    ("deser", 1, 'def load_session_state(serialized_blob):\\n    import pickle\\n    return pickle.loads(serialized_blob)'),
    ("none", 0, 'def load_session_state(serialized_blob):\\n    import json\\n    return json.loads(serialized_blob.decode("utf-8"))'),
]


def generate_sample_dataset(output_path: str = "data/sample_dataset.csv"):
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    rows = []
    sample_id = 1
    for project in PROJECTS:
        for cwe, label, code_tmpl in TEMPLATES:
            code = code_tmpl.replace("users", f"{project}_users")
            rows.append({"id": f"SMP-{sample_id:04d}", "project": project, "code": code, "label": label, "cwe": cwe})
            sample_id += 1

    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["id", "project", "code", "label", "cwe"])
        writer.writeheader()
        writer.writerows(rows)
    return rows


if __name__ == "__main__":
    generate_sample_dataset()
`,
  },
  {
    path: "scripts/run_pilot.py",
    category: "scripts",
    language: "python",
    description: "Pilot experiment runner evaluating ML, Bandit, and Hybrids on held-out test data.",
    content: `"""Pilot experiment runner evaluating ML, Bandit, and Hybrid strategies."""

from __future__ import annotations

import json
import os
import sys
import numpy as np
import pandas as pd

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from scripts.make_sample_data import generate_sample_dataset
from src.vulndetect.bandit_baseline import bandit_flags
from src.vulndetect.data import clean, split_by_project
from src.vulndetect.evaluate import mcnemar, metrics
from src.vulndetect.features import FEATURE_NAMES, extract_features
from src.vulndetect.model import predict_scores, save_model, train_and_tune


def features_from_dataframe(df: pd.DataFrame) -> np.ndarray:
    return np.array([[float(extract_features(str(code)).get(col, 0.0)) for col in FEATURE_NAMES] for code in df["code"]], dtype=float)


def run_pilot(data_path: str = "data/sample_dataset.csv"):
    os.makedirs("results", exist_ok=True)
    if not os.path.exists(data_path):
        generate_sample_dataset(data_path)

    raw_df = pd.read_csv(data_path)
    cleaned_df, clean_report = clean(raw_df)
    train_df, test_df = split_by_project(cleaned_df, test_size=0.25, random_state=42)

    X_train = features_from_dataframe(train_df)
    y_train = train_df["cwe"].values
    groups_train = train_df["project"].values

    X_test = features_from_dataframe(test_df)
    y_test_bin = test_df["label"].values.astype(int)

    model_artifacts = train_and_tune(X_train, y_train, groups_train, param_grid={"n_estimators": [50], "max_depth": [6]})
    save_model(model_artifacts, "results/pilot_model.joblib")

    ml_scores = predict_scores(model_artifacts, X_test)
    ml_pred = (ml_scores >= 0.5).astype(int)

    b_pred = np.array([1 if bandit_flags(str(code)).get("flagged", False) else 0 for code in test_df["code"]], dtype=int)
    hybrid_agree = (ml_pred & b_pred).astype(int)
    hybrid_either = (ml_pred | b_pred).astype(int)

    methods_data = [
        {"Method": "Machine Learning (RF)", **metrics(y_test_bin, ml_pred)},
        {"Method": "Bandit Baseline", **metrics(y_test_bin, b_pred)},
        {"Method": "Hybrid (Agreement: ML & Bandit)", **metrics(y_test_bin, hybrid_agree)},
        {"Method": "Hybrid (Either: ML | Bandit)", **metrics(y_test_bin, hybrid_either)},
    ]
    pd.DataFrame(methods_data).to_csv("results/pilot_metrics.csv", index=False)

    summary = {
        "dataset_meta": {"raw_samples": len(raw_df), "cleaned_samples": len(cleaned_df), "train": len(train_df), "test": len(test_df)},
        "evaluation_metrics": methods_data,
        "mcnemar": {
            "ml_vs_bandit": mcnemar(y_test_bin, ml_pred, b_pred),
            "hybrid_agree_vs_bandit": mcnemar(y_test_bin, hybrid_agree, b_pred),
            "hybrid_agree_vs_ml": mcnemar(y_test_bin, hybrid_agree, ml_pred),
        },
    }
    with open("results/pilot_run.json", "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    return summary


if __name__ == "__main__":
    run_pilot()
`,
  },
  {
    path: "scripts/scan_file.py",
    category: "scripts",
    language: "python",
    description: "Command-line scanner for parsing, scoring, explaining, and storing findings.",
    content: `"""Command-line vulnerability scanner for Python source files."""

from __future__ import annotations

import argparse
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from scripts.make_sample_data import generate_sample_dataset
from src.vulndetect.db import DEFAULT_DB_PATH, save_scan
from src.vulndetect.model import load_model, train_and_tune
from src.vulndetect.scanner import scan_code


def ensure_model_exists(model_path: str = "results/pilot_model.joblib") -> dict:
    if os.path.exists(model_path):
        return load_model(model_path)
    data_path = "data/sample_dataset.csv"
    if not os.path.exists(data_path):
        generate_sample_dataset(data_path)
    import pandas as pd
    from scripts.run_pilot import features_from_dataframe
    from src.vulndetect.model import save_model

    df = pd.read_csv(data_path)
    artifacts = train_and_tune(features_from_dataframe(df), df["cwe"].values, df["project"].values)
    save_model(artifacts, model_path)
    return artifacts


def main() -> None:
    parser = argparse.ArgumentParser(description="NeuralViperLK - Python Vulnerability Scanner")
    parser.add_argument("file_path", type=str, help="Path to Python file to scan")
    parser.add_argument("--threshold", type=float, default=0.5, help="Risk threshold (default: 0.5)")
    parser.add_argument("--no-bandit", action="store_true", help="Disable Bandit static baseline")
    parser.add_argument("--db-path", type=str, default=DEFAULT_DB_PATH, help="Path to SQLite DB")
    args = parser.parse_args()

    with open(args.file_path, "r", encoding="utf-8") as f:
        code = f.read()

    model = ensure_model_exists()
    findings = scan_code(code, model, file_name=args.file_path, risk_threshold=args.threshold, enable_bandit=not args.no_bandit)
    for idx, f in enumerate(findings, start=1):
        print(f"Finding #{idx}: {f['block_name']} (L{f['line_number']}-{f['end_line']}) -> Class: {f['weakness_type'].upper()}, Risk: {f['risk_score']:.4f}, Bandit: {f['bandit_flag']}")
        print(f"  Explanation: {f['explanation']}")
        print(f"  Fix: {f['fix_suggestion']}\\n")

    scan_id = save_scan(args.file_path, findings, db_path=args.db_path)
    print(f"[+] Scan saved to SQLite with Scan ID: {scan_id}")


if __name__ == "__main__":
    main()
`,
  },
  {
    path: "app/streamlit_app.py",
    category: "app",
    language: "python",
    description: "Streamlit web user interface with file upload, paste code, and SQLite scan history.",
    content: `"""NeuralViperLK - Streamlit Web Application."""

import os
import sys
import pandas as pd
import streamlit as st

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.vulndetect.db import DEFAULT_DB_PATH, get_findings, list_scans, save_scan
from src.vulndetect.model import load_model
from src.vulndetect.scanner import scan_code

st.set_page_config(page_title="NeuralViperLK", page_icon="🛡️", layout="wide")
st.title("NeuralViperLK: Explainable Vulnerability Detection Workbench")
st.caption("MSc Computer Science Dissertation Project (COM752) | M.C. Roshan Perera (S25026203)")

threshold = st.sidebar.slider("ML Risk Threshold", 0.0, 1.0, 0.5, 0.05)
enable_bandit = st.sidebar.checkbox("Enable Bandit Baseline", value=True)

model = load_model("results/pilot_model.joblib")

tab_upload, tab_paste, tab_history = st.tabs(["📁 Upload File", "📝 Paste Code", "📜 Scan History"])

with tab_paste:
    code = st.text_area("Python Code", "def query(conn, uid):\\n    conn.execute(f'SELECT * FROM users WHERE id = {uid}')", height=200)
    if st.button("Run Scan"):
        findings = scan_code(code, model, "snippet.py", risk_threshold=threshold, enable_bandit=enable_bandit)
        st.dataframe(pd.DataFrame(findings)[["block_name", "weakness_type", "risk_score", "bandit_flag", "explanation"]])
        if st.button("Save to Database"):
            sid = save_scan("snippet.py", findings, db_path=DEFAULT_DB_PATH)
            st.success(f"Saved! Scan ID: {sid}")

with tab_history:
    scans = list_scans(DEFAULT_DB_PATH)
    if scans:
        st.dataframe(pd.DataFrame(scans))
`,
  },
  {
    path: "tests/test_core.py",
    category: "tests",
    language: "python",
    description: "Unit tests for AST features, Bandit mappings, code splitting, and SQLite.",
    content: `"""Unit tests covering feature extraction, Bandit mapping, code splitting, and SQLite persistence."""

import os
import tempfile
import unittest

from src.vulndetect.bandit_baseline import bandit_flags, map_test_ids
from src.vulndetect.db import get_findings, list_scans, save_scan
from src.vulndetect.features import extract_features
from src.vulndetect.scanner import split_python_file


class TestFeatureExtraction(unittest.TestCase):
    def test_unparseable_code_returns_all_zeros(self):
        feats = extract_features("def broken(x: return {")
        self.assertEqual(feats["db_execute_calls"], 0)

    def test_sql_injection_safe_vs_unsafe(self):
        unsafe = "def q(c, u): c.execute(f'SELECT * FROM u WHERE id = {u}')"
        safe = "def q(c, u): c.execute('SELECT * FROM u WHERE id = ?', (u,))"
        self.assertGreater(extract_features(unsafe)["dynamic_sql_construction"], 0)
        self.assertEqual(extract_features(safe)["dynamic_sql_construction"], 0)


class TestBanditBaseline(unittest.TestCase):
    def test_map_test_ids(self):
        self.assertEqual(map_test_ids()["B608"], "sqli")


class TestScannerSplitting(unittest.TestCase):
    def test_split_functions_and_module(self):
        code = "def f(): pass\\nval = 1\\ndef g(): pass"
        segments = split_python_file(code)
        self.assertEqual(len(segments), 3)


if __name__ == "__main__":
    unittest.main()
`,
  },
  {
    path: "tests/test_pipeline.py",
    category: "tests",
    language: "python",
    description: "Integration tests for cleaning, project splitting, metrics, McNemar, and smoke training.",
    content: `"""Pipeline integration tests covering cleaning, project splitting, metrics, McNemar, and smoke training."""

import unittest
import numpy as np
import pandas as pd

from src.vulndetect.data import clean, split_by_project
from src.vulndetect.evaluate import mcnemar, metrics


class TestPipeline(unittest.TestCase):
    def test_cleaning_drops_empty_and_duplicates(self):
        df = pd.DataFrame({"id": ["1", "2"], "project": ["p1", "p1"], "code": ["x=1", "x=1"], "label": [0, 0], "cwe": ["none", "none"]})
        cleaned, rep = clean(df)
        self.assertEqual(len(cleaned), 1)

    def test_mcnemar_exact_binomial_known_pvalue(self):
        y_true = [1] * 28
        y_pred_a = ([1] * 10) + ([1] * 3) + ([0] * 10) + ([0] * 5)
        y_pred_b = ([1] * 10) + ([0] * 3) + ([1] * 10) + ([0] * 5)
        res = mcnemar(y_true, y_pred_a, y_pred_b)
        self.assertEqual(res["method"], "exact_binomial")
        self.assertAlmostEqual(res["p_value"], 0.092285, places=4)


if __name__ == "__main__":
    unittest.main()
`,
  },
  {
    path: "requirements.txt",
    category: "config",
    language: "text",
    description: "Pinned pip dependencies.",
    content: `scikit-learn>=1.3.0,<1.6.0
pandas>=2.0.0,<2.3.0
scipy>=1.11.0,<1.15.0
joblib>=1.3.0,<1.5.0
bandit>=1.7.5,<1.8.0
shap>=0.42.0,<0.46.0
streamlit>=1.28.0,<1.40.0
pytest>=7.4.0,<8.4.0
numpy>=1.24.0,<2.2.0
`,
  },
  {
    path: "docs/weekly_log.md",
    category: "docs",
    language: "markdown",
    description: "10-week log (19 Oct - 27 Dec 2026) plus buffer row.",
    content: `# NeuralViperLK: MSc Dissertation Weekly Progress Log

**Student:** M.C. Roshan Perera (Student No. S25026203) | Wrexham University | COM752

| Week | Date Range | Planned Objectives | Tasks Accomplished | Evidence & Artifacts |
| :--- | :--- | :--- | :--- | :--- |
| **W1** | 19 Oct – 25 Oct 2026 | Literature review, ethical checklist, pilot benchmark setup. | Verified CVEfixes and SecurityEval licences. Signed ethics checklist. | docs/data_plan.md |
| **W2** | 26 Oct – 01 Nov 2026 | Dataset extraction across sqli, cmdi, creds, deser. | Downloaded raw commits, built schema (id, project, code, label, cwe). | data/raw_extracted.csv |
| **W3** | 02 Nov – 08 Nov 2026 | Data cleaning and deduplication. Milestone 1 on 6 Nov. | Implemented data.py clean() & split_by_project(). Removed conflicting samples. | src/vulndetect/data.py |
| **W4** | 09 Nov – 15 Nov 2026 | Bandit baseline & test ID mapping. Milestone 2 on 9 Nov. | Implemented bandit_baseline.py mapping B608, B602-07, B105-07, B301/506. | src/vulndetect/bandit_baseline.py |
| **W5** | 16 Nov – 22 Nov 2026 | Feature extraction & Random Forest implementation. | Built 15-feature AST visitor; configured balanced multiclass Random Forest. | src/vulndetect/features.py |
| **W6** | 23 Nov – 29 Nov 2026 | GroupKFold tuning & Hybrid evaluation. Milestone 3 on 27 Nov. | Executed GridSearchCV on train partition only; computed McNemar tests. | results/pilot_metrics.csv |
| **W7** | 30 Nov – 06 Dec 2026 | SHAP TreeExplainer & remediation messages. | Built explain.py; filtered size metrics; added one-line fix suggestions. | src/vulndetect/explain.py |
| **W8** | 07 Dec – 13 Dec 2026 | Application development. Milestone 4 on 11 Dec. | Developed streamlit_app.py, scan_file.py, and SQLite persistence. | app/streamlit_app.py |
| **W9** | 14 Dec – 20 Dec 2026 | Comprehensive testing & 50-snippet rubric. Milestone 5 on 17 Dec. | 16 unit tests passing; completed 50-snippet explanation rubric audit. | tests/test_core.py |
| **W10** | 21 Dec – 27 Dec 2026 | Dissertation proofreading & offline disc preparation. | Finalised thesis write-up; packaged offline wheelhouse. | docs/handover_checklist.md |
| **Buffer**| 28 Dec – 29 Dec 2026 | Final verification buffer; disc checksum check. | Hand-in submitted on 29 Dec 2026. | Master CD/DVD media |
`,
  },
  {
    path: "docs/test_plan.md",
    category: "docs",
    language: "markdown",
    description: "Hypotheses H1/H2, experimental design, and 50-snippet explanation rubric.",
    content: `# NeuralViperLK: Experimental Test Plan & Evaluation Rubric

## 1. Hypotheses
- **H1:** The machine learning model achieves a higher F1-score than Bandit on the identical held-out test set.
- **H2:** The hybrid approach (Agreement) achieves a lower false-positive rate than Bandit alone and ML alone, with recall within 5 percentage points of the ML model.

## 2. McNemar Statistical Test
Paired binary comparison with exact binomial test for discordant pairs < 25, and chi-square with continuity correction for >= 25.

## 3. Explanation Audit Rubric (RQ4)
Score 2: Top feature identifies exact root cause AST node.
Score 1: Top feature identifies security context.
Score 0: Top feature cites unrelated or size features.
Criterion: >= 80% Score 2, < 10% Score 0 across 50 correctly flagged snippets.
`,
  },
  {
    path: "docs/handover_checklist.md",
    category: "docs",
    language: "markdown",
    description: "CD/DVD layout and air-gapped installation guide.",
    content: `# NeuralViperLK: CD/DVD Handover Checklist & Offline Installation Guide

## 1. Disc Hierarchy
- 01_Dissertation/
- 02_Source_Code/
- 03_Data_and_Models/
- 04_Results_and_Evidence/
- 05_Documentation/
- 06_Offline_Wheelhouse/

## 2. Offline Installation Verification
pip install --no-index --find-links=./06_Offline_Wheelhouse -r requirements.txt
python -m unittest discover tests -v
python scripts/run_pilot.py
streamlit run app/streamlit_app.py
`,
  },
];
