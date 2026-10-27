"""Source file scanner splitting Python files into functions and module-level code blocks.

Performs multi-granular static code evaluation:
1. Deconstructs AST into individual function declarations (def / async def) and module-level top statements.
2. Extracts feature vectors for each block.
3. Queries the trained Machine Learning vulnerability model for risk score and predicted CWE.
4. Executes the Bandit static baseline on the block to correlate rule flags.
5. Employs explainability to generate actionable rationale and remediation advice.
6. Returns sorted findings ordered descending by calculated risk.
"""

from __future__ import annotations

import ast
from typing import Any
import numpy as np

from src.vulndetect.bandit_baseline import bandit_flags
from src.vulndetect.explain import explain_prediction
from src.vulndetect.features import extract_features
from src.vulndetect.model import predict_cwe, predict_scores

BANDIT_FIXES = {
    "sqli": "Use parameterised queries (placeholders) instead of building the query text.",
    "cmdi": "Pass the command as a list, avoid shell=True, and validate all input.",
    "creds": "Move the secret to an environment variable or a secrets store.",
    "deser": "Do not load untrusted data with pickle or unsafe YAML. Use JSON or a safe loader.",
}


class CodeSegment:
    """Represents a bounded segment of Python code (function or module-level scope)."""

    def __init__(self, name: str, code: str, start_line: int, end_line: int, kind: str) -> None:
        self.name = name
        self.code = code
        self.start_line = start_line
        self.end_line = end_line
        self.kind = kind  # 'function', 'async_function', or 'module_level'


def split_python_file(code: str) -> list[CodeSegment]:
    """Split a Python file into individual function definitions and module-level blocks.

    Args:
        code: Full Python file content string.

    Returns:
        List of CodeSegment objects with accurate line tracking.
    """
    if not code or not code.strip():
        return []

    lines = code.splitlines()
    total_lines = len(lines)

    try:
        tree = ast.parse(code)
    except SyntaxError:
        # If code fails to parse, treat entire file as single module-level segment
        return [CodeSegment(name="<entire_file>", code=code, start_line=1, end_line=total_lines, kind="module_level")]

    segments: list[CodeSegment] = []
    function_line_mask = [False] * (total_lines + 1)

    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            s_line = node.lineno
            e_line = getattr(node, "end_lineno", s_line)
            # Mark lines occupied by functions
            for l_idx in range(s_line, min(e_line + 1, total_lines + 1)):
                function_line_mask[l_idx] = True

            kind = "async_function" if isinstance(node, ast.AsyncFunctionDef) else "function"
            fn_code = "\n".join(lines[s_line - 1 : e_line])
            segments.append(
                CodeSegment(
                    name=f"def {node.name}()",
                    code=fn_code,
                    start_line=s_line,
                    end_line=e_line,
                    kind=kind,
                )
            )

    # Gather module-level statements outside functions
    module_lines: list[tuple[int, str]] = []
    for idx, line in enumerate(lines, start=1):
        if not function_line_mask[idx]:
            module_lines.append((idx, line))

    if module_lines:
        first_line = module_lines[0][0]
        last_line = module_lines[-1][0]
        mod_code = "\n".join([line for _, line in module_lines]).strip()
        if mod_code:
            segments.append(
                CodeSegment(
                    name="<module_level>",
                    code=mod_code,
                    start_line=first_line,
                    end_line=last_line,
                    kind="module_level",
                )
            )

    # If no functions or module segments were formed, fall back to entire file
    if not segments:
        segments.append(
            CodeSegment(
                name="<module_level>",
                code=code,
                start_line=1,
                end_line=total_lines,
                kind="module_level",
            )
        )

    # Sort segments by start line
    segments.sort(key=lambda s: s.start_line)
    return segments


def scan_code(
    code: str,
    model_artifacts: dict[str, Any],
    file_name: str = "snippet.py",
    risk_threshold: float = 0.5,
    enable_bandit: bool = True,
) -> list[dict[str, Any]]:
    """Scan Python code, analyze each segment, and generate prioritized findings.

    Args:
        code: Python source code.
        model_artifacts: Model dictionary from train_and_tune or load_model.
        file_name: File identifier for reporting.
        risk_threshold: Decision threshold for ML vulnerability classification.
        enable_bandit: Whether to run Bandit static baseline.

    Returns:
        List of finding dictionaries, sorted in descending order of risk score.
    """
    segments = split_python_file(code)
    findings: list[dict[str, Any]] = []

    for seg in segments:
        feats = extract_features(seg.code)
        # Vectorize features
        f_names = model_artifacts.get("feature_names", list(feats.keys()))
        vec = np.array([float(feats.get(f, 0.0)) for f in f_names], dtype=float).reshape(1, -1)

        # ML Risk and CWE prediction
        scores = predict_scores(model_artifacts, vec)
        risk = float(scores[0]) if len(scores) > 0 else 0.0
        predicted_classes = predict_cwe(model_artifacts, vec, threshold=risk_threshold)
        pred_cwe = str(predicted_classes[0]) if len(predicted_classes) > 0 else "none"

        # Bandit baseline
        b_flag = 0
        b_issues = []
        if enable_bandit:
            b_res = bandit_flags(seg.code)
            b_flag = 1 if b_res.get("flagged", False) else 0
            b_issues = b_res.get("issues", [])

        # If Bandit fired but the ML score is below the threshold, report Bandit's finding.
        bandit_only = (b_flag == 1) and (risk < risk_threshold) and bool(b_issues)
        if bandit_only:
            pred_cwe = b_issues[0]["cwe"]
            rules = ", ".join(i["test_id"] for i in b_issues)
            explanation_data = {
                "explanation_text": f"Flagged by Bandit rule(s) {rules}: {b_issues[0]['issue_text']} "
                                    "The ML model scored this block below the threshold.",
                "fix_suggestion": BANDIT_FIXES.get(pred_cwe, "Review this code manually."),
                "top_features": [],
                "method": "bandit_rule",
            }
        else:
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
            "explanation_method": explanation_data["method"],
            "features": feats,
            "code_snippet": seg.code,
        })

    # Sort descending by risk score
    findings.sort(key=lambda item: item["risk_score"], reverse=True)
    return findings
