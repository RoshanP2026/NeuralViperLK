"""Bandit static analysis baseline integration.

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

# Test ID to Weakness Class mapping
TEST_ID_TO_CWE: dict[str, str] = {
    # SQL Injection (CWE-89)
    "B608": "sqli",
    # OS Command Injection (CWE-78)
    "B602": "cmdi",
    "B603": "cmdi",
    "B604": "cmdi",
    "B605": "cmdi",
    "B606": "cmdi",
    "B607": "cmdi",
    # Hard-coded Credentials (CWE-798)
    "B105": "creds",
    "B106": "creds",
    "B107": "creds",
    # Unsafe Deserialisation (CWE-502)
    "B301": "deser",
    "B302": "deser",
    "B303": "deser",
    "B506": "deser",
}


def map_test_ids() -> dict[str, str]:
    """Return a copy of the Bandit test ID to CWE weakness class dictionary."""
    return dict(TEST_ID_TO_CWE)


def bandit_available() -> bool:
    """Check if the Bandit command-line executable is available on PATH."""
    return shutil.which("bandit") is not None


def _fallback_rule_check(code: str) -> dict[str, Any]:
    """Lightweight rule matching if Bandit CLI is not installed in the environment."""
    cwe_flags = {"sqli": False, "cmdi": False, "creds": False, "deser": False}
    issues: list[dict[str, Any]] = []

    lower_code = code.lower()

    # SQL Injection heuristic (matching B608 pattern)
    if ("select " in lower_code or "insert into" in lower_code) and (
        "f\"" in code
        or "f'" in code
        or " % " in code
        or ".format(" in code
        or " + " in code
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

    # Command injection heuristic (matching B602/B605)
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

    # Hard-coded credentials heuristic (matching B105-B107)
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

    # Unsafe deserialisation heuristic (matching B301/B506)
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

    is_flagged = any(cwe_flags.values())
    return {
        "flagged": is_flagged,
        "cwe_flags": cwe_flags,
        "issues": issues,
        "source": "heuristic_fallback",
    }


def bandit_flags(code: str, use_fallback_if_missing: bool = True) -> dict[str, Any]:
    """Run Bandit analysis on a Python code snippet and return structured flags.

    Args:
        code: Python source code snippet to analyze.
        use_fallback_if_missing: If True and Bandit is not installed, use
            rule-based fallback matching standard Bandit IDs.

    Returns:
        dict containing:
            - flagged: bool (True if at least one mapped CWE issue was triggered)
            - cwe_flags: dict[str, bool] (per-CWE flags for sqli, cmdi, creds, deser)
            - issues: list[dict] (details of detected Bandit issues)
            - raw_issues: list[dict] (all raw issues from Bandit)
    """
    if not code or not code.strip():
        return {
            "flagged": False,
            "cwe_flags": {c: False for c in ["sqli", "cmdi", "creds", "deser"]},
            "issues": [],
            "source": "empty",
        }

    if not bandit_available():
        if use_fallback_if_missing:
            return _fallback_rule_check(code)
        return {
            "flagged": False,
            "cwe_flags": {c: False for c in ["sqli", "cmdi", "creds", "deser"]},
            "issues": [],
            "source": "unavailable",
        }

    # Write code to a secure temporary Python file
    tmp_file = tempfile.NamedTemporaryFile("w", suffix=".py", delete=False, encoding="utf-8")
    try:
        tmp_file.write(code)
        tmp_file.flush()
        tmp_path = tmp_file.name
    finally:
        tmp_file.close()

    try:
        # Run Bandit with JSON output
        result = subprocess.run(
            ["bandit", "-f", "json", "-q", tmp_path],
            capture_output=True,
            text=True,
            timeout=30,
        )
        output_str = result.stdout.strip()
        if not output_str and result.stderr:
            output_str = result.stderr.strip()

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
        # On any execution or parse error, gracefully fall back if allowed
        if use_fallback_if_missing:
            return _fallback_rule_check(code)
        return {
            "flagged": False,
            "cwe_flags": {c: False for c in ["sqli", "cmdi", "creds", "deser"]},
            "issues": [],
            "source": "error",
        }
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
