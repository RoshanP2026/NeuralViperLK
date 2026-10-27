"""AST-based feature extraction for vulnerability detection in Python source code.

Extracts semantic and structural security features using Python's built-in `ast` module.
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

# Non-size features considered during explainability analysis
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
    r"\b(SELECT\s+.*?\s+FROM|INSERT\s+INTO|UPDATE\s+.*?\s+SET|DELETE\s+FROM|DROP\s+TABLE|WHERE\s+.*=|UNION\s+SELECT)\b",
    re.IGNORECASE,
)

WEB_REQUEST_ATTRIBUTES = {
    "args",
    "form",
    "GET",
    "POST",
    "json",
    "values",
    "data",
    "params",
    "headers",
    "cookies",
    "files",
}

SAFE_YAML_LOADERS = {"SafeLoader", "CSafeLoader", "BaseLoader"}


def _empty_features() -> dict[str, int | float]:
    """Return an all-zero feature dictionary."""
    return {name: 0 for name in FEATURE_NAMES}


class _SecurityFeatureVisitor(ast.NodeVisitor):
    """AST visitor traversing nodes to aggregate vulnerability indicators."""

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

        # 1. eval / exec
        if func_name in {"eval", "exec"}:
            self.features["eval_exec_calls"] += 1

        # 2. os.system / os.popen
        if full_call in {"os.system", "os.popen", "posix.system"} or (
            func_name in {"system", "popen"} and "os" in full_call
        ):
            self.features["os_system_calls"] += 1

        # 3. subprocess calls
        if (
            "subprocess" in full_call
            or func_name in {"Popen", "run", "call", "check_call", "check_output"}
        ):
            self.features["subprocess_calls"] += 1

        # 4. shell=True flag
        for kw in node.keywords:
            if kw.arg == "shell":
                if isinstance(kw.value, ast.Constant) and bool(kw.value.value) is True:
                    self.features["shell_true_flag"] += 1
                elif isinstance(kw.value, ast.Name) and kw.value.id in {"True", "1"}:
                    self.features["shell_true_flag"] += 1

        # 5. pickle / _pickle deserialisation
        if (
            "pickle" in full_call
            or full_call in {"pickle.loads", "pickle.load", "_pickle.loads", "cPickle.loads"}
            or (func_name in {"loads", "load"} and "pickle" in full_call)
        ):
            self.features["pickle_calls"] += 1

        # 6. unsafe yaml.load calls
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

        # 7. Database execution calls
        if func_name in {"execute", "executemany", "raw", "execute_query"}:
            self.features["db_execute_calls"] += 1
            # Check if arguments include dynamic string construction
            for arg in node.args:
                if self._is_dynamic_string_construction(arg):
                    self.features["dynamic_sql_construction"] += 1

        # 8. String format / join used dynamically
        if func_name == "format" and isinstance(func, ast.Attribute):
            # Check if applied to a string with SQL keywords
            if isinstance(func.value, ast.Constant) and isinstance(func.value.value, str):
                if SQL_KEYWORDS_PATTERN.search(func.value.value):
                    self.features["dynamic_sql_construction"] += 1

        # 9. input() calls
        if func_name in {"input", "raw_input"}:
            self.features["input_calls"] += 1

        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> Any:
        # Check variable assignment for hard-coded credentials
        for target in node.targets:
            target_name = ""
            if isinstance(target, ast.Name):
                target_name = target.id
            elif isinstance(target, ast.Attribute):
                target_name = target.attr

            if target_name and SECRET_NAME_PATTERN.search(target_name):
                # Is assigned a non-empty string literal?
                if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                    literal_val = node.value.value.strip()
                    # Exclude empty or common placeholders like "" or "placeholder" or "TODO"
                    if literal_val and not literal_val.startswith(("{", "<", "YOUR_")):
                        self.features["secret_var_assigned"] += 1

        # Check if right-hand side is dynamic SQL assignment
        if self._is_dynamic_string_construction(node.value):
            # If variable name contains sql or query or contains SQL keyword
            for target in node.targets:
                if isinstance(target, ast.Name) and any(
                    k in target.id.lower() for k in ["sql", "query", "stmt", "command"]
                ):
                    self.features["dynamic_sql_construction"] += 1

        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> Any:
        # Variable annotation assignment: token: str = "abc"
        if node.value and isinstance(node.target, ast.Name):
            target_name = node.target.id
            if SECRET_NAME_PATTERN.search(target_name):
                if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                    if node.value.value.strip():
                        self.features["secret_var_assigned"] += 1
        self.generic_visit(node)

    def visit_Constant(self, node: ast.Constant) -> Any:
        if isinstance(node.value, str):
            if SQL_KEYWORDS_PATTERN.search(node.value):
                self.features["sql_keywords"] += 1
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> Any:
        # Check web request attributes (e.g., request.args, request.form, request.GET)
        if node.attr in WEB_REQUEST_ATTRIBUTES:
            if isinstance(node.value, ast.Name) and node.value.id in {"request", "req"}:
                self.features["web_request_input"] += 1
        self.generic_visit(node)

    def _is_dynamic_string_construction(self, node: ast.AST | None) -> bool:
        """Detect whether an AST node builds a string dynamically."""
        if node is None:
            return False
        # f-strings (JoinedStr)
        if isinstance(node, ast.JoinedStr):
            return True
        # String concatenation (+) or % formatting
        if isinstance(node, ast.BinOp):
            if isinstance(node.op, (ast.Add, ast.Mod)):
                return True
        # Call to .format()
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr == "format":
                return True
        return False


def extract_features(code: str) -> dict[str, int | float]:
    """Extract security and structural features from Python source code.

    Args:
        code: The Python source code to analyze.

    Returns:
        Dictionary mapping feature names to numerical values.
        If code is syntactically invalid or empty, returns an all-zero feature vector.
    """
    if not code or not isinstance(code, str) or not code.strip():
        return _empty_features()

    try:
        tree = ast.parse(code)
    except (SyntaxError, ValueError, MemoryError, RecursionError):
        # Gracefully handle unparseable code with zeros
        return _empty_features()

    visitor = _SecurityFeatureVisitor(code)
    visitor.visit(tree)
    return visitor.features
