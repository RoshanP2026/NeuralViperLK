"""Explainability module providing SHAP TreeExplainer and plain-English vulnerability rationales.

Computes feature contributions for the predicted vulnerability class:
- Primary: SHAP TreeExplainer for tree-based ensemble models.
- Fallback: (feature_value * feature_importance) product ranking if SHAP is absent.
- Filters out non-semantic size features (e.g. line_count, ast_node_count).
- Generates a concise developer-readable explanation from the top 3 contributing features.
- Appends actionable one-line mitigation guidance tailored to the detected CWE class.
"""

from __future__ import annotations

from typing import Any
import numpy as np

from src.vulndetect.features import EXPLANATORY_FEATURES, FEATURE_NAMES

try:
    import shap
except ImportError:
    shap = None

# Plain-English descriptions for security features
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

# One-line fix recommendations per weakness class
FIX_SUGGESTIONS: dict[str, str] = {
    "sqli": (
        "Use parameterized queries (e.g., cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))) "
        "rather than dynamic string formatting."
    ),
    "cmdi": (
        "Pass arguments as a list with shell=False (e.g., subprocess.run(['ls', path], shell=False)) "
        "and validate inputs against an allowlist."
    ),
    "creds": (
        "Extract secrets and API keys into secure environment variables (e.g., os.environ.get('API_KEY')) "
        "or a secrets manager."
    ),
    "deser": (
        "Replace pickle with safe structured serialization such as json.loads() or use yaml.safe_load() "
        "with SafeLoader."
    ),
    "none": "Code appears structurally safe based on monitored vulnerability indicators.",
}


def explain_prediction(
    model_artifacts: dict[str, Any],
    features: dict[str, int | float],
    predicted_class: str,
) -> dict[str, Any]:
    """Generate local explanation and mitigation advice for a single prediction.

    Args:
        model_artifacts: Model dictionary containing 'estimator', 'classes', 'feature_names',
            and 'feature_importances'.
        features: Dictionary of extracted features for the sample.
        predicted_class: Predicted CWE class ('sqli', 'cmdi', 'creds', 'deser', 'none').

    Returns:
        Dictionary containing:
            - top_features: list of (feature_name, contribution_score)
            - explanation_text: developer-readable summary of top factors
            - fix_suggestion: actionable one-line guidance
            - method: 'shap_tree_explainer' or 'importance_fallback'
            - all_contributions: dict of feature contributions
    """
    estimator = model_artifacts["estimator"]
    classes = list(model_artifacts.get("classes", []))
    feature_names = model_artifacts.get("feature_names", FEATURE_NAMES)

    # Convert feature dictionary to 1D vector matching training order
    vec = np.array([float(features.get(f, 0.0)) for f in feature_names], dtype=float)
    vec_2d = vec.reshape(1, -1)

    contributions: dict[str, float] = {}
    method = "importance_fallback"

    # Attempt SHAP TreeExplainer
    if shap is not None:
        try:
            explainer = shap.TreeExplainer(estimator)
            shap_values = explainer.shap_values(vec_2d)

            # Determine target class index
            class_idx = classes.index(predicted_class) if predicted_class in classes else 0

            # TreeExplainer returns either list of arrays (one per class) or 3D array (n_samples, n_features, n_classes)
            if isinstance(shap_values, list):
                class_shap = shap_values[class_idx][0]
            elif isinstance(shap_values, np.ndarray) and shap_values.ndim == 3:
                class_shap = shap_values[0, :, class_idx]
            elif isinstance(shap_values, np.ndarray) and shap_values.ndim == 2:
                class_shap = shap_values[0]
            else:
                class_shap = None

            if class_shap is not None:
                for f_name, s_val in zip(feature_names, class_shap):
                    contributions[f_name] = float(s_val)
                method = "shap_tree_explainer"
        except Exception:
            method = "importance_fallback"

    # Fallback to feature_value * feature_importance
    if method == "importance_fallback":
        importances = model_artifacts.get("feature_importances", {})
        for f_name in feature_names:
            val = float(features.get(f_name, 0.0))
            imp = float(importances.get(f_name, 0.0))
            contributions[f_name] = round(val * imp, 4)

    # Filter out size features and focus on semantic explanatory indicators
    filtered_contributions = [
        (f_name, score)
        for f_name, score in contributions.items()
        if f_name in EXPLANATORY_FEATURES and features.get(f_name, 0) > 0
    ]

    # Sort descending by contribution score, then by raw feature count
    filtered_contributions.sort(
        key=lambda item: (item[1], features.get(item[0], 0)),
        reverse=True,
    )

    top_3 = filtered_contributions[:3]

    # Formulate plain-English message
    if predicted_class == "none" or not top_3:
        explanation_text = "No prominent security vulnerability indicators triggered above risk threshold."
    else:
        feature_phrases = [
            f"{FEATURE_DESCRIPTIONS.get(f, f)} (value={features.get(f, 0)})"
            for f, _ in top_3
        ]
        if len(feature_phrases) == 1:
            reasons = feature_phrases[0]
        elif len(feature_phrases) == 2:
            reasons = f"{feature_phrases[0]} and {feature_phrases[1]}"
        else:
            reasons = f"{feature_phrases[0]}, {feature_phrases[1]}, and {feature_phrases[2]}"

        explanation_text = (
            f"Flagged as potential '{predicted_class.upper()}' due to presence of: {reasons}."
        )

    fix_suggestion = FIX_SUGGESTIONS.get(predicted_class, FIX_SUGGESTIONS["none"])

    return {
        "predicted_class": predicted_class,
        "method": method,
        "top_features": top_3,
        "explanation_text": explanation_text,
        "fix_suggestion": fix_suggestion,
        "all_contributions": contributions,
    }
