"""Multiclass Random Forest model training, hyperparameter tuning, and inference.

Configures a multiclass RandomForestClassifier across five classes:
['none', 'sqli', 'cmdi', 'creds', 'deser'] with balanced class weighting.
Uses GroupKFold inside GridSearchCV strictly on training data to prevent leakage.
Computes vulnerability risk score defined as: Risk = 1.0 - P(class='none').
"""

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


def get_default_param_grid() -> dict[str, list[Any]]:
    """Return default parameter grid for RandomForest tuning."""
    return {
        "n_estimators": [50, 100, 150],
        "max_depth": [6, 12, None],
        "min_samples_split": [2, 4],
        "min_samples_leaf": [1, 2],
    }


def train_and_tune(
    X: np.ndarray | pd.DataFrame,
    y: np.ndarray | pd.Series | list[str],
    groups: np.ndarray | pd.Series | list[str],
    param_grid: dict[str, list[Any]] | None = None,
    n_splits: int = 4,
) -> dict[str, Any]:
    """Train and tune a multiclass Random Forest with GroupKFold cross-validation.

    Args:
        X: Feature matrix of shape (n_samples, n_features).
        y: Class labels ('none', 'sqli', 'cmdi', 'creds', 'deser').
        groups: Project identifiers for GroupKFold to maintain repository isolation.
        param_grid: Optional hyperparameter search grid.
        n_splits: Number of group-aware folds for cross-validation.

    Returns:
        Dictionary of model artifacts including best estimator, classes, feature names.
    """
    if param_grid is None:
        param_grid = get_default_param_grid()

    X_mat = np.asarray(X)
    y_arr = np.asarray(y)
    groups_arr = np.asarray(groups)

    missing = [c for c in ALL_CLASSES if c not in set(y_arr)]
    if missing:
        raise ValueError(f"Training data has no examples of: {missing}. "
                         "Check the dataset, the cleaning step or the split.")

    # Determine unique groups to ensure n_splits <= len(unique_groups)
    unique_groups = len(np.unique(groups_arr))
    cv_splits = min(n_splits, max(2, unique_groups))

    gkf = GroupKFold(n_splits=cv_splits)

    base_rf = RandomForestClassifier(
        random_state=RANDOM_SEED,
        class_weight="balanced",
    )

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

    # Extract feature importances
    importances = dict(zip(FEATURE_NAMES, best_estimator.feature_importances_))

    artifacts: dict[str, Any] = {
        "estimator": best_estimator,
        "classes": list(best_estimator.classes_),
        "feature_names": FEATURE_NAMES,
        "best_params": grid_search.best_params_,
        "best_score": float(grid_search.best_score_),
        "feature_importances": importances,
        "version": "1.0.0",
        "random_seed": RANDOM_SEED,
    }

    return artifacts


def predict_scores(model_artifacts: dict[str, Any] | RandomForestClassifier, X: np.ndarray | pd.DataFrame) -> np.ndarray:
    """Compute vulnerability risk scores: Risk = 1.0 - P(none).

    Args:
        model_artifacts: Model dictionary from train_and_tune or RandomForest instance.
        X: Feature matrix.

    Returns:
        1D numpy array of float risk scores in range [0.0, 1.0].
    """
    estimator, classes = _unpack_model(model_artifacts)
    X_mat = np.asarray(X)

    if X_mat.ndim == 1:
        X_mat = X_mat.reshape(1, -1)

    probs = estimator.predict_proba(X_mat)

    # Locate the column index for 'none' class
    if "none" in classes:
        none_idx = classes.index("none")
        p_none = probs[:, none_idx]
        risk_scores = 1.0 - p_none
    else:
        # Fallback if no safe class is present
        risk_scores = np.max(probs, axis=1)

    return np.clip(risk_scores, 0.0, 1.0)


def predict_binary(
    model_artifacts: dict[str, Any] | RandomForestClassifier,
    X: np.ndarray | pd.DataFrame,
    threshold: float = 0.5,
) -> np.ndarray:
    """Predict binary vulnerability status (0 = safe, 1 = vulnerable) given a threshold.

    Args:
        model_artifacts: Model artifacts dict or RandomForestClassifier.
        X: Feature matrix.
        threshold: Risk score decision boundary.

    Returns:
        1D numpy array of binary integers (0 or 1).
    """
    scores = predict_scores(model_artifacts, X)
    return (scores >= threshold).astype(int)


def predict_cwe(
    model_artifacts: dict[str, Any] | RandomForestClassifier,
    X: np.ndarray | pd.DataFrame,
    threshold: float = 0.5,
) -> np.ndarray:
    """Predict the specific CWE weakness class or 'none'.

    If overall risk score is below threshold, classifies as 'none'.
    Otherwise, returns the highest-probability vulnerable class.

    Args:
        model_artifacts: Model artifacts dict or RandomForestClassifier.
        X: Feature matrix.
        threshold: Decision threshold.

    Returns:
        1D numpy array of class strings ('none', 'sqli', 'cmdi', 'creds', 'deser').
    """
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
            # Pick highest probability among non-'none' classes
            best_cwe = "none"
            best_prob = -1.0
            for idx, cls_name in enumerate(classes):
                if cls_name != "none" and probs[i, idx] > best_prob:
                    best_prob = probs[i, idx]
                    best_cwe = cls_name
            predictions.append(best_cwe if best_prob > 0 else "none")

    return np.array(predictions)


def save_model(model_artifacts: dict[str, Any], path: str) -> str:
    """Save model artifacts to a file using joblib.

    Args:
        model_artifacts: Trained model dictionary.
        path: Target file path.

    Returns:
        Resolved file path.
    """
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    joblib.dump(model_artifacts, path)
    return path


def load_model(path: str) -> dict[str, Any]:
    """Load model artifacts from disk using joblib.

    Args:
        path: Path to serialized model file.

    Returns:
        Model artifacts dictionary.
    """
    if not os.path.exists(path):
        raise FileNotFoundError(f"Model file not found at: {path}")
    artifacts = joblib.load(path)
    return artifacts


def _unpack_model(model_input: Any) -> tuple[RandomForestClassifier, list[str]]:
    """Helper to extract estimator and classes from dict or raw classifier."""
    if isinstance(model_input, dict):
        estimator = model_input["estimator"]
        classes = list(model_input["classes"])
        return estimator, classes
    elif hasattr(model_input, "predict_proba"):
        classes = list(getattr(model_input, "classes_", ALL_CLASSES))
        return model_input, classes
    else:
        raise TypeError("Model input must be a dictionary with 'estimator' or a RandomForestClassifier.")
