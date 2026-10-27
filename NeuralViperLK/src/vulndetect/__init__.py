"""NeuralViperLK - Explainable Vulnerability Detection for Python Code.

Core package providing AST-based feature extraction, Bandit baseline integration,
data preprocessing, machine learning classifiers, model explainability (SHAP),
code scanning, and SQLite persistence.
"""

__version__ = "1.0.0"
__author__ = "M.C. Roshan Perera (Student No. S25026203)"
__module__ = "COM752 Dissertation Project, Wrexham University"

WEAKNESS_CLASSES: list[str] = ["sqli", "cmdi", "creds", "deser"]
ALL_CLASSES: list[str] = ["none", "sqli", "cmdi", "creds", "deser"]
