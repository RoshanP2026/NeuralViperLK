# NeuralViperLK: Development Evidence and Audit Trail Guide

**Module:** COM752 Dissertation Project  
**Author:** M.C. Roshan Perera (Student No. S25026203), Wrexham University  
**Supervisor:** Department of Computing and Engineering  

---

## 1. Purpose of this Guide

In accordance with Wrexham University MSc dissertation assessment standards, all empirical claims and software artifacts must be accompanied by verifiable, tamper-evident development evidence. This document provides examiners and assessors with a navigational guide to inspect the development lifecycle, commit trail, automated test evidence, and experimental records.

---

## 2. Categories of Verifiable Evidence

### A. Version Control & Git History
- **Repository Strategy:** Development followed weekly iterations corresponding to the 10-week timetable outlined in the research proposal.
- **Commit Granularity:** Commits reflect incremental feature implementation, test creation, and bug fixes rather than monolithic uploads.
- **Viewing Git Evidence:**
  ```bash
  # View concise commit history with timestamps and author details
  git log --pretty=format:"%h - %ad : %s" --date=short
  
  # Inspect tag marking the final submission freeze
  git show v1.0.0-submission
  ```

### B. Automated Testing & Continuous Verification
- **Test Frameworks:** The test suite supports both Python's standard library `unittest` runner and `pytest`.
- **Reproducing Test Runs:**
  ```bash
  # Run all unit and integration tests with detailed output
  python -m unittest discover tests -v
  
  # Or with pytest (if installed)
  pytest -v --tb=short
  ```
- **Coverage Profile:**
  - `tests/test_core.py`: AST feature visitor, edge cases (unparseable syntax, safe vs. unsafe patterns), Bandit test ID mapping, code segment partitioning, SQLite schema & cascade deletion.
  - `tests/test_pipeline.py`: Data cleaning (deduplication, conflict excision), GroupShuffleSplit zero-leakage guarantee, classification metrics, exact binomial McNemar significance test against mathematical ground truth ($p=0.092285$).

### C. Experimental Reproducibility Artifacts
- **Seed Governance:** Random seeds are hardcoded to `42` (`RANDOM_SEED = 42`) across data splitting, Random Forest training, and cross-validation to ensure deterministic reproducibility.
- **Automated Pilot Pipeline:**
  ```bash
  python scripts/run_pilot.py
  ```
  Generates two auditable artifacts:
  - `results/pilot_metrics.csv`: Machine-readable performance metrics table (TP, FP, TN, FN, Precision, Recall, F1, FPR, Accuracy).
  - `results/pilot_run.json`: Complete experimental provenance including hyperparameters, cross-validation scores, dataset dimensions, and exact McNemar test statistics.

### D. Qualitative Explanation Rubric Audit (RQ4)
- **Objective Audit:** 50 correctly flagged vulnerable samples were systematically examined against the 3-point rubric defined in `docs/test_plan.md`.
- **Evidence Sheet:** Recorded in `04_Results_and_Evidence/rubric/explanation_rubric_50_audit.xlsx` noting code line, top 3 SHAP features, generated plain-English message, and assigned quality score.

### E. Supervisory Alignment & Timetable Adherence
- **Progress Synchronization:** Every weekly entry in `docs/weekly_log.md` matches the Gantt chart submitted in Section IV.E of the dissertation proposal.
- **Supervisory Logs:** Major architectural decisions (such as using GroupKFold and discarding conflicting duplicate samples) are traceable to the agreed actions in `docs/supervisor_meetings.md`.

---

## 3. Examiner Verification Checklist

| Criterion | Source of Verification | Location in Submission |
| :--- | :--- | :--- |
| Code Authenticity | Git commit graph & author sign-off | `04_Results_and_Evidence/logs/git_commit_history.txt` |
| Test Reliability | 100% passing tests via unittest/pytest | `tests/test_core.py`, `tests/test_pipeline.py` |
| Zero Data Leakage | GroupShuffleSplit disjoint test assertion | `src/vulndetect/data.py:split_by_project` |
| Statistical Rigor | Exact binomial McNemar calculation | `src/vulndetect/evaluate.py:mcnemar` |
| Fully Offline Usability | Air-gapped execution verification | `docs/handover_checklist.md` |
