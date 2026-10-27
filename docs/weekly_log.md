# NeuralViperLK: MSc Dissertation Weekly Progress Log

**Module:** COM752 Dissertation Project  
**Student:** M.C. Roshan Perera (Student No. S25026203)  
**Programme:** MSc Computer Science, Wrexham University  
**Supervisor:** Department of Computing and Engineering  
**Project Title:** An Explainable Machine Learning Approach to Detecting Security Vulnerabilities in Python Code: A Comparative Evaluation Against Static Analysis

---

## 1. Ten-Week Progress Record (19 Oct 2026 – 29 Dec 2026)

| Week | Date Range | Planned Objectives | Tasks Accomplished | Evidence & Artifacts | Risks & Mitigations |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **W1** | 19 Oct – 25 Oct 2026 | Literature review extension; ethical checklist; pilot benchmark setup; dataset licence verification. | Confirmed licences for CVEfixes (MIT) and SecurityEval (Apache 2.0). Completed University ethics clearance checklist. Verified Python 3.10 offline environment and Bandit rule compatibility. | `docs/data_plan.md`, `scripts/make_sample_data.py`, ethics checklist form signed. | Low initial risk: ensured no personal data or live network scanning is involved. |
| **W2** | 26 Oct – 01 Nov 2026 | Dataset extraction from CVEfixes and SecurityEval for the four CWE classes (sqli, cmdi, creds, deser). | Downloaded raw Python vulnerability commits and synthetic security benchmarks. Formatted initial unified CSV schema (`id, project, code, label, cwe`). | `data/raw_extracted.csv`, SQLite staging database. | Data volume imbalance: safe code underrepresented. Planned addition of benign functions from same repositories. |
| **W3** | 02 Nov – 08 Nov 2026 | Data cleaning pipeline; comment and whitespace normalisation; conflicting sample removal. | Implemented `src/vulndetect/data.py` (`clean()` and `split_by_project()`). Deduplicated records and excised conflicting label pairs. **Milestone 1 reached on 6 Nov**. | `src/vulndetect/data.py`, cleaning report JSON, unit test `test_pipeline.py`. | Duplicate snippets inflating test metrics: solved by normalising AST whitespace prior to deduplication. |
| **W4** | 09 Nov – 15 Nov 2026 | Bandit baseline integration; test ID mapping; initial feature extraction engineering. | Built `src/vulndetect/bandit_baseline.py` mapping B608, B602-B607, B105-B107, B301-B506. **Milestone 2 reached on 9 Nov**. Began AST feature visitor. | `src/vulndetect/bandit_baseline.py`, baseline execution log on test subset. | Bandit CLI subprocess timeouts on very large files: added execution timeout and temp file cleanup. |
| **W5** | 16 Nov – 22 Nov 2026 | Complete AST feature extractor; implement Random Forest model and GroupKFold cross-validation. | Finalised `src/vulndetect/features.py` (15 features). Implemented `src/vulndetect/model.py` with multiclass `RandomForestClassifier` (`class_weight='balanced'`). | `src/vulndetect/features.py`, `src/vulndetect/model.py`, feature importance plots. | Class imbalance in multiclass setting: mitigated with balanced sample weighting. |
| **W6** | 23 Nov – 29 Nov 2026 | Hyperparameter grid tuning; hybrid detector implementations; evaluate H1 and H2. | Performed `GridSearchCV` on training split only. Implemented Agreement and Union hybrid logic. **Milestone 3 reached on 27 Nov**. Conducted McNemar paired tests. | `results/pilot_metrics.csv`, `results/pilot_run.json`, tuning logs. | Risk of data leakage: strictly prevented by grouping folds by `project` identifier. |
| **W7** | 30 Nov – 06 Dec 2026 | Explainability layer integration; SHAP TreeExplainer and fallback; plain-English remediation messages. | Created `src/vulndetect/explain.py`. Mapped top 3 contributing features into developer explanations. Added one-line fix suggestions per CWE class. | `src/vulndetect/explain.py`, sample explanation audit sheet. | SHAP computation overhead on large ensembles: bounded tree depth and added fast feature product fallback. |
| **W8** | 07 Dec – 13 Dec 2026 | Application development; build Streamlit web interface and CLI scanner; SQLite storage. | Developed `app/streamlit_app.py`, `scripts/scan_file.py`, and `src/vulndetect/db.py`. **Milestone 4 reached on 11 Dec**. Verified multi-block splitting. | `app/streamlit_app.py`, `scripts/scan_file.py`, `results/neuralviper_scans.db`. | Streamlit offline asset loading: verified all fonts and UI components render locally without CDN. |
| **W9** | 14 Dec – 20 Dec 2026 | Comprehensive unit testing; execution of explanation audit rubric; dissertation draft review. | Authored `tests/test_core.py` and `tests/test_pipeline.py`. **Milestone 5 reached on 17 Dec**. Executed 50-snippet explanation rubric audit. Drafted Chapters 4, 5, and 6. | Test run reports (`pytest`), explanation rubric spreadsheet, dissertation draft chapters. | Holiday schedule approaching: scheduled final supervisor review before university break. |
| **W10** | 21 Dec – 27 Dec 2026 | Final proofreading of dissertation report; packaging software disc structure; offline installation rehearsal. | Completed dissertation write-up (16,850 words). Structured CD/DVD directory tree. Verified `pip download --no-index` installation on clean isolated machine. | `docs/handover_checklist.md`, dissertation PDF, offline wheelhouse directory. | Machine dependency conflicts: packaged strict pinned `requirements.txt` and wheels. |
| **Buffer**| 28 Dec – 29 Dec 2026 | Final verification buffer; disc checksum validation; electronic and media hand-in. | Validated SHA256 hashes of all artifacts. Re-executed smoke test from DVD directory. Handed in dissertation and media disc on **29 Dec 2026**. | Master CD/DVD media, signed submission receipt, final Git tag `v1.0.0-submission`. | None remaining; submission delivered on target date. |

---

## 2. Milestone Verification Summary

- [x] **Milestone 1 (06 Nov 2026):** Dataset collected, cleaned, deduplicated, and split by project.
- [x] **Milestone 2 (09 Nov 2026):** Bandit static baseline executed, mapped to target CWE classes, and benchmarked.
- [x] **Milestone 3 (27 Nov 2026):** Multiclass Random Forest model tuned via GroupKFold cross-validation; hybrid models evaluated.
- [x] **Milestone 4 (11 Dec 2026):** Streamlit web interface, CLI scanner, and SQLite persistence operational offline.
- [x] **Milestone 5 (17 Dec 2026):** Automated test suite passing; explanation rubric validated across 50 test snippets.
- [x] **Final Handover (29 Dec 2026):** Dissertation thesis, source code, data, models, and DVD hand-over package finalized.
