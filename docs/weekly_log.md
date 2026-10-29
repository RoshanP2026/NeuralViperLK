# NeuralViperLK: MSc Dissertation Weekly Progress Log

**Module:** COM752 Dissertation Project  
**Student:** M.C. Roshan Perera (Student No. S25026203)  
**Programme:** MSc Computer Science, Wrexham University  
**Supervisor:** Department of Computing and Engineering  
**Project Title:** An Explainable Machine Learning Approach to Detecting Security Vulnerabilities in Python Code: A Comparative Evaluation Against Static Analysis

> **How to use this log.** The "Planned Objectives" column is the plan. The "Tasks Done" and "Evidence" columns are filled in at the end of each week, with real dates, and only for work that has been finished. Last updated: 29 Oct 2026.

---

## 1. Ten-Week Plan and Progress Record (19 Oct 2026 – 29 Dec 2026)

| Week | Date Range | Planned Objectives | Tasks Done (fill in weekly) | Evidence & Artifacts | Planned Risks & Mitigations |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **W1** | 19 Oct – 25 Oct 2026 | Literature review extension; ethical checklist; pilot benchmark setup; dataset licence verification. | Pilot pipeline written (cleaning, project-level split, Random Forest, Bandit baseline, hybrids, McNemar). Pushed to GitHub on 27 Oct. *(Confirm the dates before submitting.)* | GitHub repository `neuralviperlk`; `scripts/run_pilot.py`; `results/pilot_run.json`. | No personal data and no live network scanning are planned. Confirm this in the ethics checklist. |
| **W2** | 26 Oct – 01 Nov 2026 | Replace the toy data with real Python samples from CVEfixes and SecurityEval for the four CWE classes (sqli, cmdi, creds, deser). Record licences. | Streamlit app deployed on Python 3.12 (29 Oct). SHAP switched on (29 Oct). Progress records corrected (29 Oct). | Live app URL; `requirements.txt`; this log. | Safe code may be under-represented. Plan: add safe functions from the same repositories. |
| **W3** | 02 Nov – 08 Nov 2026 | Run the cleaning pipeline on the real data; check comment and whitespace handling; remove duplicates and conflicting labels; write the cleaning report. | | | Duplicates may inflate scores. Plan: normalise code before removing duplicates. |
| **W4** | 09 Nov – 15 Nov 2026 | Make the Bandit baseline run through `python -m bandit` and report its source; check the rule mapping on real data. | | | Bandit may time out on large files. Plan: keep the timeout and clean up temporary files. |
| **W5** | 16 Nov – 22 Nov 2026 | Train logistic regression, random forest and gradient boosting with GroupKFold; add Bandit-as-features hybrid. | | | Class imbalance. Plan: balanced weights and per-class reporting. |
| **W6** | 23 Nov – 29 Nov 2026 | Tune on training data only; run all four hybrids; test H1 and H2 with McNemar and bootstrap intervals. | | | Leakage risk. Plan: group folds by `project`. |
| **W7** | 30 Nov – 06 Dec 2026 | Check the explanation layer; show whether SHAP or the fallback ran; run the 50-snippet explanation rubric (RQ4). | | | SHAP may be slow. Plan: limit tree depth. |
| **W8** | 07 Dec – 13 Dec 2026 | Fix app bugs (results disappearing on Save); finish CLI and SQLite storage; add a limits notice in the app. | | | Streamlit Cloud may erase saved scans. Plan: document local use for the history tab. |
| **W9** | 14 Dec – 20 Dec 2026 | Unit and integration tests with coverage; draft Chapters 4 to 7; supervisor review. | | | Holiday period. Plan: book the final supervisor review early. |
| **W10** | 21 Dec – 27 Dec 2026 | Finish Chapters 8 and 9; proofread; build the hand-over folder; test an offline install. | | | Dependency conflicts. Plan: pin versions and keep a local wheel folder. |
| **Buffer** | 28 Dec – 29 Dec 2026 | Final checks; checksums; electronic and media hand-in. | | | Keep this buffer free of new work. |

---

## 2. Milestone Tracker (targets only; tick a box only when the work is really finished)

- [ ] **Milestone 1 (target 06 Nov 2026):** Real dataset collected, cleaned, deduplicated, and split by project.
- [ ] **Milestone 2 (target 15 Nov 2026):** Bandit baseline run on real data and mapped to the four CWE classes.
- [ ] **Milestone 3 (target 27 Nov 2026):** Models tuned with GroupKFold; hybrids evaluated.
- [ ] **Milestone 4 (target 11 Dec 2026):** Streamlit app, CLI scanner and SQLite storage working.
- [ ] **Milestone 5 (target 17 Dec 2026):** Test suite passing; explanation rubric scored on 50 snippets.
- [ ] **Final hand-over (target 29 Dec 2026):** Report, source code, data, model and media package ready.
