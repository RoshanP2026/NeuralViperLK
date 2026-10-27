# NeuralViperLK: Supervisor Meeting Logs

**Student:** M.C. Roshan Perera (Student No. S25026203)  
**Programme:** MSc Computer Science, Wrexham University  
**Module:** COM752 Dissertation Project  
**Academic Year:** 2026/2027  

---

### Meeting 1: Project Inception & Research Scope
- **Date:** 21 October 2026
- **Attendees:** Student, Academic Supervisor
- **Agenda:** Refinement of research proposal, dataset sources (CVEfixes, SecurityEval), and hypothesis definitions.
- **Discussion Points:**
  - Supervisor commended the selection of 4 bounded CWE classes (sqli, cmdi, creds, deser) with direct Bandit rule alignment.
  - Advised against premature introduction of complex deep learning (e.g. CodeBERT) before establishing a rigorous AST-based Random Forest baseline.
  - Emphasised the critical need for project-level data splitting (`GroupShuffleSplit`) to prevent cross-file syntactic leakage.
- **Agreed Actions:**
  1. Complete University ethics checklist confirming no human participants and public repository licence adherence.
  2. Implement toy dataset script to validate pipeline before heavy empirical data ingestion.

---

### Meeting 2: Data Cleaning Strategy & Deduplication Protocols
- **Date:** 04 November 2026
- **Attendees:** Student, Academic Supervisor
- **Agenda:** Milestone 1 progress check; handling duplicate code and conflicting labels.
- **Discussion Points:**
  - Reviewed Croft et al. (2023) findings on noise in vulnerability datasets.
  - Agreed that whitespace and comment stripping must precede duplicate checks.
  - Confirmed that samples with conflicting labels (same normalised snippet with different vulnerability labels) must be completely discarded rather than arbitrarily majority-voted.
- **Agreed Actions:**
  1. Finalise `src/vulndetect/data.py` clean function and produce quantitative cleaning report.
  2. Map Bandit test IDs for Milestone 2.

---

### Meeting 3: Baseline Comparison & Experimental Controls
- **Date:** 18 November 2026
- **Attendees:** Student, Academic Supervisor
- **Agenda:** Bandit static baseline results, feature engineering review, cross-validation design.
- **Discussion Points:**
  - Bandit generates false alarms on harmless concatenation where no SQL context exists; our AST visitor accurately distinguishes DB execution calls.
  - Confirmed GroupKFold cross-validation strategy: tuning must strictly occur on the training set without touching the held-out test set.
  - Discussed statistical testing: McNemar's test is the standard for paired binary classifiers. Agreed on exact binomial test for discordant counts < 25.
- **Agreed Actions:**
  1. Complete hyperparameter grid search for Random Forest.
  2. Implement both Agreement and Union hybrid configurations.

---

### Meeting 4: Explainability Layer & User Interface Evaluation
- **Date:** 02 December 2026
- **Attendees:** Student, Academic Supervisor
- **Agenda:** SHAP TreeExplainer integration, plain-English summary structure, Streamlit UI.
- **Discussion Points:**
  - Demonstrated SHAP waterfall and fallback to feature importance.
  - Supervisor stressed that size features (e.g. line_count) must be excluded from developer-facing explanations because they do not constitute vulnerability root causes.
  - Reviewed Streamlit interface tabs (Upload, Paste, History) and SQLite schema design.
- **Agreed Actions:**
  1. Define written 50-snippet explanation rubric to objectively assess RQ4 without human subject study.
  2. Complete CLI scanner script for terminal workflows.

---

### Meeting 5: Pre-Submission Review & Handover Verification
- **Date:** 16 December 2026
- **Attendees:** Student, Academic Supervisor
- **Agenda:** Milestone 5 completion, test suite review, dissertation draft chapters, offline hand-over packaging.
- **Discussion Points:**
  - Reviewed experimental findings: ML model showed superior F1 over Bandit on test partition; Hybrid Agreement achieved lowest false-positive rate.
  - Approved the 50-snippet qualitative explanation rubric results.
  - Verified that the offline CD/DVD structure meets university requirements: contains pre-built wheelhouse, automated tests, full dissertation PDF, and reproducible scripts.
- **Agreed Actions:**
  1. Final proofreading and formatting of thesis document (Chapters 1–8).
  2. Burn master submission disc with SHA-256 integrity manifest for 29 December deadline.
