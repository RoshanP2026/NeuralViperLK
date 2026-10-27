# NeuralViperLK: CD/DVD Handover Checklist & Offline Installation Guide

**Module:** COM752 Dissertation Project  
**Author:** M.C. Roshan Perera (Student No. S25026203)  
**Institution:** Wrexham University  
**Submission Target:** 29 December 2026  

---

## 1. Master Optical Disc (CD/DVD) Folder Layout

The submitted physical optical disc (or standalone offline submission archive) contains the exact directory hierarchy outlined below. No internet connection is required to inspect or execute any component:

```
NeuralViperLK_S25026203_Handover/
│
├── 01_Dissertation/
│   ├── COM752_Dissertation_Final_S25026203.pdf     # Complete final dissertation thesis (15,000–20,000 words)
│   ├── Proposal_Approved_S25026203.pdf             # Signed proposal & approval form
│   └── Ethics_Approval_Checklist_S25026203.pdf     # University ethical clearance checklist
│
├── 02_Source_Code/
│   ├── app/
│   │   └── streamlit_app.py                        # Streamlit web user interface
│   ├── src/
│   │   └── vulndetect/
│   │       ├── __init__.py                         # Package definition
│   │       ├── features.py                         # AST security feature extractor
│   │       ├── bandit_baseline.py                  # Bandit static analyser integration
│   │       ├── data.py                             # Cleaning, normalisation, & project splitting
│   │       ├── model.py                            # Multiclass Random Forest & tuning
│   │       ├── evaluate.py                         # Metrics & McNemar statistical test
│   │       ├── explain.py                          # SHAP TreeExplainer & remediation messages
│   │       ├── scanner.py                          # Multi-function file scanner
│   │       └── db.py                               # SQLite persistence layer
│   ├── scripts/
│   │   ├── make_sample_data.py                     # Synthetic toy dataset generator
│   │   ├── run_pilot.py                            # Experimental benchmark script
│   │   └── scan_file.py                            # CLI file scanner
│   ├── tests/
│   │   ├── test_core.py                            # Unit tests (AST, Bandit, SQLite, splitting)
│   │   └── test_pipeline.py                        # Integration tests (clean, split, metrics, McNemar)
│   ├── requirements.txt                            # Pinned dependency manifest
│   ├── README.md                                   # Comprehensive reproduction guide
│   └── .gitignore                                  # Git exclusion definitions
│
├── 03_Data_and_Models/
│   ├── data/
│   │   ├── sample_dataset.csv                      # Pre-generated 12-project validation dataset
│   │   └── cvefixes_securityeval_cleaned.csv       # Cleaned benchmark research dataset
│   └── models/
│       └── pilot_model.joblib                      # Serialised trained Random Forest artifacts
│
├── 04_Results_and_Evidence/
│   ├── results/
│   │   ├── pilot_metrics.csv                       # Tabular comparative performance metrics
│   │   ├── pilot_run.json                          # Full experiment configuration & McNemar outputs
│   │   └── neuralviper_scans.db                    # Pre-populated SQLite demonstration scan database
│   ├── logs/
│   │   ├── pytest_execution_log.txt                # Automated test execution transcripts
│   │   └── git_commit_history.txt                  # Full Git revision log with developer timestamps
│   └── rubric/
│       └── explanation_rubric_50_audit.xlsx        # 50-snippet qualitative evaluation worksheet
│
├── 05_Documentation/
│   ├── weekly_log.md                               # 10-week progress record + buffer
│   ├── supervisor_meetings.md                      # Log of 5 supervisory meetings
│   ├── data_plan.md                                # Ingestion, cleaning, and ethical protocols
│   ├── test_plan.md                                # Hypotheses H1/H2 and evaluation rubrics
│   ├── dev_evidence_guide.md                       # Audit trail and traceability guide
│   └── handover_checklist.md                       # This document
│
└── 06_Offline_Wheelhouse/                          # Pre-downloaded Python wheel packages (.whl)
    ├── bandit-*.whl
    ├── joblib-*.whl
    ├── numpy-*.whl
    ├── pandas-*.whl
    ├── scikit_learn-*.whl
    ├── scipy-*.whl
    ├── shap-*.whl
    ├── streamlit-*.whl
    └── pytest-*.whl
```

---

## 2. Air-Gapped / Offline Installation Verification Procedure

To verify that NeuralViperLK can be cleanly installed and operated on an isolated examination machine with zero network access:

### Step 1: Pre-caching packages (performed prior to burning disc):
```bash
# Executed on internet-connected build station to populate 06_Offline_Wheelhouse:
pip download -r requirements.txt -d ./06_Offline_Wheelhouse/
```

### Step 2: Clean room installation test (executed on isolated machine):
```bash
# 1. Unplug Ethernet / disable Wi-Fi on target test machine
# 2. Create isolated Python 3.10+ virtual environment
python3 -m venv .venv_offline

# 3. Activate virtual environment
# Linux/macOS:
source .venv_offline/bin/activate
# Windows:
.venv_offline\Scripts\activate

# 4. Install exclusively from local wheelhouse without contacting PyPI
pip install --no-index --find-links=./06_Offline_Wheelhouse -r requirements.txt
```

### Step 3: Verification of Offline Integrity:
```bash
# Verify all unit and pipeline tests pass without network access
python -m unittest discover tests -v

# Run the complete experimental pilot benchmark
python scripts/run_pilot.py

# Launch the Streamlit user interface locally
streamlit run app/streamlit_app.py --server.headless true
```

---

## 3. Submission Verification Checklist

- [x] **Thesis Document:** Final PDF compiled, paginated, and formatted according to Wrexham University postgraduate guidelines.
- [x] **Executable Code:** All source files include standard type hints, docstrings, and zero external network calls.
- [x] **Offline Test Suite:** Both `tests/test_core.py` and `tests/test_pipeline.py` pass cleanly.
- [x] **Data Integrity:** Dataset marked clearly regarding synthetic toy nature vs. empirical research benchmarks.
- [x] **Hardware Compatibility:** Tested on an 8 GB RAM laptop under both Ubuntu Linux 22.04 LTS and Windows 11.
- [x] **Media Checksum:** Disc manifest generated with SHA-256 hashes for all top-level folders.
