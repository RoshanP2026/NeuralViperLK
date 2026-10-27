"""NeuralViperLK - Interactive Streamlit Web Application.

An Explainable Machine Learning Tool for Detecting Security Vulnerabilities in Python Code
and Benchmarking Against the Bandit Static Analyser.

MSc Computer Science, Wrexham University - COM752 Dissertation Project
Author: M.C. Roshan Perera (Student No. S25026203)
"""

from __future__ import annotations

import os
import sys
import pandas as pd
import streamlit as st

# Ensure repository root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from scripts.make_sample_data import generate_sample_dataset
from src.vulndetect.db import DEFAULT_DB_PATH, get_findings, list_scans, save_scan
from src.vulndetect.model import load_model, train_and_tune
from src.vulndetect.scanner import scan_code

# Code presets for student and evaluator testing
SAMPLE_PRESETS = {
    "SQL Injection (CWE-89)": '''def get_user_profile(db_connection, user_input):
    # Vulnerable: Raw string concatenation directly executed
    cursor = db_connection.cursor()
    query = f"SELECT * FROM users WHERE username = '{user_input}'"
    cursor.execute(query)
    return cursor.fetchall()
''',
    "Command Injection (CWE-78)": '''import os
import subprocess

def ping_server(target_host):
    # Vulnerable: Untrusted input concatenated into shell command
    command = "ping -c 1 " + target_host
    os.system(command)

def backup_logs(directory):
    # Vulnerable: shell=True with dynamic string
    cmd = f"tar -czf logs.tar.gz {directory}"
    subprocess.Popen(cmd, shell=True)
''',
    "Hard-coded Credentials (CWE-798)": '''def authenticate_service():
    # Vulnerable: Plaintext credentials embedded in source code
    api_key = "sk_live_948a2b84739192847192847"
    db_password = "SuperSecretDatabasePassword2026!"
    return {"api_key": api_key, "password": db_password}
''',
    "Unsafe Deserialisation (CWE-502)": '''import pickle
import yaml

def deserialize_payload(raw_stream):
    # Vulnerable: Untrusted pickle and unsafe yaml loading
    payload = pickle.loads(raw_stream)
    config = yaml.load(raw_stream)
    return payload, config
''',
    "Safe Implementations (Baseline)": '''import os
import subprocess
import json

def get_user_profile_safe(db_connection, user_input):
    cursor = db_connection.cursor()
    # Parameterized query protects against SQL injection
    cursor.execute("SELECT * FROM users WHERE username = ?", (user_input,))
    return cursor.fetchall()

def ping_server_safe(target_host):
    # List arguments without shell=True prevents command injection
    return subprocess.run(["ping", "-c", "1", target_host], shell=False, capture_output=True)

def authenticate_safe():
    # Secrets sourced safely from environment
    api_key = os.environ.get("SERVICE_API_KEY", "")
    return {"api_key": api_key}
''',
}


@st.cache_resource
def get_or_train_model():
    """Load cached model or train pilot baseline if not present on disc."""
    model_path = "results/pilot_model.joblib"
    if os.path.exists(model_path):
        return load_model(model_path)

    data_path = "data/sample_dataset.csv"
    if not os.path.exists(data_path):
        generate_sample_dataset(data_path)

    from scripts.run_pilot import features_from_dataframe
    from src.vulndetect.model import save_model

    df = pd.read_csv(data_path)
    X = features_from_dataframe(df)
    y = df["cwe"].values
    groups = df["project"].values

    artifacts = train_and_tune(X, y, groups, param_grid={"n_estimators": [50], "max_depth": [6]})
    save_model(artifacts, model_path)
    return artifacts


def render_findings_view(findings: list[dict], threshold: float, file_identifier: str, model_version: str):
    """Render findings table, metrics cards, and expandable explainability details."""
    if not findings:
        st.info("No code blocks or functions identified in the provided snippet.")
        return

    # High-level summary metrics
    total_blocks = len(findings)
    flagged_blocks = sum(1 for f in findings if f["is_flagged"])
    ml_flags = sum(1 for f in findings if f["ml_flag"])
    bandit_flags_count = sum(1 for f in findings if f["bandit_flag"])
    max_risk = max(f["risk_score"] for f in findings)

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Scanned Blocks", total_blocks)
    c2.metric("Flagged Findings", flagged_blocks, delta=f"{flagged_blocks}/{total_blocks}")
    c3.metric("Max Risk Score", f"{max_risk:.2%}")
    c4.metric("Bandit Flagged", bandit_flags_count)

    # Tabular summary
    table_rows = []
    for f in findings:
        table_rows.append({
            "Block Name": f["block_name"],
            "Lines": f"{f['line_number']} - {f['end_line']}",
            "Weakness Class": f["weakness_type"].upper(),
            "ML Risk": f"{f['risk_score']:.4f}",
            "ML Flag": "YES" if f["ml_flag"] else "NO",
            "Bandit Flag": "YES" if f["bandit_flag"] else "NO",
            "Verdict": "FLAGGED" if f["is_flagged"] else "CLEAN",
        })
    st.subheader("Scan Results Matrix")
    st.dataframe(pd.DataFrame(table_rows), use_container_width=True)

    # Detailed Explainability Expanders
    st.subheader("Explainable Vulnerability Rationale & Remediation")
    for idx, f in enumerate(findings, start=1):
        badge = "🔴 RISK" if f["is_flagged"] else "🟢 SAFE"
        header = f"{badge} #{idx}: {f['block_name']} (Lines {f['line_number']} - {f['end_line']}) — Class: {f['weakness_type'].upper()} (Risk: {f['risk_score']:.2%})"
        with st.expander(header, expanded=f["is_flagged"]):
            col_a, col_b = st.columns([1, 1])
            with col_a:
                st.markdown("**Explanation:**")
                st.write(f["explanation"])
                st.markdown("**Remediation Guidance:**")
                st.info(f["fix_suggestion"])

                if f["top_features"]:
                    st.markdown("**Key Feature Contributions:**")
                    feat_df = pd.DataFrame(f["top_features"], columns=["Feature", "Contribution"])
                    st.dataframe(feat_df, use_container_width=True)

            with col_b:
                if f["bandit_issues"]:
                    st.markdown("**Bandit Static Analysis Rules Triggered:**")
                    for b_iss in f["bandit_issues"]:
                        st.warning(f"**{b_iss['test_id']}** ({b_iss['test_name']}): {b_iss['issue_text']}")
                else:
                    st.markdown("**Bandit Static Analyser:** No rules fired on this block.")

                st.markdown("**Code Snippet:**")
                st.code(f["code_snippet"], language="python")

    # Persist Scan Button
    st.markdown("---")
    if st.button("💾 Save Scan Session to Database", key=f"save_{file_identifier}"):
        scan_id = save_scan(
            file_name=file_identifier,
            findings=findings,
            model_version=model_version,
            db_path=DEFAULT_DB_PATH,
        )
        st.success(f"Scan persisted to SQLite! Scan ID: `{scan_id}`")


def main():
    st.set_page_config(
        page_title="NeuralViperLK - Explainable Vulnerability Detection",
        page_icon="🛡️",
        layout="wide",
    )

    st.title("NeuralViperLK: Vulnerability Detection & Static Baseline Benchmarking")
    st.caption(
        "MSc Computer Science Dissertation Research Project (COM752) | "
        "Student: M.C. Roshan Perera (S25026203) | Wrexham University"
    )

    # Sidebar parameters
    st.sidebar.header("Configuration & Parameters")
    risk_threshold = st.sidebar.slider(
        "ML Risk Decision Threshold",
        min_value=0.0,
        max_value=1.0,
        value=0.50,
        step=0.05,
        help="Probability boundary 1 - P(none) required to flag a snippet as vulnerable.",
    )
    enable_bandit = st.sidebar.checkbox(
        "Enable Bandit Baseline",
        value=True,
        help="Execute the Bandit static analysis baseline alongside ML predictions.",
    )

    st.sidebar.markdown("---")
    st.sidebar.markdown("### Target Weakness Classes")
    st.sidebar.markdown(
        "- **sqli**: CWE-89 SQL Injection\n"
        "- **cmdi**: CWE-78 OS Command Injection\n"
        "- **creds**: CWE-798 Hard-coded Credentials\n"
        "- **deser**: CWE-502 Unsafe Deserialisation"
    )

    st.sidebar.markdown("---")
    st.sidebar.markdown("### Methodology & Controls")
    st.sidebar.caption(
        "• Offline operation (no network required)\n"
        "• AST-based feature extraction\n"
        "• Balanced Random Forest Classifier\n"
        "• SHAP TreeExplainer attribution\n"
        "• SQLite scan persistence"
    )

    model_artifacts = get_or_train_model()
    model_version = model_artifacts.get("version", "1.0.0")

    tab_upload, tab_paste, tab_history = st.tabs(["📁 Upload File", "📝 Paste Code", "📜 Scan History"])

    # 1. Upload File Tab
    with tab_upload:
        st.subheader("Upload Python Source File (.py)")
        uploaded_file = st.file_uploader("Select a Python file to analyze", type=["py"])
        if uploaded_file is not None:
            content = uploaded_file.read().decode("utf-8")
            st.text_area("File Preview", content, height=180, disabled=True)
            if st.button("🚀 Analyze Uploaded File", key="btn_upload"):
                with st.spinner("Extracting AST features and computing model scores..."):
                    findings = scan_code(
                        code=content,
                        model_artifacts=model_artifacts,
                        file_name=uploaded_file.name,
                        risk_threshold=risk_threshold,
                        enable_bandit=enable_bandit,
                    )
                render_findings_view(findings, risk_threshold, uploaded_file.name, model_version)

    # 2. Paste Code Tab
    with tab_paste:
        st.subheader("Paste or Select Code Snippet")
        preset_name = st.selectbox("Load Sample Vulnerability Template", list(SAMPLE_PRESETS.keys()))
        selected_code = SAMPLE_PRESETS[preset_name]

        code_input = st.text_area(
            "Python Source Code",
            value=selected_code,
            height=240,
            help="Paste arbitrary Python 3 code to analyze functions and module statements.",
        )

        if st.button("🔍 Run Explainable Security Scan", key="btn_paste"):
            with st.spinner("Running AST analysis and Bandit baseline..."):
                findings = scan_code(
                    code=code_input,
                    model_artifacts=model_artifacts,
                    file_name=f"pasted_snippet_{preset_name.split()[0].lower()}.py",
                    risk_threshold=risk_threshold,
                    enable_bandit=enable_bandit,
                )
            render_findings_view(findings, risk_threshold, f"snippet_{preset_name}", model_version)

    # 3. Scan History Tab
    with tab_history:
        st.subheader("Historical Scans Database (SQLite)")
        scans = list_scans(DEFAULT_DB_PATH)
        if not scans:
            st.info("No scans recorded yet. Run a scan in the Upload or Paste tab and click 'Save Scan Session'.")
        else:
            scan_df = pd.DataFrame(scans)
            st.dataframe(scan_df, use_container_width=True)

            selected_scan_id = st.selectbox(
                "Select Scan ID to Inspect Findings",
                scan_df["scan_id"].tolist(),
            )
            if selected_scan_id:
                findings_records = get_findings(selected_scan_id, DEFAULT_DB_PATH)
                if findings_records:
                    st.write(f"**Findings recorded for scan `{selected_scan_id}`:**")
                    st.dataframe(pd.DataFrame(findings_records), use_container_width=True)
                else:
                    st.write("No findings registered for this scan session.")


if __name__ == "__main__":
    main()
