"""Generate a synthetic toy dataset across 12 projects for pipeline validation.

DISCLAIMER / ETHICAL NOTICE:
This script produces a synthetic TOY dataset intended solely for unit testing,
continuous integration, and verifying the end-to-end training and evaluation pipeline.
It is NOT real empirical research data. Real empirical evaluations for the dissertation
must use verified samples from CVEfixes and SecurityEval as specified in docs/data_plan.md.
"""

from __future__ import annotations

import csv
import os
from typing import Any

PROJECTS = [
    "auth_service",
    "billing_gateway",
    "cms_engine",
    "data_pipeline",
    "ecom_api",
    "fleet_tracker",
    "gateway_proxy",
    "health_portal",
    "inventory_sync",
    "job_scheduler",
    "kms_vault",
    "log_aggregator",
]

# Code snippet templates: (cwe, label, code_template)
TEMPLATES: list[tuple[str, int, str]] = [
    # SQL Injection (CWE-89) - Vulnerable
    (
        "sqli",
        1,
        """def get_user_by_id(db_conn, user_id):
    query = f"SELECT id, username, email FROM users WHERE user_id = '{user_id}'"
    cursor = db_conn.cursor()
    cursor.execute(query)
    return cursor.fetchone()""",
    ),
    (
        "sqli",
        1,
        """def search_products(db, search_term):
    sql = "SELECT * FROM inventory WHERE name LIKE '%" + search_term + "%'"
    cursor = db.cursor()
    cursor.execute(sql)
    return cursor.fetchall()""",
    ),
    (
        "sqli",
        1,
        """def update_profile_status(conn, user_id, status):
    sql = "UPDATE accounts SET status = '%s' WHERE id = %s" % (status, user_id)
    cursor = conn.cursor()
    cursor.execute(sql)
    conn.commit()""",
    ),
    # SQL Injection (CWE-89) - Safe
    (
        "none",
        0,
        """def get_user_by_id(db_conn, user_id):
    query = "SELECT id, username, email FROM users WHERE user_id = ?"
    cursor = db_conn.cursor()
    cursor.execute(query, (user_id,))
    return cursor.fetchone()""",
    ),
    (
        "none",
        0,
        """def search_products(db, search_term):
    sql = "SELECT * FROM inventory WHERE name LIKE ?"
    cursor = db.cursor()
    cursor.execute(sql, (f"%{search_term}%",))
    return cursor.fetchall()""",
    ),
    # Command Injection (CWE-78) - Vulnerable
    (
        "cmdi",
        1,
        """def ping_remote_host(hostname):
    import os
    cmd = "ping -c 1 " + hostname
    exit_code = os.system(cmd)
    return exit_code == 0""",
    ),
    (
        "cmdi",
        1,
        """def backup_directory(target_path):
    import subprocess
    cmd = f"tar -czf backup.tar.gz {target_path}"
    return subprocess.Popen(cmd, shell=True)""",
    ),
    (
        "cmdi",
        1,
        """def fetch_system_stats(service_name):
    import os
    stream = os.popen(f"systemctl status {service_name}")
    return stream.read()""",
    ),
    # Command Injection (CWE-78) - Safe
    (
        "none",
        0,
        """def ping_remote_host(hostname):
    import subprocess
    result = subprocess.run(["ping", "-c", "1", hostname], shell=False, capture_output=True)
    return result.returncode == 0""",
    ),
    (
        "none",
        0,
        """def backup_directory(target_path):
    import subprocess
    return subprocess.run(["tar", "-czf", "backup.tar.gz", target_path], shell=False)""",
    ),
    # Hard-coded Credentials (CWE-798) - Vulnerable
    (
        "creds",
        1,
        """def connect_payment_gateway():
    api_key = "sk_live_948a2b84739192847192847"
    secret_token = "prod_sec_837492817492847"
    return {"api_key": api_key, "token": secret_token}""",
    ),
    (
        "creds",
        1,
        """def get_db_credentials():
    admin_password = "SuperSecretDatabasePassword2026!"
    db_user = "root_admin"
    return db_user, admin_password""",
    ),
    (
        "creds",
        1,
        """def sign_jwt_payload():
    private_key = "-----BEGIN RSA PRIVATE KEY-----MIIEpAIBAAKCAQEA0-----END RSA PRIVATE KEY-----"
    return private_key""",
    ),
    # Hard-coded Credentials (CWE-798) - Safe
    (
        "none",
        0,
        """def connect_payment_gateway():
    import os
    api_key = os.environ.get("PAYMENT_GATEWAY_API_KEY")
    secret_token = os.environ.get("PAYMENT_SECRET_TOKEN")
    return {"api_key": api_key, "token": secret_token}""",
    ),
    (
        "none",
        0,
        """def get_db_credentials():
    import os
    admin_password = os.environ.get("DB_PASSWORD", "")
    db_user = os.environ.get("DB_USER", "app_user")
    return db_user, admin_password""",
    ),
    # Unsafe Deserialisation (CWE-502) - Vulnerable
    (
        "deser",
        1,
        """def load_session_state(serialized_blob):
    import pickle
    session_data = pickle.loads(serialized_blob)
    return session_data""",
    ),
    (
        "deser",
        1,
        """def parse_user_config(raw_yaml_str):
    import yaml
    config = yaml.load(raw_yaml_str)
    return config""",
    ),
    (
        "deser",
        1,
        """def restore_cache_object(file_path):
    import _pickle
    with open(file_path, "rb") as f:
        return _pickle.load(f)""",
    ),
    # Unsafe Deserialisation (CWE-502) - Safe
    (
        "none",
        0,
        """def load_session_state(serialized_blob):
    import json
    return json.loads(serialized_blob.decode("utf-8"))""",
    ),
    (
        "none",
        0,
        """def parse_user_config(raw_yaml_str):
    import yaml
    return yaml.safe_load(raw_yaml_str)""",
    ),
    # General Safe Code (Class none)
    (
        "none",
        0,
        """def calculate_composite_score(weights, scores):
    if len(weights) != len(scores):
        raise ValueError("Dimensions must match")
    total = sum(w * s for w, s in zip(weights, scores))
    return round(total / sum(weights), 4)""",
    ),
    (
        "none",
        0,
        """def format_user_display_name(first_name, last_name, role="user"):
    name = f"{first_name.strip()} {last_name.strip()}"
    return f"{name} ({role.upper()})" """,
    ),
]


def generate_sample_dataset(output_path: str = "data/sample_dataset.csv") -> list[dict[str, Any]]:
    """Generate toy dataset across 12 projects and write to CSV."""
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    rows: list[dict[str, Any]] = []
    sample_id = 1

    # Distribute templates across 12 projects with variations
    for proj_idx, project in enumerate(PROJECTS):
        for tmpl_idx, (cwe, label, code_tmpl) in enumerate(TEMPLATES):
            # Inject slight variations per project so AST remains rich
            code = code_tmpl.replace("users", f"{project}_users")
            code = code.replace("inventory", f"{project}_inventory")
            code = code.replace("accounts", f"{project}_accounts")
            code = code.replace("backup.tar.gz", f"{project}_backup.tar.gz")

            rows.append({
                "id": f"SMP-{sample_id:04d}",
                "project": project,
                "code": code,
                "label": label,
                "cwe": cwe,
            })
            sample_id += 1

    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["id", "project", "code", "label", "cwe"])
        writer.writeheader()
        writer.writerows(rows)

    print(f"[+] Successfully generated {len(rows)} toy samples across {len(PROJECTS)} projects.")
    print(f"[+] Output path: {output_path}")
    print("[!] NOTICE: This is a synthetic toy dataset for smoke-testing and offline validation.")
    print("    Real experimental evaluation for the dissertation requires CVEfixes & SecurityEval.")
    return rows


if __name__ == "__main__":
    generate_sample_dataset()
