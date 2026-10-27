"""SQLite database persistence for scans and vulnerability findings.

Maintains structured scan history:
- scans: metadata regarding each scanned file, timestamp, model version, and finding count.
- findings: granular findings linked to scans by foreign key, tracking line number,
  weakness type, ML risk score, Bandit baseline flag, and plain-English explanation.
"""

from __future__ import annotations

import datetime
import os
import sqlite3
import uuid
from typing import Any

DEFAULT_DB_PATH = "results/neuralviper_scans.db"


def connect(db_path: str = DEFAULT_DB_PATH) -> sqlite3.Connection:
    """Open or create a SQLite database connection and initialize required tables.

    Args:
        db_path: Path to the SQLite database file.

    Returns:
        sqlite3.Connection instance with foreign keys enabled.
    """
    os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA foreign_keys = ON;")
    init_db(conn)
    return conn


def init_db(conn: sqlite3.Connection) -> None:
    """Create scans and findings tables if they do not exist."""
    with conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
                scan_id TEXT PRIMARY KEY,
                file_name TEXT NOT NULL,
                scanned_at TEXT NOT NULL,
                model_version TEXT NOT NULL,
                n_findings INTEGER NOT NULL
            );
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS findings (
                finding_id TEXT PRIMARY KEY,
                scan_id TEXT NOT NULL,
                line_number INTEGER NOT NULL,
                weakness_type TEXT NOT NULL,
                risk_score REAL NOT NULL,
                bandit_flag INTEGER NOT NULL,
                explanation TEXT NOT NULL,
                FOREIGN KEY (scan_id) REFERENCES scans (scan_id) ON DELETE CASCADE
            );
            """
        )


def save_scan(
    file_name: str,
    findings: list[dict[str, Any]],
    model_version: str = "1.0.0",
    db_path: str = DEFAULT_DB_PATH,
    conn: sqlite3.Connection | None = None,
) -> str:
    """Save a scan session and associated vulnerability findings.

    Args:
        file_name: Name or path of the scanned target file.
        findings: List of finding dictionaries from scanner.scan_code.
        model_version: Version identifier of the detection model.
        db_path: Path to SQLite database file.
        conn: Optional existing sqlite3.Connection.

    Returns:
        Generated scan_id UUID string.
    """
    close_when_done = False
    if conn is None:
        conn = connect(db_path)
        close_when_done = True

    scan_id = str(uuid.uuid4())
    scanned_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
    n_findings = len(findings)

    try:
        with conn:
            conn.execute(
                """
                INSERT INTO scans (scan_id, file_name, scanned_at, model_version, n_findings)
                VALUES (?, ?, ?, ?, ?)
                """,
                (scan_id, file_name, scanned_at, model_version, n_findings),
            )

            for f in findings:
                finding_id = str(uuid.uuid4())
                line_num = int(f.get("line_number", 1))
                w_type = str(f.get("weakness_type", "none"))
                r_score = float(f.get("risk_score", 0.0))
                b_flag = int(f.get("bandit_flag", 0))
                expl = str(f.get("explanation", ""))

                conn.execute(
                    """
                    INSERT INTO findings (finding_id, scan_id, line_number, weakness_type, risk_score, bandit_flag, explanation)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (finding_id, scan_id, line_num, w_type, r_score, b_flag, expl),
                )
    finally:
        if close_when_done:
            conn.close()

    return scan_id


def get_findings(scan_id: str, db_path: str = DEFAULT_DB_PATH) -> list[dict[str, Any]]:
    """Retrieve all findings for a given scan_id.

    Args:
        scan_id: Target scan UUID.
        db_path: Path to SQLite database file.

    Returns:
        List of finding dictionaries ordered by line number.
    """
    conn = connect(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT finding_id, scan_id, line_number, weakness_type, risk_score, bandit_flag, explanation
            FROM findings
            WHERE scan_id = ?
            ORDER BY line_number ASC
            """,
            (scan_id,),
        )
        rows = cursor.fetchall()
        results: list[dict[str, Any]] = []
        for r in rows:
            results.append({
                "finding_id": r[0],
                "scan_id": r[1],
                "line_number": r[2],
                "weakness_type": r[3],
                "risk_score": r[4],
                "bandit_flag": r[5],
                "explanation": r[6],
            })
        return results
    finally:
        conn.close()


def list_scans(db_path: str = DEFAULT_DB_PATH) -> list[dict[str, Any]]:
    """List all recorded scans ordered by timestamp descending.

    Args:
        db_path: Path to SQLite database file.

    Returns:
        List of scan metadata dictionaries.
    """
    conn = connect(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT scan_id, file_name, scanned_at, model_version, n_findings
            FROM scans
            ORDER BY scanned_at DESC
            """
        )
        rows = cursor.fetchall()
        scans: list[dict[str, Any]] = []
        for r in rows:
            scans.append({
                "scan_id": r[0],
                "file_name": r[1],
                "scanned_at": r[2],
                "model_version": r[3],
                "n_findings": r[4],
            })
        return scans
    finally:
        conn.close()
