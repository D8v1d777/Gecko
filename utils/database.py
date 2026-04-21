"""
GECKO APOCALYPSE - DATABASE MANAGER
Complete persistence layer with SQLite, deduplication, and statistics.
"""

import hashlib
import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional


class DatabaseManager:
    """Centralized database operations with deduplication."""

    def __init__(self, config: Dict):
        self.config = config
        db_path = config.get("sqlite_path", "data/gecko_apocalypse.db")
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._initialize_schema()

    def _initialize_schema(self):
        """Create database tables."""
        c = self.conn.cursor()

        c.execute("""
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                uid TEXT UNIQUE,
                type TEXT,
                severity TEXT,
                url TEXT,
                parameter TEXT,
                payload TEXT,
                evidence TEXT,
                description TEXT,
                remediation TEXT,
                cwe TEXT,
                cvss_score REAL,
                cvss_vector TEXT,
                owasp TEXT,
                compliance_flags TEXT,
                verified INTEGER DEFAULT 0,
                false_positive INTEGER DEFAULT 0,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)

        c.execute("""
            CREATE TABLE IF NOT EXISTS reconnaissance (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT,
                data_type TEXT,
                data TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)

        c.execute("""
            CREATE TABLE IF NOT EXISTS urls_visited (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT UNIQUE,
                status_code INTEGER,
                content_type TEXT,
                content_length INTEGER,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)

        c.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT UNIQUE,
                target TEXT,
                start_time DATETIME,
                end_time DATETIME,
                status TEXT,
                findings_count INTEGER DEFAULT 0,
                config_snapshot TEXT
            )
        """)

        c.execute("""
            CREATE TABLE IF NOT EXISTS checkpoints (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT,
                data TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)

        self.conn.commit()

    def store_finding(self, finding: Dict):
        """Store a security finding with deduplication."""
        uid = finding.get("uid", self._generate_uid(finding))

        # Check for duplicates
        c = self.conn.cursor()
        c.execute("SELECT id FROM findings WHERE uid = ?", (uid,))
        if c.fetchone():
            return  # Deduplicated

        compliance = json.dumps(finding.get("compliance_flags", []))

        c.execute(
            """
            INSERT OR IGNORE INTO findings
            (uid, type, severity, url, parameter, payload, evidence,
             description, remediation, cwe, cvss_score, cvss_vector, owasp,
             compliance_flags, verified)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
            (
                uid,
                finding.get("type"),
                finding.get("severity"),
                finding.get("url"),
                finding.get("parameter"),
                finding.get("payload"),
                finding.get("evidence"),
                finding.get("description"),
                finding.get("remediation"),
                finding.get("cwe"),
                finding.get("cvss_score", 0.0),
                finding.get("cvss_vector", ""),
                finding.get("owasp"),
                compliance,
                1 if finding.get("verified") else 0,
            ),
        )
        self.conn.commit()

    def store_reconnaissance(self, data: Dict):
        """Store reconnaissance data."""
        c = self.conn.cursor()
        target = data.pop("target", "unknown")
        for data_type, values in data.items():
            c.execute(
                """
                INSERT INTO reconnaissance (target, data_type, data)
                VALUES (?, ?, ?)
            """,
                (target, data_type, json.dumps(values, default=str)),
            )
        self.conn.commit()

    def store_url(
        self,
        url: str,
        status_code: int = 0,
        content_type: str = "",
        content_length: int = 0,
    ):
        """Store visited URL."""
        c = self.conn.cursor()
        c.execute(
            """
            INSERT OR IGNORE INTO urls_visited (url, status_code, content_type, content_length)
            VALUES (?, ?, ?, ?)
        """,
            (url, status_code, content_type, content_length),
        )
        self.conn.commit()

    def get_all_findings(self) -> List[Dict]:
        """Retrieve all findings."""
        c = self.conn.cursor()
        c.execute("SELECT * FROM findings ORDER BY severity, timestamp DESC")
        return [dict(row) for row in c.fetchall()]

    def get_findings_by_severity(self, severity: str) -> List[Dict]:
        """Get findings by severity level."""
        c = self.conn.cursor()
        c.execute(
            "SELECT * FROM findings WHERE severity = ? ORDER BY timestamp DESC",
            (severity,),
        )
        return [dict(row) for row in c.fetchall()]

    def get_statistics(self) -> Dict:
        """Get scan statistics."""
        c = self.conn.cursor()
        stats = {
            "total_findings": 0,
            "by_severity": {},
            "by_type": {},
            "verified_count": 0,
            "false_positives": 0,
        }

        c.execute(
            "SELECT severity, COUNT(*) as count FROM findings WHERE false_positive = 0 GROUP BY severity"
        )
        for row in c.fetchall():
            stats["by_severity"][row["severity"]] = row["count"]
            stats["total_findings"] += row["count"]

        c.execute(
            "SELECT type, COUNT(*) as count FROM findings WHERE false_positive = 0 GROUP BY type ORDER BY count DESC LIMIT 20"
        )
        for row in c.fetchall():
            stats["by_type"][row["type"]] = row["count"]

        c.execute("SELECT COUNT(*) as count FROM findings WHERE verified = 1")
        stats["verified_count"] = c.fetchone()["count"]

        c.execute("SELECT COUNT(*) as count FROM findings WHERE false_positive = 1")
        stats["false_positives"] = c.fetchone()["count"]

        return stats

    def store_checkpoint(self, scan_id: str, data: Dict):
        """Store scan checkpoint for resume."""
        c = self.conn.cursor()
        c.execute(
            """
            INSERT INTO checkpoints (scan_id, data) VALUES (?, ?)
        """,
            (scan_id, json.dumps(data, default=str)),
        )
        self.conn.commit()

    def get_latest_checkpoint(self, scan_id: str) -> Optional[Dict]:
        """Get latest checkpoint for resuming."""
        c = self.conn.cursor()
        c.execute(
            """
            SELECT data FROM checkpoints WHERE scan_id = ?
            ORDER BY timestamp DESC LIMIT 1
        """,
            (scan_id,),
        )
        row = c.fetchone()
        if row:
            return json.loads(row["data"])
        return None

    def _generate_uid(self, finding: Dict) -> str:
        """Generate unique ID for finding deduplication."""
        key = f"{finding.get('type')}-{finding.get('url')}-{finding.get('parameter')}-{finding.get('payload', '')}"
        return hashlib.md5(key.encode()).hexdigest()

    def store_scan_metadata(self, scan_id: str, target: str, config_snapshot: str):
        """Store metadata for a new scan session."""
        c = self.conn.cursor()
        c.execute(
            """
            INSERT INTO scans (scan_id, target, start_time, status, config_snapshot)
            VALUES (?, ?, ?, ?, ?)
        """,
            (scan_id, target, datetime.utcnow(), "RUNNING", config_snapshot),
        )
        self.conn.commit()

    def close(self):
        """Close database connection."""
        self.conn.close()
