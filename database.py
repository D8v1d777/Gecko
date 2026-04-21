"""
GECKO APOCALYPSE - DATABASE MANAGER
Handles all persistence operations
"""

import sqlite3
import json
from typing import Dict, List, Optional
from datetime import datetime
from pathlib import Path


class DatabaseManager:
    """Centralized database operations."""
    
    def __init__(self, config: Dict):
        self.config = config
        db_path = config.get('sqlite_path', 'data/gecko_apocalypse.db')
        
        # Ensure directory exists
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._initialize_schema()
        
    def _initialize_schema(self):
        """Create database tables."""
        c = self.conn.cursor()
        
        # Findings table
        c.execute('''
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
                owasp TEXT,
                verified INTEGER DEFAULT 0,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Reconnaissance table
        c.execute('''
            CREATE TABLE IF NOT EXISTS reconnaissance (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT,
                data_type TEXT,
                data TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # URLs visited table
        c.execute('''
            CREATE TABLE IF NOT EXISTS urls_visited (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT UNIQUE,
                status_code INTEGER,
                content_type TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Scan metadata
        c.execute('''
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT,
                start_time DATETIME,
                end_time DATETIME,
                status TEXT,
                findings_count INTEGER DEFAULT 0
            )
        ''')
        
        self.conn.commit()
        
    def store_finding(self, finding: Dict):
        """Store a security finding."""
        c = self.conn.cursor()
        
        c.execute('''
            INSERT OR REPLACE INTO findings 
            (uid, type, severity, url, parameter, payload, evidence, description, remediation, cwe, owasp, verified)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            finding.get('uid', self._generate_uid(finding)),
            finding.get('type'),
            finding.get('severity'),
            finding.get('url'),
            finding.get('parameter'),
            finding.get('payload'),
            finding.get('evidence'),
            finding.get('description'),
            finding.get('remediation'),
            finding.get('cwe'),
            finding.get('owasp'),
            1 if finding.get('verified') else 0
        ))
        
        self.conn.commit()
        
    def store_reconnaissance(self, data: Dict):
        """Store reconnaissance data."""
        c = self.conn.cursor()
        
        for data_type, values in data.items():
            c.execute('''
                INSERT INTO reconnaissance (target, data_type, data)
                VALUES (?, ?, ?)
            ''', (
                data.get('target', 'unknown'),
                data_type,
                json.dumps(values)
            ))
            
        self.conn.commit()
        
    def get_all_findings(self) -> List[Dict]:
        """Retrieve all findings."""
        c = self.conn.cursor()
        c.execute('SELECT * FROM findings ORDER BY severity, timestamp DESC')
        
        findings = []
        for row in c.fetchall():
            findings.append(dict(row))
            
        return findings
        
    def get_findings_by_severity(self, severity: str) -> List[Dict]:
        """Get findings by severity level."""
        c = self.conn.cursor()
        c.execute('SELECT * FROM findings WHERE severity = ? ORDER BY timestamp DESC', (severity,))
        
        return [dict(row) for row in c.fetchall()]
        
    def get_statistics(self) -> Dict:
        """Get scan statistics."""
        c = self.conn.cursor()
        
        stats = {
            'total_findings': 0,
            'by_severity': {},
            'by_type': {},
            'verified_count': 0
        }
        
        # Count by severity
        c.execute('SELECT severity, COUNT(*) as count FROM findings GROUP BY severity')
        for row in c.fetchall():
            stats['by_severity'][row['severity']] = row['count']
            stats['total_findings'] += row['count']
            
        # Count by type
        c.execute('SELECT type, COUNT(*) as count FROM findings GROUP BY type ORDER BY count DESC LIMIT 10')
        for row in c.fetchall():
            stats['by_type'][row['type']] = row['count']
            
        # Verified count
        c.execute('SELECT COUNT(*) as count FROM findings WHERE verified = 1')
        stats['verified_count'] = c.fetchone()['count']
        
        return stats
        
    def _generate_uid(self, finding: Dict) -> str:
        """Generate unique ID for finding."""
        import hashlib
        key = f"{finding.get('type')}-{finding.get('url')}-{finding.get('parameter')}"
        return hashlib.md5(key.encode()).hexdigest()
        
    def close(self):
        """Close database connection."""
        self.conn.close()
