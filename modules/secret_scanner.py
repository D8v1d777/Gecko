"""GECKO APOCALYPSE - Secret Scanner (API keys, tokens, credentials, entropy analysis)"""

import math
import re
from typing import Dict, List


class SecretScanner:
    def __init__(self, session, config, db):
        self.session = session
        self.config = config
        self.db = db
        self.patterns = {
            "AWS Access Key": r"AKIA[0-9A-Z]{16}",
            "AWS Secret Key": r'aws(.{0,20})?[\'""][0-9a-zA-Z\/+]{40}[\'""]',
            "GitHub Token": r"ghp_[a-zA-Z0-9]{36}",
            "GitHub OAuth": r"gho_[a-zA-Z0-9]{36}",
            "GitLab Token": r"glpat-[a-zA-Z0-9_-]{20}",
            "SendGrid Key": r"SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}",
            "Slack Token": r"xox[baprs]-[0-9]{10,12}-[0-9]{10,12}-[a-zA-Z0-9]{24,32}",
            "Slack Webhook": r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+",
            "Private Key": r"-----BEGIN (RSA|EC|DSA|OPENSSH|PGP) PRIVATE KEY-----",
            "Google API Key": r"AIza[0-9A-Za-z\\-_]{35}",
            "Stripe Live Key": r"sk_live_[0-9a-zA-Z]{24}",
            "Stripe Publishable": r"pk_live_[0-9a-zA-Z]{24}",
            "Twilio Key": r"SK[0-9a-fA-F]{32}",
            "Mailgun Key": r"key-[0-9a-zA-Z]{32}",
            "Database URL": r'(mysql|postgres|mongodb|redis|amqp)://[^\s<>"\']+',
            "Discord Webhook": r"https://discord\.com/api/webhooks/[0-9]+/[a-zA-Z0-9_-]+",
            "Heroku API Key": r"[hH][eE][rR][oO][kK][uU].{0,30}[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}",
            "Firebase URL": r"https://[a-z0-9-]+\.firebaseio\.com",
            "Generic API Key": r'api[_-]?key["\s:=]+["\']?[a-zA-Z0-9_-]{20,}["\']?',
            "Generic Secret": r'secret["\s:=]+["\']?[a-zA-Z0-9_-]{20,}["\']?',
            "Bearer Token": r"[Bb]earer\s+[a-zA-Z0-9_-]{20,}",
        }

    async def scan(self, url, content, headers, response):
        findings = []
        for stype, pattern in self.patterns.items():
            for m in set(re.findall(pattern, content, re.IGNORECASE)):
                val = m if isinstance(m, str) else m[0]
                ent = self._entropy(val)
                if ent > 3.0 or stype in [
                    "Private Key",
                    "Database URL",
                    "Firebase URL",
                ]:
                    sev = (
                        "CRITICAL"
                        if stype
                        in [
                            "AWS Access Key",
                            "Private Key",
                            "Database URL",
                            "Stripe Live Key",
                        ]
                        else (
                            "HIGH"
                            if stype
                            in [
                                "GitHub Token",
                                "SendGrid Key",
                                "Slack Token",
                                "Google API Key",
                            ]
                            else "MEDIUM"
                        )
                    )
                    findings.append(
                        {
                            "type": f"Exposed Secret: {stype}",
                            "severity": sev,
                            "url": url,
                            "evidence": (val[:50] + "..." if len(val) > 50 else val),
                            "description": f"{stype} exposed",
                            "remediation": "Remove and rotate credentials",
                            "cwe": "CWE-200",
                            "owasp": "A01:2021",
                        }
                    )
        return findings

    def _entropy(self, data):
        if not data:
            return 0
        return -sum(
            data.count(c) / len(data) * math.log2(data.count(c) / len(data))
            for c in set(data)
        )
