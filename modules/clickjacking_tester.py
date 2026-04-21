"""GECKO APOCALYPSE - Clickjacking Tester"""

import asyncio
from typing import Dict, List

import aiohttp


class ClickjackingTester:
    def __init__(self, session, config, db):
        self.session = session
        self.config = config
        self.db = db

    async def scan(self, url, content, headers, response):
        findings = []
        h = {k.lower(): v for k, v in headers.items()}

        xfo = h.get("x-frame-options", "").lower()
        csp = h.get("content-security-policy", "").lower()

        vulnerable = False
        if not xfo and "frame-ancestors" not in csp:
            vulnerable = True
        elif xfo == "allowall":
            vulnerable = True

        if vulnerable:
            findings.append(
                {
                    "type": "Clickjacking Vulnerability",
                    "severity": "MEDIUM",
                    "url": url,
                    "evidence": f"X-Frame-Options: {xfo}, CSP: {csp}",
                    "remediation": "Implement X-Frame-Options: DENY or SAMEORIGIN and CSP frame-ancestors",
                    "cwe": "CWE-1021",
                    "owasp": "A05:2021",
                }
            )

        return findings
