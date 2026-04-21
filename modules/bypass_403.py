"""GECKO APOCALYPSE - Bypass 403 / 401 Tester"""

import asyncio
from typing import Dict, List
from urllib.parse import urlparse

import aiohttp


class Bypass403:
    def __init__(self, session, config, db):
        self.session = session
        self.config = config
        self.db = db

    async def scan(self, url, content, headers, response):
        findings = []
        if response.status not in [401, 403]:
            return findings

        parsed = urlparse(url)
        path = parsed.path

        # Headers to spoof
        spoof_headers = [
            {"X-Original-URL": path},
            {"X-Rewrite-URL": path},
            {"X-Forwarded-For": "127.0.0.1"},
            {"X-Custom-IP-Authorization": "127.0.0.1"},
        ]

        for h in spoof_headers:
            try:
                async with self.session.get(
                    url, headers=h, timeout=aiohttp.ClientTimeout(total=10)
                ) as r:
                    if r.status == 200:
                        findings.append(
                            {
                                "type": "403/401 Bypass",
                                "severity": "HIGH",
                                "url": url,
                                "evidence": f"Bypassed restriction using header: {h}",
                                "remediation": "Do not trust client-controlled headers for access control",
                                "cwe": "CWE-284",
                            }
                        )
            except:
                pass

        # Path manipulation
        path_manipulations = [
            f"{path}/",
            f"{path}%2e",
            f"{path}/.",
            f"//.{path}",
            f"{path}%20",
        ]

        for p in path_manipulations:
            test_url = parsed._replace(path=p).geturl()
            try:
                async with self.session.get(
                    test_url, timeout=aiohttp.ClientTimeout(total=10)
                ) as r:
                    if r.status == 200:
                        findings.append(
                            {
                                "type": "403/401 Bypass (Path)",
                                "severity": "HIGH",
                                "url": url,
                                "evidence": f"Bypassed restriction using path: {p}",
                                "cwe": "CWE-284",
                            }
                        )
            except:
                pass

        return findings
