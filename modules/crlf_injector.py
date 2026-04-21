"""GECKO APOCALYPSE - CRLF Injector (HTTP Response Splitting)"""

import asyncio
from typing import Dict, List
from urllib.parse import parse_qs, urlencode, urlparse

import aiohttp


class CRLFInjector:
    def __init__(self, session, config, db):
        self.session = session
        self.config = config
        self.db = db

    async def scan(self, url, content, headers, response):
        findings = []
        params = parse_qs(urlparse(url).query)
        payloads = [
            "%0d%0aSet-Cookie:crlf=injection",
            "%0aSet-Cookie:crlf=injection",
            "%0d%0a%0d%0a<script>alert('crlf')</script>",
            "\\r\\nSet-Cookie:crlf=injection",
        ]

        for param in params:
            for p in payloads:
                test = self._inject(url, param, p)
                try:
                    async with self.session.get(
                        test,
                        allow_redirects=False,
                        timeout=aiohttp.ClientTimeout(total=10),
                    ) as r:
                        if "crlf=injection" in r.headers.get("Set-Cookie", ""):
                            findings.append(
                                {
                                    "type": "CRLF Injection (HTTP Response Splitting)",
                                    "severity": "HIGH",
                                    "url": url,
                                    "parameter": param,
                                    "payload": p,
                                    "evidence": "Injected Set-Cookie header found in response",
                                    "remediation": "Sanitize carriage return and line feed characters in user input",
                                    "cwe": "CWE-113",
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
