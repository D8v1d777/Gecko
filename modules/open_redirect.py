"""GECKO APOCALYPSE - Advanced Open Redirect Tester"""

import asyncio
from typing import Dict, List
from urllib.parse import parse_qs, urlencode, urlparse

import aiohttp


class OpenRedirect:
    def __init__(self, session, config, db):
        self.session = session
        self.config = config
        self.db = db

    async def scan(self, url, content, headers, response):
        findings = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        payloads = [
            "https://evil.com",
            "//evil.com",
            "\\\\evil.com",
            "https:evil.com",
            "http://legit.com.evil.com",
            "http://evil.com#legit.com",
            "http://evil.com?legit.com",
            "/%09/evil.com",
            "/%5c/evil.com",
        ]

        for param in params:
            # Heuristic to save requests: only test params that look like destinations
            if not any(
                k in param.lower()
                for k in ["url", "redirect", "next", "return", "dest", "goto"]
            ):
                continue

            for p in payloads:
                test = self._inject(url, param, p)
                try:
                    async with self.session.get(
                        test,
                        allow_redirects=False,
                        timeout=aiohttp.ClientTimeout(total=10),
                    ) as r:
                        loc = r.headers.get("Location", "")
                        if "evil.com" in loc:
                            findings.append(
                                {
                                    "type": "Open Redirect",
                                    "severity": "MEDIUM",
                                    "url": url,
                                    "parameter": param,
                                    "payload": p,
                                    "evidence": f"Server redirected to: {loc}",
                                    "cwe": "CWE-601",
                                    "owasp": "A01:2021",
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
