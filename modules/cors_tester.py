"""GECKO APOCALYPSE - CORS Misconfiguration Tester"""

import asyncio
from typing import Dict, List, Optional
from urllib.parse import urlparse

import aiohttp


class CORSTester:
    def __init__(self, session, config, db):
        self.session = session
        self.config = config
        self.db = db

    async def scan(self, url, content, headers, response):
        findings = []
        netloc = urlparse(url).netloc
        origins = [
            "null",
            "https://evil.com",
            f"https://evil.{netloc}",
            f"https://{netloc}.evil.com",
            f"http://{netloc}",
            f"https://{netloc}%60.evil.com",
            f"https://{netloc}_.evil.com",
        ]
        for origin in origins:
            r = await self._test(url, origin)
            if r:
                findings.append(r)
        return findings

    async def _test(self, url, origin):
        try:
            async with self.session.get(
                url, headers={"Origin": origin}, timeout=aiohttp.ClientTimeout(total=10)
            ) as r:
                acao = r.headers.get("Access-Control-Allow-Origin", "")
                acac = r.headers.get("Access-Control-Allow-Credentials", "")
                if acao == origin and acac == "true":
                    sev = (
                        "CRITICAL" if origin in ["null", "https://evil.com"] else "HIGH"
                    )
                    return {
                        "type": "CORS Misconfiguration",
                        "severity": sev,
                        "url": url,
                        "evidence": f"ACAO: {acao}, ACAC: {acac}",
                        "payload": origin,
                        "description": f'CORS reflects origin "{origin}" with credentials',
                        "remediation": "Strict origin whitelist",
                        "cwe": "CWE-942",
                        "owasp": "A05:2021",
                    }
                if acao == "*" and acac == "true":
                    return {
                        "type": "CORS Wildcard with Credentials",
                        "severity": "HIGH",
                        "url": url,
                        "evidence": "ACAO: *, ACAC: true",
                        "cwe": "CWE-942",
                    }
        except:
            pass
