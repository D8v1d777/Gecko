"""GECKO APOCALYPSE - WebDAV Tester"""

import asyncio
from typing import Dict, List

import aiohttp


class WebDAVTester:
    def __init__(self, session, config, db):
        self.session = session
        self.config = config
        self.db = db

    async def scan(self, url, content, headers, response):
        findings = []
        try:
            async with self.session.request(
                "OPTIONS", url, timeout=aiohttp.ClientTimeout(total=10)
            ) as r:
                allow = r.headers.get("Allow", "").upper()
                dav = r.headers.get("DAV", "")

                if dav or any(
                    m in allow for m in ["PROPFIND", "PUT", "DELETE", "MOVE", "COPY"]
                ):
                    findings.append(
                        {
                            "type": "WebDAV Enabled",
                            "severity": "MEDIUM",
                            "url": url,
                            "evidence": f"Allow: {allow} | DAV: {dav}",
                            "remediation": "Disable WebDAV if not strictly required",
                            "cwe": "CWE-16",
                        }
                    )

                    if "PUT" in allow:
                        # Attempt to put a benign file
                        test_url = url.rstrip("/") + "/gecko_test.txt"
                        async with self.session.request(
                            "PUT",
                            test_url,
                            data="test",
                            timeout=aiohttp.ClientTimeout(total=10),
                        ) as put_r:
                            if put_r.status in [200, 201, 204]:
                                findings.append(
                                    {
                                        "type": "Insecure HTTP Method (PUT)",
                                        "severity": "HIGH",
                                        "url": test_url,
                                        "evidence": f"Successfully PUT a file. Status: {put_r.status}",
                                        "remediation": "Disable PUT method or enforce strict authentication",
                                        "cwe": "CWE-650",
                                    }
                                )
        except:
            pass
        return findings
