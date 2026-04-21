"""GECKO APOCALYPSE - HTTP Parameter Pollution Tester"""

import asyncio
from typing import Dict, List
from urllib.parse import parse_qs, urlencode, urlparse

import aiohttp


class HPPTester:
    def __init__(self, session, config, db):
        self.session = session
        self.config = config
        self.db = db

    async def scan(self, url, content, headers, response):
        findings = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        if not params:
            return findings

        for param in params:
            # Create a polluted URL: ?param=original&param=polluted
            polluted_params = list(parsed.query.split("&"))
            polluted_params.append(f"{param}=gecko_hpp_test")
            polluted_query = "&".join(polluted_params)

            test_url = parsed._replace(query=polluted_query).geturl()

            try:
                async with self.session.get(
                    test_url, timeout=aiohttp.ClientTimeout(total=10)
                ) as r:
                    c = await r.text(errors="ignore")
                    if "gecko_hpp_test" in c:
                        findings.append(
                            {
                                "type": "HTTP Parameter Pollution",
                                "severity": "MEDIUM",
                                "url": url,
                                "parameter": param,
                                "evidence": "Application reflects the second (polluted) parameter",
                                "remediation": "Strictly validate and extract the first or last parameter consistently",
                                "cwe": "CWE-235",
                            }
                        )
                        break
            except:
                pass

        return findings
