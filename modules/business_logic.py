"""GECKO APOCALYPSE - Business Logic Tester (race conditions, price manipulation, workflow bypass, privilege escalation, referral gaming)"""

import asyncio
import re
import time
from typing import Dict, List, Optional
from urllib.parse import parse_qs, urlencode, urlparse

import aiohttp


class BusinessLogicTester:
    def __init__(self, session, config, db):
        self.session = session
        self.config = config
        self.db = db

    async def scan(self, url, content, headers, response):
        findings = []
        for t in [
            self._race_condition,
            self._price_manip,
            self._negative_qty,
            self._discount_abuse,
            self._workflow_bypass,
            self._privilege_esc,
        ]:
            r = await t(url, content)
            if r:
                findings.append(r)
        return findings

    async def _race_condition(self, url, content):
        if not any(
            k in url.lower()
            for k in [
                "checkout",
                "purchase",
                "redeem",
                "claim",
                "transfer",
                "vote",
                "like",
            ]
        ):
            return
        tasks = [
            self.session.post(url, timeout=aiohttp.ClientTimeout(total=10))
            for _ in range(10)
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        ok = sum(1 for r in results if hasattr(r, "status") and r.status == 200)
        if ok > 1:
            return {
                "type": "Race Condition",
                "severity": "HIGH",
                "url": url,
                "evidence": f"{ok}/10 concurrent requests succeeded",
                "remediation": "Implement proper locking/transactions",
                "cwe": "CWE-362",
                "owasp": "A04:2021",
            }

    async def _price_manip(self, url, content):
        params = parse_qs(urlparse(url).query)
        for k in params:
            if any(p in k.lower() for p in ["price", "amount", "total", "cost", "fee"]):
                for val in ["-100", "0", "0.01", "999999"]:
                    parsed = urlparse(url)
                    ps = parse_qs(parsed.query)
                    ps[k] = [val]
                    try:
                        async with self.session.get(
                            parsed._replace(query=urlencode(ps, doseq=True)).geturl(),
                            timeout=aiohttp.ClientTimeout(total=10),
                        ) as r:
                            if r.status == 200:
                                return {
                                    "type": "Price Manipulation",
                                    "severity": "CRITICAL",
                                    "url": url,
                                    "parameter": k,
                                    "payload": val,
                                    "evidence": f"Accepted value: {val}",
                                    "remediation": "Server-side price validation",
                                    "cwe": "CWE-20",
                                }
                    except:
                        pass

    async def _negative_qty(self, url, content):
        params = parse_qs(urlparse(url).query)
        for k in params:
            if any(
                q in k.lower() for q in ["qty", "quantity", "count", "amount", "num"]
            ):
                parsed = urlparse(url)
                ps = parse_qs(parsed.query)
                ps[k] = ["-999"]
                try:
                    async with self.session.get(
                        parsed._replace(query=urlencode(ps, doseq=True)).geturl(),
                        timeout=aiohttp.ClientTimeout(total=10),
                    ) as r:
                        if r.status == 200:
                            return {
                                "type": "Negative Quantity Bypass",
                                "severity": "HIGH",
                                "url": url,
                                "parameter": k,
                                "evidence": "Accepted negative quantity",
                                "cwe": "CWE-20",
                            }
                except:
                    pass

    async def _discount_abuse(self, url, content):
        if not any(
            k in url.lower() for k in ["coupon", "discount", "promo", "code", "voucher"]
        ):
            return
        # Test multiple application
        try:
            data = {"code": "TESTCODE", "coupon": "DISCOUNT"}
            async with self.session.post(
                url, data=data, timeout=aiohttp.ClientTimeout(total=10)
            ) as r1:
                async with self.session.post(
                    url, data=data, timeout=aiohttp.ClientTimeout(total=10)
                ) as r2:
                    if r1.status == 200 and r2.status == 200:
                        return {
                            "type": "Discount Code Reuse",
                            "severity": "MEDIUM",
                            "url": url,
                            "evidence": "Discount code applied multiple times",
                            "cwe": "CWE-799",
                        }
        except:
            pass

    async def _workflow_bypass(self, url, content):
        """Check if workflow steps can be skipped."""
        if not any(k in url.lower() for k in ["step", "wizard", "checkout", "process"]):
            return
        # Try to skip to final step
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        for k in params:
            if "step" in k.lower():
                params[k] = ["999"]
                try:
                    async with self.session.get(
                        parsed._replace(query=urlencode(params, doseq=True)).geturl(),
                        timeout=aiohttp.ClientTimeout(total=10),
                    ) as r:
                        if r.status == 200:
                            return {
                                "type": "Workflow Step Bypass",
                                "severity": "HIGH",
                                "url": url,
                                "evidence": "Skipped to final step",
                                "cwe": "CWE-841",
                            }
                except:
                    pass

    async def _privilege_esc(self, url, content):
        """Test for privilege escalation via parameter tampering."""
        params = parse_qs(urlparse(url).query)
        for k in params:
            if any(
                p in k.lower()
                for p in ["role", "user_type", "admin", "level", "access", "group"]
            ):
                for val in ["admin", "root", "superuser", "1"]:
                    parsed = urlparse(url)
                    ps = parse_qs(parsed.query)
                    ps[k] = [val]
                    try:
                        async with self.session.get(
                            parsed._replace(query=urlencode(ps, doseq=True)).geturl(),
                            timeout=aiohttp.ClientTimeout(total=10),
                        ) as r:
                            if r.status == 200:
                                return {
                                    "type": "Privilege Escalation",
                                    "severity": "CRITICAL",
                                    "url": url,
                                    "parameter": k,
                                    "payload": val,
                                    "cwe": "CWE-269",
                                }
                    except:
                        pass
