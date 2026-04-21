"""GECKO APOCALYPSE - Insecure Deserialization Attacker"""

import asyncio
from typing import Dict, List

import aiohttp


class DeserializationAttacker:
    def __init__(self, session, config, db):
        self.session = session
        self.config = config
        self.db = db

    async def scan(self, url, content, headers, response):
        findings = []
        cookies = headers.get("set-cookie", "")

        sigs = {
            "Java": ["rO0AB", "aced0005"],
            "PHP": ["O:", "a:", "s:"],
            "Python": ["gASV", "KVK"],
            ".NET": ["AAEAAAD/////"],
        }

        detected_techs = []
        for tech, patterns in sigs.items():
            for p in patterns:
                if p in cookies or p in content:
                    detected_techs.append(tech)
                    break

        if detected_techs:
            findings.append(
                {
                    "type": "Potential Insecure Deserialization",
                    "severity": "HIGH",
                    "url": url,
                    "evidence": f'Found serialized signatures for: {", ".join(detected_techs)}',
                    "remediation": "Do not deserialize untrusted data or use safe serialization formats like JSON",
                    "cwe": "CWE-502",
                    "owasp": "A08:2021",
                }
            )

        return findings
