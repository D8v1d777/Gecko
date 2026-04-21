"""GECKO APOCALYPSE - WebSocket Security Tester (origin bypass, CSWSH, auth)"""

import asyncio
import re
from typing import Dict, List, Optional
from urllib.parse import urlparse

import aiohttp


class WebSocketTester:
    def __init__(self, session, config, db):
        self.session = session
        self.config = config
        self.db = db

    async def scan(self, url, content, headers, response):
        findings = []
        for ws_url in self._find_ws(url, content):
            r = await self._test_origin(ws_url)
            if r:
                findings.append(r)
            r2 = await self._test_unauth(ws_url)
            if r2:
                findings.append(r2)
        return findings

    def _find_ws(self, url, content):
        ws = set(re.findall(r'(wss?://[^\s"\'<>]+)', content))
        base = urlparse(url)
        for p in ["/ws", "/websocket", "/socket.io", "/sockjs", "/cable", "/hub"]:
            ws.add(f"ws://{base.netloc}{p}")
        return list(ws)

    async def _test_origin(self, ws_url):
        http_url = ws_url.replace("ws://", "http://").replace("wss://", "https://")
        try:
            h = {
                "Upgrade": "websocket",
                "Connection": "Upgrade",
                "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
                "Sec-WebSocket-Version": "13",
                "Origin": "https://evil.com",
            }
            async with self.session.get(
                http_url, headers=h, timeout=aiohttp.ClientTimeout(total=10)
            ) as r:
                if r.status == 101:
                    return {
                        "type": "WebSocket Origin Bypass",
                        "severity": "HIGH",
                        "url": ws_url,
                        "evidence": "WebSocket accepted from arbitrary origin",
                        "description": "Cross-Site WebSocket Hijacking possible",
                        "remediation": "Validate Origin header",
                        "cwe": "CWE-346",
                        "owasp": "A07:2021",
                    }
        except:
            pass

    async def _test_unauth(self, ws_url):
        http_url = ws_url.replace("ws://", "http://").replace("wss://", "https://")
        try:
            h = {
                "Upgrade": "websocket",
                "Connection": "Upgrade",
                "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
                "Sec-WebSocket-Version": "13",
            }
            async with self.session.get(
                http_url, headers=h, timeout=aiohttp.ClientTimeout(total=10)
            ) as r:
                if r.status == 101:
                    return {
                        "type": "WebSocket No Authentication",
                        "severity": "MEDIUM",
                        "url": ws_url,
                        "evidence": "WebSocket connection without auth",
                        "cwe": "CWE-306",
                    }
        except:
            pass
