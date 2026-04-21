"""GECKO APOCALYPSE - HTTP Request Smuggling + Host Header Injection"""
import asyncio, aiohttp, socket, time
from typing import List, Dict, Optional
from urllib.parse import urlparse

class HTTPSmuggler:
    def __init__(self, session, config, db):
        self.session = session; self.config = config; self.db = db

    async def scan(self, url, content, headers, response):
        findings = []
        # Host Header Injection
        r = await self._host_header_injection(url)
        if r: findings.append(r)
        # CL.TE detection
        r2 = await self._test_cl_te(url)
        if r2: findings.append(r2)
        # TE.CL detection
        r3 = await self._test_te_cl(url)
        if r3: findings.append(r3)
        return findings

    async def _host_header_injection(self, url):
        """Test Host header injection."""
        tests = [
            {'Host': 'evil.com'},
            {'Host': urlparse(url).netloc, 'X-Forwarded-Host': 'evil.com'},
            {'Host': urlparse(url).netloc, 'X-Host': 'evil.com'},
            {'Host': urlparse(url).netloc, 'X-Original-URL': '/admin'},
            {'Host': urlparse(url).netloc, 'X-Rewrite-URL': '/admin'},
        ]
        for h in tests:
            try:
                async with self.session.get(url, headers=h, timeout=aiohttp.ClientTimeout(total=10), allow_redirects=False) as r:
                    body = await r.text(errors='ignore')
                    loc = r.headers.get('Location','')
                    if 'evil.com' in loc or 'evil.com' in body:
                        return {'type':'Host Header Injection','severity':'HIGH','url':url,
                                'evidence':f'Host reflected: {loc or body[:200]}',
                                'remediation':'Validate Host header, use server-side URL generation',
                                'cwe':'CWE-644','owasp':'A05:2021'}
            except: pass

    async def _test_cl_te(self, url):
        """Test CL.TE smuggling (simplified via aiohttp)."""
        parsed = urlparse(url)
        try:
            body = "0\r\n\r\nGPOST / HTTP/1.1\r\nHost: " + parsed.netloc + "\r\n\r\n"
            h = {'Content-Length': str(len(body)), 'Transfer-Encoding': 'chunked'}
            t = time.time()
            async with self.session.post(url, data=body, headers=h, timeout=aiohttp.ClientTimeout(total=15)) as r:
                el = time.time() - t
                if el > 5:
                    return {'type':'HTTP Request Smuggling (CL.TE)','severity':'CRITICAL','url':url,
                            'evidence':f'Response delayed {el:.1f}s','cwe':'CWE-444','owasp':'A05:2021',
                            'remediation':'Normalize frontend/backend Transfer-Encoding handling'}
        except: pass

    async def _test_te_cl(self, url):
        """Test TE.CL smuggling."""
        parsed = urlparse(url)
        try:
            body = "1\r\nZ\r\nQ\r\n\r\n"
            h = {'Transfer-Encoding': 'chunked', 'Content-Length': '5'}
            t = time.time()
            async with self.session.post(url, data=body, headers=h, timeout=aiohttp.ClientTimeout(total=15)) as r:
                el = time.time() - t
                if el > 5:
                    return {'type':'HTTP Request Smuggling (TE.CL)','severity':'CRITICAL','url':url,
                            'evidence':f'Response delayed {el:.1f}s','cwe':'CWE-444'}
        except: pass
