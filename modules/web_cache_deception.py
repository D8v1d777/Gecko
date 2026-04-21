"""GECKO APOCALYPSE - Web Cache Deception Prober"""
import asyncio, aiohttp
from typing import List, Dict
from urllib.parse import urlparse

class WebCacheDeceptionProber:
    def __init__(self, session, config, db):
        self.session = session; self.config = config; self.db = db

    async def scan(self, url, content, headers, response):
        findings = []
        parsed = urlparse(url)
        if not parsed.path.endswith('/') and '.' not in parsed.path.split('/')[-1]:
            test_url = url + "/test.css"
            try:
                async with self.session.get(test_url, timeout=aiohttp.ClientTimeout(total=10)) as r:
                    h = str(r.headers).lower()
                    if r.status == 200 and 'hit' in h and ('x-cache' in h or 'cf-cache-status' in h):
                        findings.append({'type':'Web Cache Deception','severity':'HIGH','url':url,
                                'payload':test_url,'evidence':f'Response cached dynamically with static extension',
                                'remediation':'Configure cache to ignore files returning dynamic content types',
                                'cwe':'CWE-524'})
            except: pass
        return findings
