"""GECKO APOCALYPSE - Advanced Host Header Poisoning"""
import asyncio, aiohttp
from typing import List, Dict
from urllib.parse import urlparse

class HostHeaderPoisoning:
    def __init__(self, session, config, db):
        self.session = session; self.config = config; self.db = db

    async def scan(self, url, content, headers, response):
        findings = []
        parsed = urlparse(url)
        netloc = parsed.netloc
        
        poisoned_headers = [
            {'Host': f"{netloc}:@evil.com"},
            {'Host': f"evil.com#{netloc}"},
            {'Host': f"{netloc}", 'X-Forwarded-Host': 'evil.com', 'X-Forwarded-Server': 'evil.com'},
            {'Host': f"{netloc}", 'X-Host': 'evil.com'},
            {'Host': f"evil.com"}
        ]
        
        for h in poisoned_headers:
            try:
                async with self.session.get(url, headers=h, allow_redirects=False, timeout=aiohttp.ClientTimeout(total=10)) as r:
                    loc = r.headers.get('Location', '')
                    c = await r.text(errors='ignore')
                    
                    if 'evil.com' in loc or 'evil.com' in c:
                        findings.append({'type':'Advanced Host Header Poisoning','severity':'HIGH','url':url,
                                'evidence':f'Host header manipulation successful using headers: {h}. Reflected in: {"Location header" if "evil.com" in loc else "Response body"}',
                                'remediation':'Strictly validate the Host header and do not use it to generate absolute URLs or links',
                                'cwe':'CWE-20'})
                        break
            except: pass
            
        return findings
