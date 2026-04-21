"""GECKO APOCALYPSE - API Fuzzer (BOLA/IDOR, mass assignment, rate limiting, versioning, data exposure)"""
import asyncio, aiohttp, re, json, time
from typing import List, Dict, Optional
from urllib.parse import urlparse, parse_qs, urlencode

class APIFuzzer:
    def __init__(self, session, config, db):
        self.session = session; self.config = config; self.db = db

    async def scan(self, url, content, headers, response):
        findings = []
        if not self._is_api(url, headers): return findings
        for t in [self._bola, self._mass_assign, self._rate_limit, self._version_bypass,
                   self._data_exposure, self._method_enum]:
            r = await t(url, content, headers)
            if r: findings.append(r) if isinstance(r, dict) else findings.extend(r)
        return findings

    def _is_api(self, url, headers):
        return any(['/api/' in url, '/v1/' in url, '/v2/' in url, '/v3/' in url,
                     'application/json' in headers.get('content-type',''),
                     'graphql' in url.lower(), '/rest/' in url])

    async def _bola(self, url, content, headers):
        ids = re.findall(r'/(\d+)(?:/|$|\?)', url)
        if not ids: return
        oid = ids[0]
        for tid in [str(int(oid)+1), str(int(oid)-1), '1', '999999']:
            try:
                async with self.session.get(url.replace(f'/{oid}', f'/{tid}'), timeout=aiohttp.ClientTimeout(total=10)) as r:
                    if r.status == 200:
                        return {'type':'BOLA/IDOR Vulnerability','severity':'CRITICAL','url':url,'payload':tid,
                                'evidence':f'Accessed object {tid} without auth',
                                'remediation':'Implement authorization checks','cwe':'CWE-639','owasp':'API1:2023'}
            except: pass

    async def _mass_assign(self, url, content, headers):
        fields = {'is_admin':True,'role':'admin','admin':True,'verified':True,'premium':True,'balance':99999}
        try:
            async with self.session.post(url, json=fields, timeout=aiohttp.ClientTimeout(total=10)) as r:
                if r.status in [200,201]:
                    c = await r.text(errors='ignore')
                    if any(f in c for f in fields): 
                        return {'type':'Mass Assignment','severity':'HIGH','url':url,
                                'evidence':'API accepted unauthorized fields',
                                'remediation':'Whitelist allowed fields','cwe':'CWE-915','owasp':'API6:2023'}
        except: pass

    async def _rate_limit(self, url, content, headers):
        """Test API rate limiting."""
        success = 0
        for _ in range(20):
            try:
                async with self.session.get(url, timeout=aiohttp.ClientTimeout(total=5)) as r:
                    if r.status == 200: success += 1
                    elif r.status == 429: return  # Rate limited properly
            except: pass
        if success >= 18:
            return {'type':'API No Rate Limiting','severity':'MEDIUM','url':url,
                    'evidence':f'{success}/20 requests succeeded without rate limiting',
                    'remediation':'Implement rate limiting','cwe':'CWE-770','owasp':'API4:2023'}

    async def _version_bypass(self, url, content, headers):
        """Try accessing older API versions."""
        findings = []
        parsed = urlparse(url)
        for old_v in ['/v1/','/v0/','/v2/','/api/internal/','/api/debug/','/api/test/']:
            test = re.sub(r'/v\d+/', old_v, url)
            if test == url: continue
            try:
                async with self.session.get(test, timeout=aiohttp.ClientTimeout(total=10)) as r:
                    if r.status == 200:
                        findings.append({'type':'API Version Bypass','severity':'MEDIUM','url':test,
                                        'evidence':f'Older/internal API version accessible',
                                        'remediation':'Deprecate and disable old API versions','cwe':'CWE-1059'})
                        break
            except: pass
        return findings

    async def _data_exposure(self, url, content, headers):
        """Check for excessive data exposure."""
        try:
            async with self.session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as r:
                if r.status == 200:
                    c = await r.text(errors='ignore')
                    sensitive = ['password','secret','token','ssn','credit_card','api_key','private_key']
                    found = [s for s in sensitive if s in c.lower()]
                    if found:
                        return {'type':'Excessive Data Exposure','severity':'HIGH','url':url,
                                'evidence':f'Sensitive fields: {", ".join(found)}',
                                'remediation':'Filter response data','cwe':'CWE-213','owasp':'API3:2023'}
        except: pass

    async def _method_enum(self, url, content, headers):
        """Test HTTP method enumeration."""
        dangerous = []
        for method in ['PUT','DELETE','PATCH','TRACE','OPTIONS']:
            try:
                async with self.session.request(method, url, timeout=aiohttp.ClientTimeout(total=5)) as r:
                    if r.status not in [404,405,501]:
                        dangerous.append(method)
            except: pass
        if 'TRACE' in dangerous:
            return {'type':'HTTP TRACE Method Enabled','severity':'MEDIUM','url':url,
                    'evidence':f'Dangerous methods: {", ".join(dangerous)}',
                    'remediation':'Disable unnecessary HTTP methods','cwe':'CWE-16'}
