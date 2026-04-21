"""GECKO APOCALYPSE - Client-Side Template Injection (CSTI) Tester"""
import asyncio, aiohttp, re
from typing import List, Dict
from urllib.parse import urlparse, parse_qs, urlencode

class CSTITester:
    def __init__(self, session, config, db):
        self.session = session; self.config = config; self.db = db

    async def scan(self, url, content, headers, response):
        findings = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        # We look for frameworks like Angular or Vue.js in the content
        is_angular = 'ng-app' in content or 'angular' in content.lower()
        is_vue = 'vue' in content.lower()
        
        if not (is_angular or is_vue):
            return findings
            
        payloads = []
        if is_angular:
            payloads.append("{{$on.constructor('alert(\"CSTI\")')()}}")
            payloads.append("{{constructor.constructor('alert(1)')()}}")
        if is_vue:
            payloads.append("{{constructor.constructor('alert(\"CSTI\")')()}}")
            
        for param in params:
            for p in payloads:
                test = self._inject(url, param, p)
                try:
                    async with self.session.get(test, timeout=aiohttp.ClientTimeout(total=10)) as r:
                        c = await r.text(errors='ignore')
                        if p in c:
                            findings.append({'type':'Client-Side Template Injection (CSTI)','severity':'HIGH','url':url,
                                    'parameter':param,'payload':p,'evidence':'Template injection payload reflected directly into the DOM',
                                    'remediation':'Avoid using server-side input directly in client-side templates, use v-pre or ng-non-bindable','cwe':'CWE-94'})
                            break
                except: pass
                
        return findings

    def _inject(self, url, param, value):
        parsed = urlparse(url); params = parse_qs(parsed.query)
        params[param] = [value]
        return parsed._replace(query=urlencode(params, doseq=True)).geturl()
