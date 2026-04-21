"""GECKO APOCALYPSE - WAF Detector (Web Application Firewall Detection)"""
import asyncio, aiohttp
from typing import List, Dict

class WAFDetector:
    def __init__(self, session, config, db):
        self.session = session; self.config = config; self.db = db

    async def scan(self, url, content, headers, response):
        findings = []
        payload = "<script>alert('WAF-Test')</script> OR 1=1"
        try:
            async with self.session.get(url, params={"waf_test": payload}, timeout=aiohttp.ClientTimeout(total=10)) as r:
                if r.status in [403, 406, 501]:
                    c = await r.text(errors='ignore')
                    h = str(r.headers).lower()
                    waf_name = "Unknown WAF"
                    sigs = {
                        'Cloudflare': ['cloudflare', 'cf-ray'],
                        'AWS WAF': ['x-amzn-requestid', 'awselb'],
                        'Akamai': ['akamai', 'x-akamai'],
                        'Imperva': ['imperva', 'incapsula'],
                        'F5 BIG-IP': ['bigip', 'f5'],
                        'ModSecurity': ['mod_security'],
                        'Sucuri': ['sucuri']
                    }
                    for k, v in sigs.items():
                        if any(s in h or s in c.lower() for s in v):
                            waf_name = k
                            break
                    findings.append({'type':'WAF Detected','severity':'INFO','url':url,
                            'evidence':f'WAF identified as {waf_name} due to blocking payload with {r.status}',
                            'cwe':'CWE-200'})
        except: pass
        return findings
