"""GECKO APOCALYPSE - SAML Attacker"""
import asyncio, aiohttp, re, base64
from typing import List, Dict
from urllib.parse import urlparse, parse_qs

class SAMLAttacker:
    def __init__(self, session, config, db):
        self.session = session; self.config = config; self.db = db

    async def scan(self, url, content, headers, response):
        findings = []
        if 'SAMLResponse' in content or 'SAMLRequest' in content:
            # We don't actively attack unless we capture a SAML response,
            # but we can flag the endpoint.
            findings.append({'type':'SAML Endpoint Detected','severity':'INFO','url':url,
                             'evidence':'SAML keywords found in response','cwe':'CWE-284'})
        
        # Check URL parameters for SAML
        params = parse_qs(urlparse(url).query)
        if 'SAMLResponse' in params:
            saml_resp = params['SAMLResponse'][0]
            try:
                decoded = base64.b64decode(saml_resp).decode('utf-8', errors='ignore')
                if 'Signature' not in decoded:
                    findings.append({'type':'SAML Signature Missing','severity':'HIGH','url':url,
                                    'evidence':'SAML Response does not contain a Signature element',
                                    'remediation':'Ensure all SAML assertions are signed','cwe':'CWE-347'})
            except: pass
            
        return findings
