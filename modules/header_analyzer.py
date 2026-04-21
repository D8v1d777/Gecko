"""GECKO APOCALYPSE - Security Header Analyzer (CSP, HSTS, SRI, Permissions-Policy, Feature-Policy)"""
import re
from typing import List, Dict

class HeaderAnalyzer:
    def __init__(self, session, config, db):
        self.session = session; self.config = config; self.db = db

    async def scan(self, url, content, headers, response):
        findings = []
        h = {k.lower(): v for k, v in headers.items()}

        # Missing security headers
        checks = {
            'strict-transport-security': ('MEDIUM', 'HSTS not set', 'Add Strict-Transport-Security header'),
            'x-frame-options': ('MEDIUM', 'Clickjacking possible', 'Add X-Frame-Options: DENY'),
            'x-content-type-options': ('LOW', 'MIME sniffing possible', 'Add X-Content-Type-Options: nosniff'),
            'content-security-policy': ('HIGH', 'No CSP protection', 'Implement Content-Security-Policy'),
            'referrer-policy': ('LOW', 'Referrer leakage', 'Add Referrer-Policy: strict-origin'),
            'permissions-policy': ('LOW', 'No permissions policy', 'Add Permissions-Policy header'),
            'x-xss-protection': ('LOW', 'XSS filter not set', 'Add X-XSS-Protection: 1; mode=block'),
            'cross-origin-opener-policy': ('LOW', 'No COOP', 'Add Cross-Origin-Opener-Policy'),
            'cross-origin-resource-policy': ('LOW', 'No CORP', 'Add Cross-Origin-Resource-Policy'),
        }
        for header, (sev, desc, rem) in checks.items():
            if header not in h:
                findings.append({'type':'Missing Security Header','severity':sev,'url':url,
                                'evidence':f'Missing: {header}','description':desc,
                                'remediation':rem,'cwe':'CWE-16','owasp':'A05:2021'})

        # CSP analysis
        csp = h.get('content-security-policy','')
        if csp:
            if 'unsafe-inline' in csp:
                findings.append({'type':'CSP Allows unsafe-inline','severity':'MEDIUM','url':url,
                                'evidence':f'CSP: {csp[:200]}','remediation':'Remove unsafe-inline, use nonces','cwe':'CWE-16'})
            if 'unsafe-eval' in csp:
                findings.append({'type':'CSP Allows unsafe-eval','severity':'MEDIUM','url':url,
                                'evidence':f'CSP: {csp[:200]}','remediation':'Remove unsafe-eval','cwe':'CWE-16'})
            if "'none'" not in csp and 'default-src' not in csp:
                findings.append({'type':'CSP Missing default-src','severity':'LOW','url':url,
                                'evidence':'No default-src directive','cwe':'CWE-16'})

        # HSTS analysis
        hsts = h.get('strict-transport-security','')
        if hsts:
            if 'includeSubDomains' not in hsts:
                findings.append({'type':'HSTS Missing includeSubDomains','severity':'LOW','url':url,
                                'evidence':f'HSTS: {hsts}','cwe':'CWE-16'})
            if 'preload' not in hsts:
                findings.append({'type':'HSTS Not Preloaded','severity':'INFO','url':url,
                                'evidence':f'HSTS: {hsts}','remediation':'Add preload directive'})
            ma = re.search(r'max-age=(\d+)', hsts)
            if ma and int(ma.group(1)) < 31536000:
                findings.append({'type':'HSTS Short max-age','severity':'LOW','url':url,
                                'evidence':f'max-age={ma.group(1)} (<1 year)','cwe':'CWE-16'})

        # SRI check in HTML
        scripts = re.findall(r'<script[^>]*src=["\']([^"\']+)["\'][^>]*>', content)
        for script in scripts:
            if ('cdn' in script or 'unpkg' in script or 'jsdelivr' in script):
                tag = re.search(rf'<script[^>]*src=["\']({re.escape(script)})["\'][^>]*>', content)
                if tag and 'integrity=' not in tag.group(0):
                    findings.append({'type':'Missing SRI','severity':'MEDIUM','url':url,
                                    'evidence':f'External script without integrity: {script}',
                                    'remediation':'Add integrity attribute to external scripts','cwe':'CWE-353'})
                    break

        return findings
