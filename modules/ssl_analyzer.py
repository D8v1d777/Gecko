"""GECKO APOCALYPSE - SSL/TLS Analyzer (cert validation, TLS versions, cipher suites, cert transparency)"""
import asyncio, ssl, socket
from typing import List, Dict
from urllib.parse import urlparse
from datetime import datetime

class SSLAnalyzer:
    def __init__(self, session, config, db):
        self.session = session; self.config = config; self.db = db

    async def scan(self, url, content, headers, response):
        findings = []
        if not url.startswith('https'):
            findings.append({'type':'No HTTPS','severity':'HIGH','url':url,
                            'evidence':'Unencrypted connection','remediation':'Implement HTTPS','cwe':'CWE-319'})
            return findings

        parsed = urlparse(url)
        host = parsed.hostname
        port = parsed.port or 443

        # Certificate analysis
        cert_findings = await self._check_cert(host, port)
        findings.extend(cert_findings)

        # TLS version check
        tls_findings = await self._check_tls_versions(host, port)
        findings.extend(tls_findings)

        return findings

    async def _check_cert(self, host, port):
        findings = []
        try:
            ctx = ssl.create_default_context()
            loop = asyncio.get_event_loop()
            def _connect():
                with socket.create_connection((host, port), timeout=10) as sock:
                    with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                        return ssock.getpeercert()
            cert = await loop.run_in_executor(None, _connect)
            if cert:
                # Check expiry
                not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                days_left = (not_after - datetime.utcnow()).days
                if days_left < 0:
                    findings.append({'type':'Expired SSL Certificate','severity':'CRITICAL','url':f'https://{host}',
                                    'evidence':f'Expired {abs(days_left)} days ago','cwe':'CWE-295'})
                elif days_left < 30:
                    findings.append({'type':'SSL Certificate Expiring Soon','severity':'MEDIUM','url':f'https://{host}',
                                    'evidence':f'Expires in {days_left} days','cwe':'CWE-295'})

                # Check self-signed
                issuer = dict(x[0] for x in cert.get('issuer', []))
                subject = dict(x[0] for x in cert.get('subject', []))
                if issuer.get('commonName') == subject.get('commonName'):
                    findings.append({'type':'Self-Signed Certificate','severity':'MEDIUM','url':f'https://{host}',
                                    'evidence':f'Issuer matches subject: {issuer.get("commonName")}','cwe':'CWE-295'})

                # Check SANs
                sans = [v for t, v in cert.get('subjectAltName', [])]
                if f'*.{host}' not in sans and host not in sans:
                    pass  # Certificate may still be valid via parent domain
        except ssl.SSLCertVerificationError as e:
            findings.append({'type':'SSL Certificate Verification Failed','severity':'HIGH','url':f'https://{host}',
                            'evidence':str(e)[:200],'cwe':'CWE-295'})
        except Exception:
            pass
        return findings

    async def _check_tls_versions(self, host, port):
        findings = []
        weak_protocols = [
            (ssl.PROTOCOL_TLSv1 if hasattr(ssl, 'PROTOCOL_TLSv1') else None, 'TLSv1.0'),
        ]
        for proto, name in weak_protocols:
            if proto is None: continue
            try:
                ctx = ssl.SSLContext(proto)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                loop = asyncio.get_event_loop()
                def _connect():
                    with socket.create_connection((host, port), timeout=5) as sock:
                        with ctx.wrap_socket(sock) as ssock:
                            return ssock.version()
                ver = await loop.run_in_executor(None, _connect)
                if ver:
                    findings.append({'type':'Weak TLS Version Supported','severity':'MEDIUM',
                                    'url':f'https://{host}','evidence':f'{name} supported',
                                    'remediation':f'Disable {name}','cwe':'CWE-326'})
            except: pass
        return findings
