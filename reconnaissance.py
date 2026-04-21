"""
GECKO APOCALYPSE - RECONNAISSANCE & INTELLIGENCE ENGINE
Complete OSINT, Subdomain Enum, Tech Detection, Secret Scanning
================================================================================
"""

import asyncio
import hashlib
import json
import math
import re
from datetime import datetime
from typing import Dict, List, Optional, Set
from urllib.parse import urlparse

import aiohttp
import dns.resolver


class ReconEngine:
    """Complete reconnaissance and OSINT capabilities."""

    def __init__(self, session: aiohttp.ClientSession, config: Dict, db):
        self.session = session
        self.config = config
        self.db = db
        self.subdomains: Set[str] = set()

    async def enumerate_subdomains(self, domain: str) -> List[str]:
        """Comprehensive subdomain enumeration."""
        domain = urlparse(domain).netloc if domain.startswith("http") else domain

        # Method 1: Certificate Transparency logs
        crt_subs = await self._crt_sh_subdomains(domain)
        self.subdomains.update(crt_subs)

        # Method 2: DNS brute force
        brute_subs = await self._dns_bruteforce(domain)
        self.subdomains.update(brute_subs)

        # Method 3: Search engine scraping
        search_subs = await self._search_engine_scraping(domain)
        self.subdomains.update(search_subs)

        return list(self.subdomains)

    async def _crt_sh_subdomains(self, domain: str) -> List[str]:
        """Query crt.sh for certificate transparency logs."""
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        subdomains = set()

        try:
            async with self.session.get(url, timeout=30) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    for entry in data:
                        name = entry.get("name_value", "")
                        # Parse subdomains
                        for subdomain in name.split("\n"):
                            subdomain = subdomain.strip("*.").strip()
                            if subdomain.endswith(domain):
                                subdomains.add(subdomain)
        except:
            pass

        return list(subdomains)

    async def _dns_bruteforce(self, domain: str) -> List[str]:
        """DNS brute force with common subdomain list."""
        common_subdomains = [
            "www",
            "mail",
            "ftp",
            "localhost",
            "webmail",
            "smtp",
            "pop",
            "ns1",
            "webdisk",
            "ns2",
            "cpanel",
            "whm",
            "autodiscover",
            "autoconfig",
            "stage",
            "staging",
            "dev",
            "development",
            "test",
            "api",
            "admin",
            "portal",
            "dashboard",
            "app",
            "mobile",
            "blog",
            "forum",
            "shop",
            "store",
            "cdn",
            "static",
            "assets",
            "img",
            "images",
        ]

        valid_subdomains = []

        for subdomain in common_subdomains:
            full_domain = f"{subdomain}.{domain}"
            if await self._dns_resolve(full_domain):
                valid_subdomains.append(full_domain)

        return valid_subdomains

    async def _dns_resolve(self, domain: str) -> bool:
        """Check if domain resolves."""
        try:
            answers = dns.resolver.resolve(domain, "A")
            return len(answers) > 0
        except:
            return False

    async def _search_engine_scraping(self, domain: str) -> List[str]:
        """Scrape search engines for subdomains."""
        # Note: This is simplified - real implementation would use actual search APIs
        return []

    async def dns_analysis(self, domain: str) -> Dict:
        """Complete DNS analysis."""
        domain = urlparse(domain).netloc if domain.startswith("http") else domain

        results = {
            "a_records": [],
            "aaaa_records": [],
            "mx_records": [],
            "ns_records": [],
            "txt_records": [],
            "cname_records": [],
        }

        record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]

        for rtype in record_types:
            try:
                answers = dns.resolver.resolve(domain, rtype)
                results[f"{rtype.lower()}_records"] = [str(r) for r in answers]
            except:
                pass

        return results

    async def whois_lookup(self, domain: str) -> Dict:
        """WHOIS information lookup."""
        # Simplified - real implementation would use python-whois
        return {
            "domain": domain,
            "registrar": "Unknown",
            "creation_date": "Unknown",
            "expiration_date": "Unknown",
        }

    async def certificate_transparency(self, domain: str) -> List[str]:
        """Certificate transparency log analysis."""
        return await self._crt_sh_subdomains(domain)

    async def detect_technologies(self, url: str) -> Dict:
        """Detect web technologies in use."""
        try:
            async with self.session.get(url, timeout=15) as resp:
                content = await resp.text()
                headers = dict(resp.headers)

                techs = {
                    "cms": self._detect_cms(content, headers),
                    "frameworks": self._detect_frameworks(content, headers),
                    "server": headers.get("Server", "Unknown"),
                    "programming_language": self._detect_language(headers, content),
                    "cdn": self._detect_cdn(headers),
                    "waf": self._detect_waf(headers),
                    "analytics": self._detect_analytics(content),
                }

                return techs
        except:
            return {}

    def _detect_cms(self, content: str, headers: Dict) -> List[str]:
        """Detect Content Management Systems."""
        cms_signatures = {
            "WordPress": ["/wp-content/", "/wp-includes/", "wp-json"],
            "Drupal": ["Drupal", "/sites/default/", "/modules/"],
            "Joomla": ["Joomla", "/components/", "/modules/mod_"],
            "Magento": ["Magento", "/skin/frontend/", "/mage/"],
            "Shopify": ["cdn.shopify.com", "shopify"],
            "Wix": ["wix.com", "wixstatic"],
            "Squarespace": ["squarespace", "sqsp.com"],
        }

        detected = []
        for cms, signatures in cms_signatures.items():
            if any(sig in content or sig in str(headers) for sig in signatures):
                detected.append(cms)

        return detected

    def _detect_frameworks(self, content: str, headers: Dict) -> List[str]:
        """Detect web frameworks."""
        frameworks = {
            "React": ["react", "_react", "react-dom"],
            "Angular": ["ng-", "angular", "ng-app"],
            "Vue.js": ["vue", "v-if", "v-for", "v-bind"],
            "Next.js": ["next.js", "_next/", "__NEXT_DATA__"],
            "Django": ["csrfmiddlewaretoken", "django"],
            "Flask": ["werkzeug", "flask"],
            "Express": ["express", "x-powered-by: Express"],
            "Laravel": ["laravel", "laravel_session"],
            "Ruby on Rails": ["rails", "csrf-token", "x-csrf-token"],
            "ASP.NET": ["aspnet", "viewstate", "__VIEWSTATE"],
        }

        detected = []
        for framework, signatures in frameworks.items():
            if any(
                sig.lower() in content.lower() or sig.lower() in str(headers).lower()
                for sig in signatures
            ):
                detected.append(framework)

        return detected

    def _detect_language(self, headers: Dict, content: str) -> str:
        """Detect programming language."""
        header_str = str(headers).lower()

        if "php" in header_str or ".php" in content:
            return "PHP"
        elif "python" in header_str or "wsgi" in header_str:
            return "Python"
        elif "java" in header_str or "jsp" in content:
            return "Java"
        elif "asp.net" in header_str or "aspx" in content:
            return "ASP.NET"
        elif "ruby" in header_str or "rack" in header_str:
            return "Ruby"
        elif "node" in header_str or "express" in header_str:
            return "Node.js"

        return "Unknown"

    def _detect_cdn(self, headers: Dict) -> List[str]:
        """Detect CDN usage."""
        cdn_headers = {
            "Cloudflare": ["cf-ray", "cloudflare"],
            "Fastly": ["fastly", "x-fastly"],
            "Akamai": ["akamai", "x-akamai"],
            "Amazon CloudFront": ["cloudfront", "x-amz"],
            "Cloudinary": ["cloudinary"],
            "KeyCDN": ["keycdn"],
        }

        detected = []
        header_str = str(headers).lower()

        for cdn, signatures in cdn_headers.items():
            if any(sig in header_str for sig in signatures):
                detected.append(cdn)

        return detected

    def _detect_waf(self, headers: Dict) -> List[str]:
        """Detect Web Application Firewall."""
        waf_signatures = {
            "Cloudflare": "cloudflare",
            "AWS WAF": "awselb",
            "Akamai": "akamai",
            "Imperva": "imperva",
            "F5 BIG-IP": "bigip",
            "ModSecurity": "mod_security",
            "Sucuri": "sucuri",
        }

        detected = []
        header_str = str(headers).lower()

        for waf, signature in waf_signatures.items():
            if signature in header_str:
                detected.append(waf)

        return detected

    def _detect_analytics(self, content: str) -> List[str]:
        """Detect analytics platforms."""
        analytics = []

        if "google-analytics.com" in content or "gtag" in content:
            analytics.append("Google Analytics")
        if "facebook.com/tr" in content or "fbq(" in content:
            analytics.append("Facebook Pixel")
        if "hotjar" in content:
            analytics.append("Hotjar")
        if "mixpanel" in content:
            analytics.append("Mixpanel")
        if "segment.com" in content or "analytics.js" in content:
            analytics.append("Segment")

        return analytics

    async def wayback_analysis(self, url: str) -> Dict:
        """Analyze Wayback Machine snapshots."""
        domain = urlparse(url).netloc
        wayback_url = f"http://web.archive.org/cdx/search/cdx?url={domain}/*&output=json&limit=100"

        snapshots = []

        try:
            async with self.session.get(wayback_url, timeout=30) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    # Skip header row
                    for row in data[1:]:
                        snapshots.append(
                            {"timestamp": row[1], "url": row[2], "status": row[4]}
                        )
        except:
            pass

        return {"count": len(snapshots), "snapshots": snapshots[:20]}

    async def scan_github_leaks(self, domain: str) -> List[Dict]:
        """Scan for leaked secrets on GitHub."""
        # This would require GitHub API token
        # Simplified implementation
        findings = []

        # Search patterns
        search_queries = [
            f'"{domain}" password',
            f'"{domain}" api_key',
            f'"{domain}" secret',
            f'"{domain}" token',
            f'"{domain}" credentials',
        ]

        # Note: Real implementation would use GitHub API
        # For now, return empty
        return findings

    async def check_breaches(self, domain: str) -> Dict:
        """Check for data breaches."""
        # This would require HaveIBeenPwned API
        # Simplified implementation
        return {"breached": False, "breach_count": 0, "breaches": []}


class SecretScanner:
    """Scan for exposed secrets and credentials."""

    def __init__(self, session: aiohttp.ClientSession, config: Dict, db):
        self.session = session
        self.config = config
        self.db = db

        # Secret patterns
        self.patterns = {
            "AWS Access Key": r"AKIA[0-9A-Z]{16}",
            "AWS Secret Key": r'aws(.{0,20})?[\'"][0-9a-zA-Z\/+]{40}[\'"]',
            "GitHub Token": r"ghp_[a-zA-Z0-9]{36}",
            "GitHub OAuth": r"gho_[a-zA-Z0-9]{36}",
            "SendGrid API Key": r"SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}",
            "Slack Token": r"xox[baprs]-[0-9]{10,12}-[0-9]{10,12}-[a-zA-Z0-9]{24,32}",
            "Private Key": r"-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----",
            "JWT Token": r"eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+",
            "Google API Key": r"AIza[0-9A-Za-z\\-_]{35}",
            "Stripe API Key": r"sk_live_[0-9a-zA-Z]{24}",
            "Twilio API Key": r"SK[0-9a-fA-F]{32}",
            "Database URL": r"(mysql|postgres|mongodb|redis)://[^\s]+",
            "Email": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
        }

    async def scan(self, url: str, content: str, headers: Dict, response) -> List[Dict]:
        """Scan content for exposed secrets."""
        findings = []

        for secret_type, pattern in self.patterns.items():
            matches = re.findall(pattern, content, re.IGNORECASE)

            for match in set(matches):
                # Calculate entropy
                entropy = self._calculate_entropy(match)

                # Only report high-entropy strings
                if entropy > 3.5 or secret_type in ["Private Key", "Database URL"]:
                    severity = self._determine_severity(secret_type)

                    findings.append(
                        {
                            "type": f"Exposed Secret: {secret_type}",
                            "severity": severity,
                            "url": url,
                            "evidence": (
                                match[:50] + "..." if len(match) > 50 else match
                            ),
                            "entropy": f"{entropy:.2f}",
                            "description": f"{secret_type} exposed in response",
                            "remediation": "Remove sensitive data, rotate credentials",
                            "cwe": "CWE-200",
                            "owasp": "A01:2021 - Broken Access Control",
                        }
                    )

        return findings

    def _calculate_entropy(self, data: str) -> float:
        """Calculate Shannon entropy."""
        if not data:
            return 0

        entropy = 0
        for char in set(data):
            prob = data.count(char) / len(data)
            entropy -= prob * math.log2(prob)

        return entropy

    def _determine_severity(self, secret_type: str) -> str:
        """Determine severity based on secret type."""
        critical_types = ["AWS Access Key", "Private Key", "Database URL"]
        high_types = ["GitHub Token", "SendGrid API Key", "Stripe API Key"]

        if secret_type in critical_types:
            return "CRITICAL"
        elif secret_type in high_types:
            return "HIGH"
        else:
            return "MEDIUM"


class TechDetector:
    """Technology stack detection."""

    def __init__(self, session: aiohttp.ClientSession, config: Dict, db):
        self.session = session
        self.config = config
        self.db = db

    async def scan(self, url: str, content: str, headers: Dict, response) -> List[Dict]:
        """Detect technologies and create info findings."""
        findings = []

        # Detect CMS
        cms_list = self._detect_cms(content, headers)
        for cms in cms_list:
            findings.append(
                {
                    "type": "Technology Detection",
                    "severity": "INFO",
                    "url": url,
                    "evidence": f"CMS: {cms}",
                    "description": f"Detected CMS: {cms}",
                }
            )

        # Detect server
        server = headers.get("Server", headers.get("server"))
        if server:
            findings.append(
                {
                    "type": "Server Banner",
                    "severity": "INFO",
                    "url": url,
                    "evidence": f"Server: {server}",
                    "description": "Server banner exposed",
                }
            )

        return findings

    def _detect_cms(self, content: str, headers: Dict) -> List[str]:
        """Detect CMS (reuse from ReconEngine)."""
        cms_signatures = {
            "WordPress": ["/wp-content/", "/wp-includes/"],
            "Drupal": ["Drupal", "/sites/default/"],
            "Joomla": ["Joomla", "/components/"],
        }

        detected = []
        for cms, signatures in cms_signatures.items():
            if any(sig in content for sig in signatures):
                detected.append(cms)

        return detected


class HeaderAnalyzer:
    """Security headers analysis."""

    def __init__(self, session: aiohttp.ClientSession, config: Dict, db):
        self.session = session
        self.config = config
        self.db = db

    async def scan(self, url: str, content: str, headers: Dict, response) -> List[Dict]:
        """Analyze security headers."""
        findings = []

        # Check for missing security headers
        required_headers = {
            "Strict-Transport-Security": "MEDIUM",
            "X-Frame-Options": "MEDIUM",
            "X-Content-Type-Options": "LOW",
            "Content-Security-Policy": "HIGH",
            "X-XSS-Protection": "LOW",
            "Referrer-Policy": "LOW",
            "Permissions-Policy": "LOW",
        }

        for header, severity in required_headers.items():
            if header.lower() not in [h.lower() for h in headers.keys()]:
                findings.append(
                    {
                        "type": "Missing Security Header",
                        "severity": severity,
                        "url": url,
                        "evidence": f"Missing header: {header}",
                        "description": f"{header} not set",
                        "remediation": f"Add {header} header",
                        "cwe": "CWE-16",
                    }
                )

        return findings


class SSLAnalyzer:
    """SSL/TLS analysis."""

    def __init__(self, session: aiohttp.ClientSession, config: Dict, db):
        self.session = session
        self.config = config
        self.db = db

    async def scan(self, url: str, content: str, headers: Dict, response) -> List[Dict]:
        """Analyze SSL/TLS configuration."""
        findings = []

        # Check if HTTPS
        if not url.startswith("https"):
            findings.append(
                {
                    "type": "No HTTPS",
                    "severity": "HIGH",
                    "url": url,
                    "evidence": "Site not using HTTPS",
                    "description": "Sensitive data transmitted over unencrypted connection",
                    "remediation": "Implement HTTPS",
                }
            )

        # Note: Full SSL analysis requires python-ssl library
        return findings


class APIFuzzer:
    """API-specific fuzzing and testing."""

    def __init__(self, session: aiohttp.ClientSession, config: Dict, db):
        self.session = session
        self.config = config
        self.db = db

    async def scan(self, url: str, content: str, headers: Dict, response) -> List[Dict]:
        """Fuzz API endpoints."""
        findings = []

        # Check if this is an API endpoint
        if not self._is_api_endpoint(url, headers):
            return findings

        # Test BOLA/IDOR
        bola_finding = await self._test_bola(url)
        if bola_finding:
            findings.append(bola_finding)

        # Test mass assignment
        mass_assign = await self._test_mass_assignment(url)
        if mass_assign:
            findings.append(mass_assign)

        return findings

    def _is_api_endpoint(self, url: str, headers: Dict) -> bool:
        """Check if endpoint is an API."""
        api_indicators = [
            "/api/" in url,
            "/v1/" in url,
            "/v2/" in url,
            "application/json" in headers.get("content-type", ""),
            "application/xml" in headers.get("content-type", ""),
        ]
        return any(api_indicators)

    async def _test_bola(self, url: str) -> Optional[Dict]:
        """Test for Broken Object Level Authorization."""
        # Extract IDs from URL
        id_pattern = r"/(\d+)(?:/|$)"
        matches = re.findall(id_pattern, url)

        if not matches:
            return None

        original_id = matches[0]
        test_ids = [str(int(original_id) + 1), str(int(original_id) - 1), "999999"]

        for test_id in test_ids:
            test_url = url.replace(f"/{original_id}", f"/{test_id}")

            try:
                async with self.session.get(test_url, timeout=10) as resp:
                    if resp.status == 200:
                        return {
                            "type": "BOLA/IDOR Vulnerability",
                            "severity": "CRITICAL",
                            "url": url,
                            "payload": test_id,
                            "evidence": f"Accessed object {test_id} without authorization",
                            "description": "Broken Object Level Authorization detected",
                            "remediation": "Implement proper authorization checks",
                            "cwe": "CWE-639",
                            "owasp": "API1:2023 - Broken Object Level Authorization",
                        }
            except:
                pass

        return None

    async def _test_mass_assignment(self, url: str) -> Optional[Dict]:
        """Test for mass assignment vulnerabilities."""
        # Only test POST/PUT/PATCH
        dangerous_fields = {
            "is_admin": True,
            "role": "admin",
            "admin": True,
            "verified": True,
            "premium": True,
        }

        try:
            async with self.session.post(
                url, json=dangerous_fields, timeout=10
            ) as resp:
                if resp.status in [200, 201]:
                    content = await resp.text()
                    if any(field in content for field in dangerous_fields.keys()):
                        return {
                            "type": "Mass Assignment",
                            "severity": "HIGH",
                            "url": url,
                            "evidence": "API accepted unauthorized fields",
                            "description": "Mass assignment allows privilege escalation",
                            "remediation": "Whitelist allowed fields",
                            "cwe": "CWE-915",
                        }
        except:
            pass

        return None


class JSFrameworkHunter:
    """JavaScript framework exploitation."""

    def __init__(self, session: aiohttp.ClientSession, config: Dict, db):
        self.session = session
        self.config = config
        self.db = db

    async def scan(self, url: str, content: str, headers: Dict, response) -> List[Dict]:
        """Hunt for JS framework vulnerabilities."""
        findings = []

        # Detect prototype pollution
        if "constructor.prototype" in content or "__proto__" in content:
            findings.append(
                {
                    "type": "Potential Prototype Pollution",
                    "severity": "MEDIUM",
                    "url": url,
                    "evidence": "Prototype pollution indicators found",
                    "description": "JavaScript prototype pollution possible",
                }
            )

        # Detect source maps
        if ".map" in content or "sourceMappingURL" in content:
            findings.append(
                {
                    "type": "Source Maps Exposed",
                    "severity": "LOW",
                    "url": url,
                    "evidence": "JavaScript source maps available",
                    "description": "Source maps expose application logic",
                }
            )

        return findings


class VulnerabilityScanner:
    """Stub for main vulnerability scanner."""

    def __init__(self, session: aiohttp.ClientSession, config: Dict, db):
        self.session = session
        self.config = config
        self.db = db


# Export all
__all__ = [
    "ReconEngine",
    "SecretScanner",
    "TechDetector",
    "HeaderAnalyzer",
    "SSLAnalyzer",
    "APIFuzzer",
    "JSFrameworkHunter",
    "VulnerabilityScanner",
]
