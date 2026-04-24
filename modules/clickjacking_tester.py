"""GECKO APOCALYPSE - Clickjacking Tester (Real-World Enhanced)"""

import asyncio
import re
from typing import Dict, List, Optional
from urllib.parse import urlparse

import aiohttp
from bs4 import BeautifulSoup  # Optional: for content-aware analysis


class ClickjackingTester:
    # Context-aware severity mapping
    SENSITIVE_PATHS = [
        r'/login', r'/admin', r'/account', r'/payment', r'/checkout',
        r'/profile', r'/settings', r'/api/auth', r'/oauth'
    ]
    
    # CSP bypass patterns to flag
    CSP_BYPASS_PATTERNS = [
        r'frame-ancestors\s+[*]',           # Wildcard allowance
        r'frame-ancestors\s+https?://\*',   # Protocol-relative wildcard
        r'default-src\s+[*]',               # Overly permissive fallback
    ]

    def __init__(self, session, config, db):
        self.session = session
        self.config = config
        self.db = db
        self.stealth_delay = config.get('stealth', {}).get('delay_ms', 100)

    async def scan(self, url: str, content: str, headers: Dict, response) -> List[Dict]:
        findings = []
        h = {k.lower(): v for k, v in headers.items()}
        
        # === 1. Header Analysis ===
        xfo = h.get("x-frame-options", "").strip().lower()
        csp = h.get("content-security-policy", "").lower()
        csp_report_only = h.get("content-security-policy-report-only", "").lower()
        permissions_policy = h.get("permissions-policy", "").lower()  # Formerly Feature-Policy
        
        # === 2. Protection Status Evaluation ===
        protection_status = self._evaluate_protection(xfo, csp, csp_report_only)
        
        # === 3. Context-Aware Risk Assessment ===
        is_sensitive = self._is_sensitive_endpoint(url)
        base_severity = protection_status.get("severity")
        final_severity = self._calibrate_severity(base_severity, is_sensitive, url)
        
        # === 4. Exploitability Check (Optional - requires config enable) ===
        if self.config.get('clickjacking', {}).get('active_test', False):
            embeddable = await self._test_iframe_embeddability(url, headers)
            if not protection_status["protected"] and embeddable:
                protection_status["exploitable"] = True
                protection_status["poc_snippet"] = await self._generate_poc(url, headers)
        
        # === 5. Generate Finding (Only if truly vulnerable) ===
        if not protection_status["protected"]:
            finding = {
                "type": "Clickjacking Vulnerability",
                "severity": final_severity,
                "url": url,
                "evidence": {
                    "x_frame_options": xfo or "NOT SET",
                    "content_security_policy": csp or "NOT SET",
                    "permissions_policy": permissions_policy or "NOT SET",
                    "csp_report_only": bool(csp_report_only),
                    "protection_details": protection_status["details"]
                },
                "context": {
                    "is_sensitive_endpoint": is_sensitive,
                    "page_title": self._extract_title(content),
                    "has_login_form": self._detect_auth_forms(content)
                },
                "remediation": self._generate_remediation(xfo, csp, is_sensitive),
                "references": [
                    "https://owasp.org/www-community/attacks/Clickjacking",
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options"
                ],
                "cwe": "CWE-1021",
                "owasp": "A05:2021-Security Misconfiguration",
                "cvss_hint": self._estimate_cvss(final_severity, is_sensitive)
            }
            
            # Add PoC if active testing was performed
            if protection_status.get("poc_snippet"):
                finding["proof_of_concept"] = protection_status["poc_snippet"]
                
            findings.append(finding)
            
            # Log to DB for session resumption
            await self.db.log_finding(url, "clickjacking", finding)
        
        # Stealth mode: respect delay
        if self.stealth_delay:
            await asyncio.sleep(self.stealth_delay / 1000)
            
        return findings

    def _evaluate_protection(self, xfo: str, csp: str, csp_ro: str) -> Dict:
        """Evaluate header protection with bypass detection"""
        details = []
        protected = False
        
        # Check X-Frame-Options
        if xfo in ["deny", "sameorigin"]:
            protected = True
            details.append(f"✓ X-Frame-Options: {xfo.upper()}")
        elif xfo:
            if "allow-from" in xfo:
                details.append("⚠ X-Frame-Options: ALLOW-FROM (deprecated, browser support limited)")
            elif xfo == "allowall":
                details.append("✗ X-Frame-Options: ALLOWALL (invalid/non-protective)")
            else:
                details.append(f"✗ X-Frame-Options: Unrecognized value '{xfo}'")
        else:
            details.append("✗ X-Frame-Options: NOT SET")
        
        # Check CSP frame-ancestors
        if "frame-ancestors" in csp:
            # Extract frame-ancestors directive
            match = re.search(r'frame-ancestors\s+([^;]+)', csp)
            if match:
                ancestors = match.group(1).strip()
                if ancestors == "'none'":
                    protected = True
                    details.append("✓ CSP: frame-ancestors 'none'")
                elif ancestors in ["'self'", "self"]:
                    protected = True
                    details.append("✓ CSP: frame-ancestors 'self'")
                else:
                    # Check for bypass patterns
                    for pattern in self.CSP_BYPASS_PATTERNS:
                        if re.search(pattern, csp):
                            details.append(f"⚠ CSP: frame-ancestors may be bypassed ({ancestors})")
                            break
                    else:
                        details.append(f"ℹ CSP: frame-ancestors allows: {ancestors}")
        elif csp:
            details.append("ℹ CSP present but missing frame-ancestors directive")
        else:
            details.append("✗ CSP: NOT SET or missing frame-ancestors")
        
        # Report-Only CSP doesn't enforce protection
        if csp_ro and not protected:
            details.append("⚠ CSP-Report-Only present but NOT enforcing protection")
        
        return {
            "protected": protected,
            "severity": "LOW" if protected else "MEDIUM",
            "details": "; ".join(details),
            "exploitable": False  # Updated later if active test runs
        }

    def _is_sensitive_endpoint(self, url: str) -> bool:
        """Determine if URL handles sensitive operations"""
        path = urlparse(url).path.lower()
        return any(re.search(pattern, path) for pattern in self.SENSITIVE_PATHS)

    def _calibrate_severity(self, base: str, is_sensitive: bool, url: str) -> str:
        """Adjust severity based on context and exploitability"""
        if is_sensitive:
            return "HIGH" if base == "MEDIUM" else base
        # Public marketing pages with no auth = lower risk
        if any(kw in url.lower() for kw in ["/blog", "/docs", "/public", "/static"]):
            return "INFO" if base == "MEDIUM" else base
        return base

    async def _test_iframe_embeddability(self, url: str, headers: Dict) -> bool:
        """Lightweight test: check if page blocks iframe via JS (X-Frame-Options bypass detection)"""
        # Note: Full render test would require headless browser (Playwright/Puppeteer)
        # This is a heuristic check for common JS frame-busters
        try:
            async with self.session.get(url, headers=headers, timeout=10) as resp:
                text = await resp.text()
                # Detect common frame-busting scripts
                frame_busters = [
                    r'if\s*\(\s*top\s*!=\s*self\s*\)',
                    r'window\.top\.location',
                    r'document\.write.*iframe',
                    r'X-Frame-Options.*deny',  # Double protection hint
                ]
                return not any(re.search(pat, text, re.I) for pat in frame_busters)
        except Exception:
            return True  # Assume embeddable on error (conservative)

    async def _generate_poc(self, url: str, headers: Dict) -> str:
        """Generate minimal PoC HTML snippet"""
        return f"""<!-- Clickjacking PoC for {url} -->
<iframe src="{url}" width="800" height="600" sandbox="allow-forms allow-scripts"></iframe>
<!-- Test: If page loads inside iframe, vulnerability confirmed -->"""

    def _generate_remediation(self, xfo: str, csp: str, is_sensitive: bool) -> str:
        """Context-aware remediation guidance"""
        base = "Set the following headers to prevent clickjacking:\n\n"
        
        # Always recommend CSP (modern standard)
        csp_rec = "Content-Security-Policy: frame-ancestors 'self';" if is_sensitive else "Content-Security-Policy: frame-ancestors 'self' https://trusted-partner.com;"
        
        # X-Frame-Options as defense-in-depth (still widely supported)
        xfo_rec = "X-Frame-Options: DENY;" if is_sensitive else "X-Frame-Options: SAMEORIGIN;"
        
        return base + f"```nginx\nadd_header {csp_rec}\nadd_header {xfo_rec}\n```\n\n" + (
            "🔒 For sensitive pages (auth/admin), use 'DENY' and avoid wildcard CSP values." 
            if is_sensitive 
            else "💡 Test framing requirements with legitimate partners before restricting."
        )

    def _estimate_cvss(self, severity: str, is_sensitive: bool) -> Dict:
        """Provide CVSS v3.1 hint for triage"""
        if severity == "HIGH":
            return {"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N", "score": 5.4}
        elif severity == "MEDIUM":
            return {"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:N", "score": 4.3}
        return {"vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:N", "score": 2.6}

    # === Utility Helpers ===
    def _extract_title(self, html: str) -> Optional[str]:
        if not html: return None
        try:
            soup = BeautifulSoup(html, 'html.parser')
            return soup.title.string.strip() if soup.title else None
        except:
            return None

    def _detect_auth_forms(self, html: str) -> bool:
        if not html: return False
        return bool(re.search(r'<form[^>]*(login|auth|signin|password)', html, re.I))