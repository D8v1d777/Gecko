"""GECKO APOCALYPSE - Authentication Bypass (2FA, session fixation, password reset, enumeration, CAPTCHA, SSO, cookie analysis)"""

import asyncio
import json
import re
import time
from typing import Dict, List, Optional
from urllib.parse import urlparse

import aiohttp


class AuthBypass:
    def __init__(self, session, config, db):
        self.session = session
        self.config = config
        self.db = db

    async def scan(self, url, content, headers, response):
        findings = []
        for t in [
            self._session_fix,
            self._reset_poison,
            self._enum_timing,
            self._cookie_analysis,
            self._2fa_bypass,
            self._captcha_bypass,
            self._magic_link,
        ]:
            r = await t(url, content, headers)
            if r:
                findings.append(r)
        return findings

    async def _session_fix(self, url, content, headers):
        cookies = headers.get("set-cookie", "").lower()
        for name in [
            "sessionid",
            "phpsessid",
            "jsessionid",
            "asp.net_sessionid",
            "connect.sid",
        ]:
            if name in cookies:
                return {
                    "type": "Session Fixation Risk",
                    "severity": "MEDIUM",
                    "url": url,
                    "evidence": f"Session cookie set pre-auth: {name}",
                    "remediation": "Regenerate session ID after login",
                    "cwe": "CWE-384",
                }

    async def _reset_poison(self, url, content, headers):
        if not any(k in url.lower() for k in ["reset", "forgot", "password"]):
            return
        try:
            async with self.session.post(
                url,
                headers={"Host": "evil.com"},
                data={"email": "test@test.com"},
                timeout=aiohttp.ClientTimeout(total=10),
            ) as r:
                if r.status == 200:
                    return {
                        "type": "Password Reset Poisoning",
                        "severity": "HIGH",
                        "url": url,
                        "evidence": "Accepted manipulated Host header",
                        "remediation": "Use server config for URL generation",
                        "cwe": "CWE-640",
                    }
        except:
            pass

    async def _enum_timing(self, url, content, headers):
        if not any(k in url.lower() for k in ["login", "signin", "auth"]):
            return
        timings = []
        for user in ["admin", "nonexistentuser99999xyz"]:
            t = time.time()
            try:
                async with self.session.post(
                    url,
                    data={"username": user, "password": "wrong"},
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as r:
                    timings.append(time.time() - t)
            except:
                timings.append(0)
        if len(timings) == 2 and abs(timings[0] - timings[1]) > 0.5:
            return {
                "type": "Username Enumeration (Timing)",
                "severity": "LOW",
                "url": url,
                "evidence": f"Timing diff: {abs(timings[0]-timings[1]):.2f}s",
                "cwe": "CWE-203",
            }

    async def _cookie_analysis(self, url, content, headers):
        """Analyze cookie security attributes."""
        cookies = headers.get("set-cookie", "")
        if not cookies:
            return
        issues = []
        if "httponly" not in cookies.lower():
            issues.append("Missing HttpOnly")
        if "secure" not in cookies.lower():
            issues.append("Missing Secure")
        if "samesite" not in cookies.lower():
            issues.append("Missing SameSite")
        if issues:
            return {
                "type": "Insecure Cookie Attributes",
                "severity": "MEDIUM",
                "url": url,
                "evidence": "; ".join(issues),
                "remediation": "Set HttpOnly, Secure, SameSite=Strict",
                "cwe": "CWE-614",
            }

    async def _2fa_bypass(self, url, content, headers):
        """Check for 2FA bypass indicators."""
        if not any(
            k in content.lower() for k in ["2fa", "two-factor", "totp", "otp", "mfa"]
        ):
            return
        # Test direct access to post-2FA endpoints
        base = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
        for p in ["/dashboard", "/account", "/profile", "/admin", "/home"]:
            try:
                async with self.session.get(
                    f"{base}{p}", timeout=aiohttp.ClientTimeout(total=5)
                ) as r:
                    if r.status == 200 and any(
                        k in (await r.text(errors="ignore")).lower()
                        for k in ["dashboard", "welcome", "account"]
                    ):
                        return {
                            "type": "2FA Bypass Possible",
                            "severity": "HIGH",
                            "url": f"{base}{p}",
                            "evidence": "Post-2FA page accessible without completing 2FA",
                            "remediation": "Enforce 2FA on all protected routes",
                            "cwe": "CWE-304",
                        }
            except:
                pass

    async def _captcha_bypass(self, url, content, headers):
        """Check if CAPTCHA can be bypassed."""
        if "captcha" not in content.lower() and "recaptcha" not in content.lower():
            return
        # Test submitting without captcha
        forms = re.findall(r'<form[^>]*action=["\']([^"\']+)["\']', content)
        for form in forms[:3]:
            action = (
                form
                if form.startswith("http")
                else f"{urlparse(url).scheme}://{urlparse(url).netloc}{form}"
            )
            try:
                async with self.session.post(
                    action,
                    data={"username": "test", "password": "test"},
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as r:
                    if (
                        r.status == 200
                        and "captcha" not in (await r.text(errors="ignore")).lower()
                    ):
                        return {
                            "type": "CAPTCHA Bypass",
                            "severity": "MEDIUM",
                            "url": action,
                            "evidence": "Form submitted without CAPTCHA validation",
                            "remediation": "Server-side CAPTCHA validation",
                            "cwe": "CWE-804",
                        }
            except:
                pass

    async def _magic_link(self, url, content, headers):
        """Check magic link token strength."""
        if not any(k in url.lower() for k in ["magic", "token", "verify", "confirm"]):
            return
        params = dict(
            p.split("=", 1) for p in urlparse(url).query.split("&") if "=" in p
        )
        for k, v in params.items():
            if "token" in k.lower() and len(v) < 20:
                return {
                    "type": "Weak Magic Link Token",
                    "severity": "HIGH",
                    "url": url,
                    "evidence": f"Token length: {len(v)} chars",
                    "remediation": "Use cryptographically strong tokens (32+ chars)",
                    "cwe": "CWE-330",
                }
