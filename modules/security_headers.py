"""
GECKO - Security Headers Scanner
Checks for missing/misconfigured security headers across discovered endpoints.
"""
import asyncio
import re


REQUIRED_HEADERS = {
    "strict-transport-security":    ("HIGH",   "Missing HSTS", "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains"),
    "content-security-policy":      ("HIGH",   "No CSP - XSS risk increased", "Implement Content-Security-Policy"),
    "x-frame-options":              ("MEDIUM", "Clickjacking possible", "Add: X-Frame-Options: DENY"),
    "x-content-type-options":       ("MEDIUM", "MIME sniffing possible", "Add: X-Content-Type-Options: nosniff"),
    "referrer-policy":              ("LOW",    "Referrer leakage risk", "Add: Referrer-Policy: strict-origin-when-cross-origin"),
    "permissions-policy":           ("LOW",    "Browser features unrestricted", "Add Permissions-Policy header"),
    "cross-origin-opener-policy":   ("LOW",    "COOP not set", "Add: Cross-Origin-Opener-Policy: same-origin"),
}

CSP_DANGEROUS = ["'unsafe-inline'", "'unsafe-eval'", "data:", "http:"]


class SecurityHeaders:
    name = "security_headers"
    severity = "medium"

    async def run(self, target, session, context):
        findings = []

        # Only test root + a sample of discovered HTML endpoints
        endpoints = [target]
        ctx_endpoints = list(context.get("endpoints") or [])
        html_endpoints = [e for e in ctx_endpoints if not any(
            s in e for s in ["/api/", "/rest/", ".json", ".js", ".css"]
        )][:5]
        endpoints.extend(html_endpoints)

        tasks = [_check_headers(session, ep) for ep in endpoints]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for result_list in results:
            if isinstance(result_list, list):
                findings.extend(result_list)

        # Deduplicate by (type, description) - only report each issue once
        seen = set()
        deduped = []
        for f in findings:
            key = (f.get("type"), f.get("description"))
            if key not in seen:
                seen.add(key)
                deduped.append(f)

        return deduped


async def _check_headers(session, endpoint):
    findings = []
    try:
        r = await session.get(endpoint, timeout=8, follow_redirects=True)
        h = {k.lower(): v for k, v in r.headers.items()}

        # Check required headers
        for header, (severity, desc, rem) in REQUIRED_HEADERS.items():
            if header not in h:
                findings.append({
                    "type": "Missing Security Header",
                    "severity": severity,
                    "endpoint": endpoint,
                    "description": desc,
                    "header": header,
                    "remediation": rem,
                    "confidence": "HIGH",
                    "cwe": "CWE-693",
                    "owasp": "A05:2021",
                })

        # Analyze CSP if present
        csp = h.get("content-security-policy", "")
        if csp:
            for dangerous in CSP_DANGEROUS:
                if dangerous in csp:
                    findings.append({
                        "type": "Weak Content Security Policy",
                        "severity": "MEDIUM",
                        "endpoint": endpoint,
                        "description": f"CSP contains dangerous directive: {dangerous}",
                        "evidence": f"CSP: {csp[:200]}",
                        "remediation": f"Remove '{dangerous}' from CSP; use nonces for inline scripts",
                        "confidence": "HIGH",
                        "cwe": "CWE-693",
                        "owasp": "A05:2021",
                    })

        # Check HSTS max-age if present
        hsts = h.get("strict-transport-security", "")
        if hsts:
            match = re.search(r'max-age=(\d+)', hsts)
            if match and int(match.group(1)) < 31536000:
                findings.append({
                    "type": "HSTS Short max-age",
                    "severity": "LOW",
                    "endpoint": endpoint,
                    "description": f"HSTS max-age is {match.group(1)}s (< 1 year)",
                    "remediation": "Set max-age to at least 31536000",
                    "confidence": "HIGH",
                    "cwe": "CWE-319",
                    "owasp": "A05:2021",
                })

        # Check Server header information disclosure
        server = h.get("server", "")
        if server and any(v in server.lower() for v in ["apache/", "nginx/", "iis/", "express", "php/"]):
            findings.append({
                "type": "Server Version Disclosure",
                "severity": "LOW",
                "endpoint": endpoint,
                "description": f"Server header reveals version: {server}",
                "remediation": "Remove or genericize the Server header",
                "confidence": "HIGH",
                "cwe": "CWE-200",
                "owasp": "A05:2021",
            })

        # X-Powered-By disclosure
        xpb = h.get("x-powered-by", "")
        if xpb:
            findings.append({
                "type": "X-Powered-By Disclosure",
                "severity": "LOW",
                "endpoint": endpoint,
                "description": f"X-Powered-By reveals tech stack: {xpb}",
                "remediation": "Remove X-Powered-By header",
                "confidence": "HIGH",
                "cwe": "CWE-200",
                "owasp": "A05:2021",
            })

    except Exception:
        pass
    return findings
