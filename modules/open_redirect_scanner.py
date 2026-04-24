"""
GECKO - Open Redirect Scanner
Tests discovered redirect-like parameters for open redirect vulnerabilities.
"""
import asyncio
from urllib.parse import urlencode, urlparse, parse_qs


REDIRECT_PARAMS = [
    "url", "redirect", "redirect_uri", "redirect_url", "returnUrl", "return",
    "next", "goto", "dest", "destination", "redir", "target", "continue",
    "callback", "back", "forward", "ref", "referer", "referrer",
]

REDIRECT_PAYLOADS = [
    ("https://evil.com", "Absolute URL"),
    ("//evil.com", "Protocol-relative URL"),
    ("//evil.com/%2F..", "Path traversal bypass"),
    ("/\\evil.com", "Backslash bypass"),
    ("https:evil.com", "Colon bypass"),
    ("https://evil.com%09", "Tab-encoded bypass"),
    ("https://evil.com%00", "Null byte bypass"),
    ("https://evil.com@target.com", "Userinfo confusion"),
    ("%2Fevil.com%2F", "URL-encoded bypass"),
]


def _inject_param(endpoint, param, value):
    parsed = urlparse(endpoint)
    params = parse_qs(parsed.query, keep_blank_values=True)
    params[param] = [value]
    return parsed._replace(query=urlencode(params, doseq=True)).geturl()


class OpenRedirectScanner:
    name = "open_redirect"
    severity = "medium"

    async def run(self, target, session, context):
        findings = []
        seen = set()

        ctx_params = list(context.get("params") or [])
        endpoints = list(context.get("endpoints") or [target])

        # Identify redirect-susceptible params
        redirect_params = [p for p in ctx_params if p.lower() in REDIRECT_PARAMS]
        # Always include common ones
        for rp in REDIRECT_PARAMS[:8]:
            if rp not in redirect_params:
                redirect_params.append(rp)

        tasks = []
        for endpoint in endpoints[:30]:
            parsed = urlparse(endpoint)
            url_params = list(parse_qs(parsed.query).keys())
            test_params = url_params if url_params else redirect_params

            for param in test_params:
                if param.lower() not in [rp.lower() for rp in REDIRECT_PARAMS]:
                    continue
                for payload, technique in REDIRECT_PAYLOADS:
                    key = f"{endpoint}|{param}|{payload}"
                    if key not in seen:
                        seen.add(key)
                        tasks.append(_test_redirect(session, endpoint, param, payload, technique, target))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, dict):
                findings.append(r)

        return findings


async def _test_redirect(session, endpoint, param, payload, technique, target):
    try:
        url = _inject_param(endpoint, param, payload)
        r = await session.get(url, timeout=8, follow_redirects=False)

        location = r.headers.get("location", "")
        status = r.status_code

        if status in (301, 302, 303, 307, 308) and location:
            # Check if redirect goes to evil domain
            parsed_loc = urlparse(location)
            if "evil.com" in parsed_loc.netloc or (
                parsed_loc.netloc and parsed_loc.netloc not in urlparse(target).netloc
            ):
                return {
                    "type": "Open Redirect",
                    "severity": "MEDIUM",
                    "endpoint": endpoint,
                    "parameter": param,
                    "payload": payload,
                    "technique": technique,
                    "evidence": f"HTTP {status} → Location: {location}",
                    "confidence": "HIGH",
                    "cwe": "CWE-601",
                    "owasp": "A01:2021",
                    "poc": url,
                    "remediation": "Validate redirect URLs against an allowlist of trusted origins",
                }
    except Exception:
        pass
    return None
