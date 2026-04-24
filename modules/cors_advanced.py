"""
GECKO - Advanced CORS Scanner
Tests all discovered endpoints with multiple origin vectors.
"""
import asyncio


ORIGIN_VECTORS = [
    ("https://evil.com", "External attacker origin"),
    ("null", "Null origin (sandbox/iframe bypass)"),
    ("https://evil.com.target.com", "Subdomain prefix confusion"),
    ("https://target.evil.com", "Target domain suffix confusion"),
]


class CORSAdvanced:
    name = "cors_advanced"
    severity = "high"

    async def run(self, target, session, context):
        findings = []
        seen = set()

        endpoints = list(context.get("endpoints") or [target])
        # Prioritize API endpoints where CORS matters most
        api_endpoints = [e for e in endpoints if "/api/" in e or "/rest/" in e]
        other_endpoints = [e for e in endpoints if e not in api_endpoints]
        ordered = api_endpoints[:20] + other_endpoints[:10]

        if not ordered:
            ordered = [target]

        tasks = []
        for endpoint in ordered:
            key = f"cors|{endpoint}"
            if key not in seen:
                seen.add(key)
                tasks.append(_test_cors(session, endpoint, target))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, list):
                findings.extend(r)

        return findings


async def _test_cors(session, endpoint, target):
    findings = []
    try:
        for origin, description in ORIGIN_VECTORS:
            # Replace subdomain confusion vectors with target-aware values
            from urllib.parse import urlparse
            parsed = urlparse(target)
            host = parsed.netloc
            actual_origin = origin.replace("target.com", host)

            r = await session.get(
                endpoint,
                headers={"Origin": actual_origin},
                timeout=8,
                follow_redirects=True
            )
            acao = r.headers.get("Access-Control-Allow-Origin", "")
            acac = r.headers.get("Access-Control-Allow-Credentials", "")

            if not acao:
                continue

            # Wildcard CORS
            if acao == "*":
                findings.append({
                    "type": "CORS - Wildcard Origin",
                    "severity": "MEDIUM",
                    "endpoint": endpoint,
                    "origin_tested": actual_origin,
                    "vector": description,
                    "evidence": f"Access-Control-Allow-Origin: *",
                    "confidence": "HIGH",
                    "cwe": "CWE-942",
                    "owasp": "A05:2021",
                    "remediation": "Restrict CORS to specific trusted origins",
                })
                break

            # Reflected origin with credentials - critical
            if actual_origin in acao and acac.lower() == "true":
                findings.append({
                    "type": "CORS - Origin Reflection with Credentials",
                    "severity": "CRITICAL",
                    "endpoint": endpoint,
                    "origin_tested": actual_origin,
                    "vector": description,
                    "evidence": f"ACAO: {acao} | ACAC: {acac}",
                    "confidence": "HIGH",
                    "cwe": "CWE-942",
                    "owasp": "A05:2021",
                    "poc": (
                        f'fetch("{endpoint}", {{credentials:"include"}}).then(r=>r.text()).then(d=>console.log(d))'
                    ),
                    "remediation": "Never reflect arbitrary origins when Allow-Credentials is true",
                })
                break

            # Reflected origin without credentials - medium
            if actual_origin in acao:
                findings.append({
                    "type": "CORS - Origin Reflection",
                    "severity": "MEDIUM",
                    "endpoint": endpoint,
                    "origin_tested": actual_origin,
                    "vector": description,
                    "evidence": f"ACAO reflects supplied origin: {acao}",
                    "confidence": "MEDIUM",
                    "cwe": "CWE-942",
                    "owasp": "A05:2021",
                    "remediation": "Validate origins against an allowlist",
                })

            # Null origin accepted
            if origin == "null" and "null" in acao:
                findings.append({
                    "type": "CORS - Null Origin Accepted",
                    "severity": "HIGH",
                    "endpoint": endpoint,
                    "origin_tested": "null",
                    "vector": description,
                    "evidence": f"ACAO: null — exploitable from sandboxed iframes",
                    "confidence": "HIGH",
                    "cwe": "CWE-942",
                    "owasp": "A05:2021",
                    "remediation": "Never allowlist the null origin",
                })

    except Exception:
        pass
    return findings
