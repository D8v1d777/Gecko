"""
GECKO - Advanced IDOR / BOLA Scanner
Tests REST API endpoints for Broken Object Level Authorization.
Compares responses when accessing other users' resources.
"""
import asyncio
import json
import re
from urllib.parse import urlparse


# Sensitive fields that indicate data exposure in API responses
SENSITIVE_FIELDS = [
    "password", "passwordhash", "passwordhash", "totpsecret",
    "isadmin", "role", "token", "email", "createdAt", "deletedAt",
    "deluxetoken", "lastloginin",
]

# Range of IDs to probe
ID_PROBE_RANGE = list(range(1, 21))


def _replace_id(endpoint, new_id):
    return re.sub(r'/(\d+)([/?]|$)', f'/{new_id}\\2', endpoint)


def _has_numeric_id(endpoint):
    return bool(re.search(r'/\d+', endpoint))


def _extract_sensitive(data, endpoint):
    """Check if JSON response exposes sensitive fields."""
    exposed = []
    try:
        obj = data if isinstance(data, (dict, list)) else json.loads(data)
        def _walk(node):
            if isinstance(node, dict):
                for k, v in node.items():
                    if k.lower() in SENSITIVE_FIELDS and v:
                        exposed.append(f"{k}={str(v)[:40]}")
                    _walk(v)
            elif isinstance(node, list):
                for item in node[:5]:
                    _walk(item)
        _walk(obj)
    except Exception:
        pass
    return exposed


class IDORAdvanced:
    name = "idor_advanced"
    severity = "high"

    async def run(self, target, session, context):
        findings = []
        seen = set()

        endpoints = list(context.get("endpoints") or [])
        endpoint_scores = context.get("endpoint_scores") or {}

        # Sort by score descending (admin/api endpoints first)
        endpoints.sort(key=lambda e: endpoint_scores.get(e, 1), reverse=True)

        tasks = []

        for endpoint in endpoints[:40]:
            # Test 1: Numeric ID enumeration
            if _has_numeric_id(endpoint):
                key = f"idor|{endpoint}"
                if key not in seen:
                    seen.add(key)
                    tasks.append(_test_idor_enum(session, endpoint, target))

            # Test 2: Collection endpoints - check if unauthenticated access returns all data
            if any(seg in endpoint for seg in ["/api/users", "/api/orders", "/api/BasketItems"]):
                key = f"collection|{endpoint}"
                if key not in seen:
                    seen.add(key)
                    tasks.append(_test_collection_exposure(session, endpoint))

            # Test 3: Admin/sensitive endpoint access
            if any(seg in endpoint.lower() for seg in ["/admin", "/administration", "/config"]):
                key = f"admin|{endpoint}"
                if key not in seen:
                    seen.add(key)
                    tasks.append(_test_admin_access(session, endpoint))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, list):
                findings.extend(r)
            elif isinstance(r, dict):
                findings.append(r)

        return findings


async def _test_idor_enum(session, endpoint, target):
    findings = []
    try:
        # Baseline: get the original endpoint
        baseline_r = await session.get(endpoint, timeout=8, follow_redirects=True)
        baseline_status = baseline_r.status_code
        baseline_len = len(baseline_r.text)

        if baseline_status == 404:
            return findings

        # Probe other IDs
        different_responses = 0
        for probe_id in ID_PROBE_RANGE[:10]:
            probed_url = _replace_id(endpoint, probe_id)
            if probed_url == endpoint:
                continue
            try:
                r = await session.get(probed_url, timeout=8, follow_redirects=True)
                if r.status_code == 200 and r.status_code != baseline_status:
                    different_responses += 1

                if r.status_code == 200:
                    # Check for sensitive data exposure
                    ct = r.headers.get("content-type", "")
                    if "json" in ct:
                        exposed = _extract_sensitive(r.text, probed_url)
                        if exposed:
                            findings.append({
                                "type": "IDOR - Sensitive Data Exposure",
                                "severity": "HIGH",
                                "endpoint": probed_url,
                                "evidence": f"Exposed fields: {', '.join(exposed[:5])}",
                                "confidence": "HIGH",
                                "cwe": "CWE-639",
                                "owasp": "A01:2021",
                                "remediation": "Implement object-level authorization checks on every request",
                            })
            except Exception:
                continue

        if different_responses >= 3 and not findings:
            findings.append({
                "type": "IDOR - Object Enumeration",
                "severity": "MEDIUM",
                "endpoint": endpoint,
                "evidence": f"{different_responses} different IDs returned HTTP 200",
                "confidence": "MEDIUM",
                "cwe": "CWE-639",
                "owasp": "A01:2021",
                "remediation": "Use unpredictable identifiers (UUIDs) and validate ownership",
            })

    except Exception:
        pass
    return findings


async def _test_collection_exposure(session, endpoint):
    try:
        r = await session.get(endpoint, timeout=8, follow_redirects=True)
        if r.status_code == 200:
            ct = r.headers.get("content-type", "")
            if "json" in ct:
                exposed = _extract_sensitive(r.text, endpoint)
                # Check if we got a list of items
                try:
                    data = r.json()
                    count = len(data) if isinstance(data, list) else (
                        len(data.get("data", [])) if isinstance(data, dict) else 0
                    )
                except Exception:
                    count = 0

                if count > 0 or exposed:
                    return {
                        "type": "BFLA - Unauthenticated Collection Access",
                        "severity": "HIGH",
                        "endpoint": endpoint,
                        "evidence": f"Returned {count} items without authentication"
                                    + (f". Sensitive fields: {', '.join(exposed[:5])}" if exposed else ""),
                        "confidence": "HIGH",
                        "cwe": "CWE-285",
                        "owasp": "A01:2021",
                        "remediation": "Require authentication for all data endpoints",
                    }
    except Exception:
        pass
    return None


async def _test_admin_access(session, endpoint):
    try:
        r = await session.get(endpoint, timeout=8, follow_redirects=True)
        if r.status_code == 200:
            return {
                "type": "Unauthorized Admin Access",
                "severity": "CRITICAL",
                "endpoint": endpoint,
                "evidence": f"HTTP 200 returned for admin endpoint without authentication",
                "confidence": "HIGH",
                "cwe": "CWE-285",
                "owasp": "A01:2021",
                "remediation": "Restrict admin endpoints to authorized roles only",
            }
    except Exception:
        pass
    return None
