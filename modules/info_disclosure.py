"""
GECKO - Information Disclosure Scanner
Probes for sensitive files, error messages, stack traces, and API spec exposure.
"""
import asyncio
import re
import json


# Sensitive paths to probe
SENSITIVE_PATHS = [
    # Source code / config leaks
    ("/.git/HEAD", "Git repository exposed"),
    ("/.git/config", "Git config exposed"),
    ("/.env", ".env file exposed"),
    ("/.env.local", ".env.local exposed"),
    ("/.env.production", ".env.production exposed"),
    ("/config.js", "Config JS exposed"),
    ("/config.json", "Config JSON exposed"),
    ("/configuration.json", "Configuration JSON exposed"),
    ("/package.json", "package.json exposed"),
    ("/composer.json", "composer.json exposed"),

    # API documentation
    ("/swagger.json", "Swagger API spec exposed"),
    ("/swagger/v1/swagger.json", "Swagger v1 spec exposed"),
    ("/api-docs", "API docs exposed"),
    ("/api/swagger", "Swagger API exposed"),
    ("/openapi.json", "OpenAPI spec exposed"),
    ("/openapi.yaml", "OpenAPI YAML exposed"),
    ("/graphql", "GraphQL endpoint exposed"),

    # Monitoring / debug
    ("/server-status", "Apache server-status exposed"),
    ("/server-info", "Apache server-info exposed"),
    ("/actuator", "Spring Boot Actuator exposed"),
    ("/actuator/env", "Actuator env dump"),
    ("/actuator/health", "Actuator health"),
    ("/actuator/mappings", "Actuator route mappings"),
    ("/debug", "Debug endpoint"),
    ("/_profiler", "Symfony profiler"),
    ("/phpinfo.php", "PHP info exposed"),
    ("/__debug__", "Django debug toolbar"),
    ("/metrics", "Prometheus metrics exposed"),
    ("/health", "Health endpoint"),
    ("/status", "Status endpoint"),

    # Backup files
    ("/backup.zip", "Backup archive"),
    ("/backup.sql", "SQL backup"),
    ("/dump.sql", "SQL dump"),
    ("/db.sqlite", "SQLite database"),
    ("/database.sqlite", "SQLite database"),

    # OWASP Juice Shop specifics
    ("/ftp", "FTP directory listing"),
    ("/ftp/acquisitions.md", "Sensitive acquisitions file"),
    ("/rest/admin/application-configuration", "Admin config exposed"),
    ("/rest/admin/application-version", "App version exposed"),
    ("/rest/chatbot/status", "Chatbot status"),
    ("/support/logs", "Support logs exposed"),
]

# Patterns indicating sensitive data in responses
SENSITIVE_PATTERNS = [
    (r"stack trace", "Stack trace in response"),
    (r"exception in thread", "Java exception"),
    (r"at [a-z]+\.[a-z]+\.[a-z]+\(", "Stack trace line"),
    (r"warning:.*php", "PHP warning"),
    (r"fatal error.*php", "PHP fatal error"),
    (r"traceback \(most recent call", "Python traceback"),
    (r"debug=true", "Debug mode enabled"),
    (r"secret[_\s]?key\s*[=:]\s*\S+", "Secret key in response"),
    (r"api[_\s]?key\s*[=:]\s*['\"]?\w{16,}", "API key in response"),
    (r"password\s*[=:]\s*['\"]?\S+", "Password in response"),
    (r"token\s*[=:]\s*['\"]?[a-zA-Z0-9+/=]{20,}", "Token in response"),
    (r"-----BEGIN (RSA |EC )?PRIVATE KEY-----", "Private key exposed"),
    (r"aws[_\s]?access[_\s]?key[_\s]?id\s*[=:]\s*[A-Z0-9]{20}", "AWS Access Key"),
]

PATTERN_RE = [(re.compile(p, re.IGNORECASE), desc) for p, desc in SENSITIVE_PATTERNS]


class InfoDisclosure:
    name = "info_disclosure"
    severity = "medium"

    async def run(self, target, session, context):
        findings = []
        base = target.rstrip("/")

        # Probe all sensitive paths
        tasks = [_probe_path(session, base, path, desc) for path, desc in SENSITIVE_PATHS]

        # Also scan discovered API endpoints for sensitive data in responses
        api_endpoints = [e for e in (context.get("endpoints") or []) if "/api/" in e or "/rest/" in e]
        for ep in api_endpoints[:15]:
            tasks.append(_scan_response_for_secrets(session, ep))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, dict):
                findings.append(r)
            elif isinstance(r, list):
                findings.extend(r)

        return findings


async def _probe_path(session, base, path, description):
    url = f"{base}{path}"
    try:
        r = await session.get(url, timeout=8, follow_redirects=True)
        if r.status_code == 200:
            body = r.text[:2000]
            severity = "HIGH"
            cwe = "CWE-200"

            # Escalate severity for truly sensitive paths
            if any(s in path for s in [".git", ".env", "swagger", "api-docs", "openapi", "actuator/env"]):
                severity = "CRITICAL"
            elif any(s in path for s in ["backup", "dump", "database", "private"]):
                severity = "CRITICAL"

            return {
                "type": "Information Disclosure",
                "severity": severity,
                "endpoint": url,
                "description": description,
                "evidence": f"HTTP 200 returned for {path} | Size: {len(r.text)} bytes",
                "snippet": body[:300],
                "confidence": "HIGH",
                "cwe": cwe,
                "owasp": "A05:2021",
                "remediation": f"Restrict access to {path} via server configuration or remove the file",
            }
    except Exception:
        pass
    return None


async def _scan_response_for_secrets(session, endpoint):
    findings = []
    try:
        r = await session.get(endpoint, timeout=8, follow_redirects=True)
        if r.status_code != 200:
            return findings

        body = r.text
        for pattern, desc in PATTERN_RE:
            match = pattern.search(body)
            if match:
                findings.append({
                    "type": "Sensitive Data in Response",
                    "severity": "HIGH",
                    "endpoint": endpoint,
                    "description": desc,
                    "evidence": f"Pattern matched: '{match.group(0)[:80]}'",
                    "confidence": "MEDIUM",
                    "cwe": "CWE-312",
                    "owasp": "A02:2021",
                    "remediation": "Do not expose sensitive data in API responses",
                })
    except Exception:
        pass
    return findings
