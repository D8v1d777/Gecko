"""GECKO APOCALYPSE - JS Framework Hunter (React DevTools, Vue state, Angular injection, prototype pollution, DOM clobbering, source maps, PostMessage, localStorage)"""

import asyncio
import re
from typing import Dict, List, Optional
from urllib.parse import urljoin, urlparse

import aiohttp


class JSFrameworkHunter:
    def __init__(self, session, config, db):
        self.session = session
        self.config = config
        self.db = db

    async def scan(self, url, content, headers, response):
        findings = []
        for t in [
            self._prototype_pollution,
            self._source_maps,
            self._dom_clobbering,
            self._postmessage,
            self._localstorage,
            self._react_devtools,
            self._vue_state,
            self._angular_injection,
            self._frontend_routes,
        ]:
            r = await t(url, content, headers)
            if r:
                findings.append(r) if isinstance(r, dict) else findings.extend(r)
        return findings

    async def _prototype_pollution(self, url, content, headers):
        indicators = [
            "__proto__",
            "constructor.prototype",
            "Object.assign",
            "merge(",
            "extend(",
            "defaultsDeep",
        ]
        if any(i in content for i in indicators):
            return {
                "type": "Prototype Pollution Risk",
                "severity": "MEDIUM",
                "url": url,
                "evidence": "Prototype pollution patterns found in JS",
                "remediation": "Use Object.create(null), validate merge inputs",
                "cwe": "CWE-1321",
            }

    async def _source_maps(self, url, content, headers):
        maps = re.findall(r"//# sourceMappingURL=(\S+)", content)
        sm_header = headers.get("SourceMap", headers.get("X-SourceMap", ""))
        if sm_header:
            maps.append(sm_header)
        for m in maps[:3]:
            map_url = m if m.startswith("http") else urljoin(url, m)
            try:
                async with self.session.get(
                    map_url, timeout=aiohttp.ClientTimeout(total=10)
                ) as r:
                    if r.status == 200 and "sources" in await r.text(errors="ignore"):
                        return {
                            "type": "Source Maps Exposed",
                            "severity": "LOW",
                            "url": map_url,
                            "evidence": "JavaScript source maps publicly accessible",
                            "remediation": "Remove source maps from production",
                            "cwe": "CWE-540",
                        }
            except:
                pass

    async def _dom_clobbering(self, url, content, headers):
        patterns = [
            r"document\.\w+\s*\|\|",
            r"window\.\w+\s*\|\|",
            r"getElementById.*\.textContent",
            r"getElementsByName.*\[0\]",
        ]
        for p in patterns:
            if re.search(p, content):
                return {
                    "type": "DOM Clobbering Risk",
                    "severity": "MEDIUM",
                    "url": url,
                    "evidence": f"DOM clobbering pattern: {p}",
                    "remediation": "Validate DOM element references",
                    "cwe": "CWE-79",
                }

    async def _postmessage(self, url, content, headers):
        if "addEventListener" in content and "message" in content:
            if not re.search(r"event\.origin\s*[!=]==", content) and not re.search(
                r"e\.origin\s*[!=]==", content
            ):
                return {
                    "type": "PostMessage No Origin Check",
                    "severity": "HIGH",
                    "url": url,
                    "evidence": "postMessage handler without origin validation",
                    "remediation": "Always validate event.origin",
                    "cwe": "CWE-346",
                }

    async def _localstorage(self, url, content, headers):
        sensitive = [
            "token",
            "password",
            "secret",
            "apikey",
            "api_key",
            "auth",
            "session",
            "jwt",
            "credit",
        ]
        ls_writes = re.findall(r'localStorage\.setItem\(["\'](\w+)["\']', content)
        ss_writes = re.findall(r'sessionStorage\.setItem\(["\'](\w+)["\']', content)
        found = [
            k for k in ls_writes + ss_writes if any(s in k.lower() for s in sensitive)
        ]
        if found:
            return {
                "type": "Sensitive Data in Storage",
                "severity": "MEDIUM",
                "url": url,
                "evidence": f'Keys: {", ".join(found)}',
                "remediation": "Avoid storing sensitive data in localStorage/sessionStorage",
                "cwe": "CWE-922",
            }

    async def _react_devtools(self, url, content, headers):
        if (
            "__REACT_DEVTOOLS_GLOBAL_HOOK__" in content
            or "_reactRootContainer" in content
        ):
            if "__NEXT_DATA__" in content:
                # Check for exposed server data
                match = re.search(
                    r'<script id="__NEXT_DATA__"[^>]*>(.*?)</script>', content
                )
                if match:
                    try:
                        data = match.group(1)
                        if any(
                            s in data.lower()
                            for s in ["apikey", "secret", "token", "password"]
                        ):
                            return {
                                "type": "Next.js Data Leak",
                                "severity": "HIGH",
                                "url": url,
                                "evidence": "Sensitive data in __NEXT_DATA__",
                                "cwe": "CWE-200",
                            }
                    except:
                        pass

    async def _vue_state(self, url, content, headers):
        if "__vue__" in content or "Vue.config" in content:
            if (
                "Vue.config.devtools=!0" in content
                or "Vue.config.devtools = true" in content
            ):
                return {
                    "type": "Vue DevTools Enabled",
                    "severity": "LOW",
                    "url": url,
                    "evidence": "Vue.js devtools enabled in production",
                    "cwe": "CWE-489",
                }

    async def _angular_injection(self, url, content, headers):
        if "ng-app" in content or "angular" in content.lower():
            # Test Angular template injection indicators
            if "{{" in content and "}}" in content:
                if re.search(r"\{\{[^}]*constructor[^}]*\}\}", content):
                    return {
                        "type": "Angular Template Injection",
                        "severity": "HIGH",
                        "url": url,
                        "evidence": "Angular template with constructor access",
                        "cwe": "CWE-94",
                    }

    async def _frontend_routes(self, url, content, headers):
        """Enumerate frontend routes from JS bundles."""
        routes = set()
        route_patterns = [
            r'path:\s*["\'](/[^"\']+)["\']',
            r'route:\s*["\'](/[^"\']+)["\']',
            r'to:\s*["\'](/[^"\']+)["\']',
            r'href:\s*["\'](/[^"\']+)["\']',
        ]
        for p in route_patterns:
            routes.update(re.findall(p, content))
        admin_routes = [
            r
            for r in routes
            if any(
                k in r.lower()
                for k in ["admin", "manage", "config", "debug", "internal"]
            )
        ]
        if admin_routes:
            return {
                "type": "Hidden Frontend Routes",
                "severity": "INFO",
                "url": url,
                "evidence": f'Routes: {", ".join(admin_routes[:10])}',
                "cwe": "CWE-200",
            }
