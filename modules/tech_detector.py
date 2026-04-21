"""GECKO APOCALYPSE - Technology Detector (Wappalyzer-style fingerprinting)"""

from typing import Dict, List


class TechDetector:
    def __init__(self, session, config, db):
        self.session = session
        self.config = config
        self.db = db

    async def scan(self, url, content, headers, response):
        findings = []
        h = dict(headers)
        # CMS detection
        for cms in self._cms(content, h):
            findings.append(
                {
                    "type": "Technology Detection",
                    "severity": "INFO",
                    "url": url,
                    "evidence": f"CMS: {cms}",
                }
            )
        # Server banner
        server = h.get("Server", h.get("server", ""))
        if server:
            findings.append(
                {
                    "type": "Server Banner Disclosure",
                    "severity": "INFO",
                    "url": url,
                    "evidence": f"Server: {server}",
                    "remediation": "Remove server version info",
                    "cwe": "CWE-200",
                }
            )
            # Check for outdated versions
            if any(
                v in server
                for v in [
                    "Apache/2.2",
                    "Apache/2.0",
                    "nginx/1.1",
                    "nginx/1.0",
                    "IIS/6",
                    "IIS/7",
                ]
            ):
                findings.append(
                    {
                        "type": "Outdated Server Version",
                        "severity": "MEDIUM",
                        "url": url,
                        "evidence": f"Outdated: {server}",
                        "remediation": "Upgrade server software",
                        "cwe": "CWE-1104",
                    }
                )
        # X-Powered-By
        xpb = h.get("X-Powered-By", h.get("x-powered-by", ""))
        if xpb:
            findings.append(
                {
                    "type": "X-Powered-By Disclosure",
                    "severity": "LOW",
                    "url": url,
                    "evidence": f"X-Powered-By: {xpb}",
                    "remediation": "Remove X-Powered-By header",
                    "cwe": "CWE-200",
                }
            )
        return findings

    def _cms(self, c, h):
        sigs = {
            "WordPress": ["/wp-content/", "/wp-includes/"],
            "Drupal": ["Drupal", "/sites/default/"],
            "Joomla": ["Joomla", "/components/"],
            "Magento": ["Magento"],
            "Shopify": ["cdn.shopify.com"],
        }
        return [k for k, v in sigs.items() if any(s in c for s in v)]
