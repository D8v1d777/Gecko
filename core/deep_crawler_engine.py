import asyncio
import hashlib
import json
import logging
import re
import time
from dataclasses import dataclass, field
from typing import Dict, List, Set, Callable, Any, Optional
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, quote
from collections import defaultdict

import aiohttp
import tenacity
from aiolimiter import AsyncLimiter
from bs4 import BeautifulSoup
from core.finding import Finding, Severity

logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s")
logger = logging.getLogger("DeepSecurityCrawler")

@dataclass
class CrawlConfig:
    base_url: str
    allowed_domains: Set[str]
    max_depth: int = 4
    max_pages: int = 1500
    delay: float = 0.15
    timeout: float = 15
    user_agent: str = "AuthorizedScanner/2.1"
    render_js: bool = False
    proxy: Optional[str] = None
    headers: Dict[str, str] = field(default_factory=dict)
    authorization_verified: bool = True  # Tool is pre-authorized by entities


class FindingsManager:
    def __init__(self):
        self.findings: List[Finding] = []
        self._seen_hashes: Set[str] = set()

    def _hash_finding(self, f: Finding) -> str:
        raw = f"{f.url}|{f.type}|{f.evidence}|{json.dumps(f.context, sort_keys=True)}"
        return hashlib.sha256(raw.encode()).hexdigest()

    def add(self, finding: Finding) -> bool:
        h = self._hash_finding(finding)
        if h not in self._seen_hashes:
            self._seen_hashes.add(h)
            self.findings.append(finding)
            return True
        return False

    def export_json(self) -> str:
        return json.dumps([f.__dict__ for f in self.findings], indent=2)

class URLCanonicalizer:
    @staticmethod
    def normalize(url: str) -> str:
        parsed = urlparse(url)
        query = parse_qs(parsed.query, keep_blank_values=True)
        # Sort query params, remove tracking params, normalize fragments
        clean_query = {k: sorted(v) for k, v in query.items() if not k.startswith(('utm_', 'fbclid', 'gclid'))}
        normalized = urljoin(f"{parsed.scheme}://{parsed.netloc}{parsed.path}", urlencode(clean_query, doseq=True))
        return normalized.rstrip('/')

class DeepSecurityCrawler:
    def __init__(self, config: CrawlConfig):
        self.config = config
        self.visited: Set[str] = set()
        self.queue: asyncio.Queue = asyncio.Queue()
        self.findings = FindingsManager()
        self.limiter = AsyncLimiter(max_rate=15, time_period=1)
        self.session: Optional[aiohttp.ClientSession] = None
        self.plugins: List[Callable] = []
        self._csrf_tokens: Dict[str, str] = {}
        self._cookies = aiohttp.CookieJar()
        self._canon = URLCanonicalizer()

        if not config.authorization_verified:
            logger.warning("Authorization not verified. Active testing plugins will be bypassed.")

    def register_plugin(self, callback: Callable):
        self.plugins.append(callback)

    @tenacity.retry(
        stop=tenacity.stop_after_attempt(3),
        wait=tenacity.wait_exponential(multiplier=1, min=2, max=10),
        retry=tenacity.retry_if_exception_type((aiohttp.ClientError, asyncio.TimeoutError))
    )
    async def fetch(self, url: str) -> tuple[str, Optional[dict]]:
        canon = self._canon.normalize(url)
        if canon in self.visited or not self._in_scope(url):
            return "", None

        async with self.limiter:
            async with self.session.get(
                url, timeout=aiohttp.ClientTimeout(total=self.config.timeout),
                headers={"User-Agent": self.config.user_agent, **self.config.headers},
                cookies=self._cookies
            ) as resp:
                if resp.status >= 500:
                    resp.raise_for_status()
                text = await resp.text()
                self._cookies.update_cookies(resp.cookies)
                self._extract_state(text, url)
                return text, dict(resp.headers)

    def _extract_state(self, html: str, url: str):
        soup = BeautifulSoup(html, "html.parser")
        for meta in soup.find_all("meta", attrs={"name": re.compile(r"csrf|token|nonce", re.I)}):
            self._csrf_tokens[url] = meta.get("content", "")

    def _in_scope(self, url: str) -> bool:
        domain = urlparse(url).netloc
        return domain in self.config.allowed_domains

    async def run(self):
        connector = aiohttp.TCPConnector(limit=60, ttl_dns_cache=300, force_close=True)
        async with aiohttp.ClientSession(connector=connector, cookie_jar=self._cookies) as self.session:
            await self.queue.put((self.config.base_url, 0))
            tasks = [asyncio.create_task(self._worker()) for _ in range(20)]
            await self.queue.join()
            for t in tasks: t.cancel()

    async def _worker(self):
        while True:
            url, depth = await self.queue.get()
            canon = self._canon.normalize(url)
            if canon in self.visited or depth > self.config.max_depth:
                self.queue.task_done()
                continue

            self.visited.add(canon)
            logger.info(f"[{len(self.visited)}/{self.config.max_pages}] D:{depth} {url}")

            html, headers = await self.fetch(url)
            if not html:
                self.queue.task_done()
                continue

            extracted = self._deep_extract(url, html)
            await self._process_passive_findings(url, headers, extracted)

            for plugin in self.plugins:
                try:
                    gate = "passive" if not self.config.authorization_verified else "active"
                    plugin_findings = await plugin(url, html, headers, extracted, gate=gate)
                    if plugin_findings:
                        for f in plugin_findings:
                            if isinstance(f.get("severity"), str):
                                try:
                                    f["severity"] = Severity(f["severity"].lower())
                                except ValueError:
                                    f["severity"] = Severity.INFO
                            self.findings.add(Finding(**f))
                except Exception as e:
                    logger.error(f"Plugin error on {url}: {e}")

            self._enqueue_discoveries(url, depth, extracted)
            await asyncio.sleep(self.config.delay)
            self.queue.task_done()

    def _deep_extract(self, url: str, html: str) -> Dict[str, Any]:
        soup = BeautifulSoup(html, "html.parser")
        data = {
            "forms": [], "scripts": [], "links": [], "api_hints": [],
            "hidden_params": [], "meta": {}
        }

        # Forms & parameters
        for form in soup.find_all("form"):
            action = urljoin(url, form.get("action", url))
            method = form.get("method", "get").upper()
            params = [i.get("name") for i in form.find_all(["input", "select", "textarea"]) if i.get("name")]
            data["forms"].append({"url": action, "method": method, "params": params})

        # Links & canonicalization
        for a in soup.find_all("a", href=True):
            raw = urljoin(url, a["href"])
            if raw.startswith(("http://", "https://")):
                data["links"].append(self._canon.normalize(raw))

        # Scripts & potential endpoints
        for script in soup.find_all("script", src=True):
            data["scripts"].append(urljoin(url, script["src"]))

        # API/Endpoint pattern matching
        text_pool = soup.get_text() + " ".join([s.get("src", "") for s in soup.find_all("script")])
        api_patterns = [r'/api/v\d+', r'/graphql', r'/rest/', r'/wp-json/', r'/swagger', r'/openapi', r'/\.env']
        for p in api_patterns:
            data["api_hints"].extend(set(re.findall(p, text_pool, re.I)))

        # Hidden parameter discovery
        param_patterns = [r'name=["\']([^"\']+)["\']', r'data-([^"\s=]+)', r'(?<!["\w])param[s]?["\']?\s*[:=]\s*["\']([^"\']+)["\']']
        for pat in param_patterns:
            data["hidden_params"].extend(set(re.findall(pat, html, re.I)))

        return data

    async def _process_passive_findings(self, url: str, headers: dict, extracted: dict):
        if not headers.get("Content-Security-Policy"):
            self.findings.add(Finding(url=url, type="missing_csp", severity=Severity.LOW,
                                      description="Missing Content-Security-Policy", evidence="Response lacks CSP header"))
        if extracted["api_hints"]:
            self.findings.add(Finding(url=url, type="api_surface", severity=Severity.INFO,
                                      description="Potential API endpoints detected", evidence=", ".join(extracted["api_hints"][:5])))
        if extracted["forms"]:
            self.findings.add(Finding(url=url, type="form_discovery", severity=Severity.INFO,
                                      description=f"{len(extracted['forms'])} forms found", evidence=str(extracted["forms"][:3])))

    def _enqueue_discoveries(self, base_url: str, depth: int, extracted: dict):
        if len(self.visited) >= self.config.max_pages: return
        for link in extracted["links"]:
            if self._in_scope(link) and self._canon.normalize(link) not in self.visited:
                asyncio.create_task(self.queue.put((link, depth + 1)))

    def export_findings(self) -> str:
        return self.findings.export_json()
