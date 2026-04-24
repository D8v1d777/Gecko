import asyncio
import re
import xml.etree.ElementTree as ET
from bs4 import BeautifulSoup
from core.extractor import Extractor


# Common REST API endpoints for typical web apps / OWASP Juice Shop
COMMON_ENDPOINTS = [
    "/api/products",
    "/api/users",
    "/api/users/1",
    "/api/users/2",
    "/api/users/3",
    "/api/BasketItems",
    "/api/Baskets",
    "/api/Challenges",
    "/api/Feedbacks",
    "/api/Complaints",
    "/api/Deliverys",
    "/api/SecurityQuestions",
    "/api/SecurityAnswers",
    "/api/Quantitys",
    "/api/PrivacyRequests",
    "/api/Addresss",
    "/api/Cards",
    "/api/Orders",
    "/rest/user/login",
    "/rest/user/change-password",
    "/rest/user/reset-password",
    "/rest/user/whoami",
    "/rest/basket",
    "/rest/products/search",
    "/rest/captcha",
    "/rest/memories",
    "/rest/track-order/1",
    "/administration",
    "/profile",
    "/login",
    "/register",
    "/logout",
    "/forgot-password",
    "/about",
    "/contact",
    "/search",
]

# Common parameters found in juice shop / typical web apps
COMMON_PARAMS = [
    "q", "query", "search", "id", "user", "username", "email",
    "password", "token", "redirect", "url", "callback", "returnUrl",
    "next", "dest", "destination", "redir", "redirectUri",
]


class AsyncCrawler:
    def __init__(self, target, session, context_store, max_depth=2):
        self.target = target.rstrip("/")
        self.session = session
        self.context_store = context_store
        self.max_depth = max_depth
        self.visited = set()
        self.extractor = Extractor(self.context_store)
        self._js_files = set()

    async def crawl(self):
        """Main crawl entry point: seed, parse robots/sitemap, crawl HTML, extract JS routes."""
        self._seed_common_endpoints()
        # Run robots.txt and sitemap in parallel with base page crawl
        await asyncio.gather(
            self._parse_robots_txt(),
            self._parse_sitemap(),
            self._crawl_url(self.target, depth=0),
        )
        await self._extract_js_api_routes()

    def _seed_common_endpoints(self):
        """Pre-seed context store with well-known API endpoints and parameters."""
        for ep in COMMON_ENDPOINTS:
            self.context_store.add_endpoint(f"{self.target}{ep}")
        for p in COMMON_PARAMS:
            self.context_store.add_param(p)

    async def _parse_robots_txt(self):
        """Parse robots.txt to discover disallowed (often sensitive) paths."""
        try:
            r = await self.session.get(f"{self.target}/robots.txt", timeout=5, follow_redirects=True)
            if r.status_code == 200:
                for line in r.text.splitlines():
                    line = line.strip()
                    if line.lower().startswith("disallow:") or line.lower().startswith("allow:"):
                        path = line.split(":", 1)[1].strip()
                        if path and path != "/":
                            self.context_store.add_endpoint(f"{self.target}{path}")
        except Exception:
            pass

    async def _parse_sitemap(self):
        """Parse sitemap.xml for additional URLs."""
        for sitemap_path in ["/sitemap.xml", "/sitemap_index.xml"]:
            try:
                r = await self.session.get(f"{self.target}{sitemap_path}", timeout=5, follow_redirects=True)
                if r.status_code == 200 and "xml" in r.headers.get("content-type", ""):
                    root = ET.fromstring(r.text)
                    ns = {"sm": "http://www.sitemaps.org/schemas/sitemap/0.9"}
                    for loc in root.findall(".//sm:loc", ns):
                        url = loc.text.strip() if loc.text else ""
                        if url.startswith(self.target):
                            self.context_store.add_endpoint(url)
            except Exception:
                pass

    async def _crawl_url(self, url, depth):
        if depth > self.max_depth or url in self.visited:
            return
        self.visited.add(url)
        try:
            r = await self.session.get(url, timeout=8, follow_redirects=True)
            self.extractor.process(r, url)
            content_type = r.headers.get("Content-Type", "")

            if "text/html" in content_type:
                soup = BeautifulSoup(r.text, "html.parser")

                # Collect links
                links = []
                for a in soup.find_all("a", href=True):
                    href = a["href"]
                    if href.startswith("/") and not href.startswith("//"):
                        links.append(f"{self.target}{href}")
                    elif href.startswith(self.target):
                        links.append(href)

                # Collect forms + params
                for form in soup.find_all("form"):
                    action = form.get("action", "")
                    if action.startswith("/"):
                        action = f"{self.target}{action}"
                    elif not action.startswith("http"):
                        action = f"{self.target}/{action}"
                    self.context_store.add_endpoint(action)
                    for inp in form.find_all("input", name=True):
                        self.context_store.add_param(inp["name"])
                    for sel in form.find_all("select", name=True):
                        self.context_store.add_param(sel["name"])
                    for ta in form.find_all("textarea", name=True):
                        self.context_store.add_param(ta["name"])

                # Collect JS bundle files for SPA route extraction
                for script in soup.find_all("script", src=True):
                    src = script["src"]
                    if src.startswith("/") and not src.startswith("//"):
                        self._js_files.add(f"{self.target}{src}")
                    elif src.startswith("http"):
                        self._js_files.add(src)

                # Extract inline script content
                for script in soup.find_all("script"):
                    if not script.get("src") and script.string:
                        await self._parse_js_for_routes(script.string)

                # Recurse into links
                tasks = [
                    self._crawl_url(link, depth + 1)
                    for link in links
                    if link not in self.visited
                ]
                if tasks:
                    await asyncio.gather(*tasks)

            elif "javascript" in content_type or url.endswith(".js"):
                await self._parse_js_for_routes(r.text)

        except Exception:
            pass

    async def _extract_js_api_routes(self):
        """Fetch and parse all collected JS bundle files for embedded API routes."""
        tasks = []
        for js_url in self._js_files:
            if js_url not in self.visited:
                self.visited.add(js_url)
                tasks.append(self._fetch_and_parse_js(js_url))
        if tasks:
            await asyncio.gather(*tasks)

    async def _fetch_and_parse_js(self, url):
        try:
            r = await self.session.get(url, timeout=10, follow_redirects=True)
            await self._parse_js_for_routes(r.text)
        except Exception:
            pass

    async def _parse_js_for_routes(self, text):
        """Extract API paths from JavaScript using regex."""
        # Match paths like "/api/...", "/rest/...", etc.
        api_patterns = re.findall(r'["\'](/(?:api|rest|assets|admin|ftp)[^"\'<> ]{1,80})["\']', text)
        for path in api_patterns:
            if "${" not in path and "{{" not in path:
                self.context_store.add_endpoint(f"{self.target}{path}")

        # Extract endpoint paths from fetch/axios/http calls
        fetch_patterns = re.findall(r'(?:fetch|get|post|put|delete|axios)\s*\(\s*["\']([^"\']{5,100})["\']', text)
        for path in fetch_patterns:
            if path.startswith("/"):
                self.context_store.add_endpoint(f"{self.target}{path}")
            elif path.startswith("http"):
                self.context_store.add_endpoint(path)

        # Extract query parameter names from JS objects
        param_blocks = re.findall(r'params\s*[=:]\s*\{([^}]{1,200})\}', text)
        for block in param_blocks:
            for key in re.findall(r'["\']?(\w+)["\']?\s*:', block):
                if len(key) < 30:
                    self.context_store.add_param(key)
