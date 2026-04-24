import asyncio
import os
import sys

import httpx

from dashboard import broadcast
from core.context_store import ContextStore
from core.crawler import AsyncCrawler
from modules.cors import CORSModule
from modules.graphql_fuzz import GraphQLFuzzModule
from modules.http_smuggling import HTTPSmugglingModule
from modules.idor import IDORModule
try:
    from modules.jwt_scan import JWTModule
except Exception:
    class JWTModule:
        name = "jwt"

        async def run(self, target, session, context):
            return []

from modules.race_condition import RaceConditionModule
from modules.ssrf import SSRFModule
from modules.subdomain import SubdomainModule

# Advanced bug-bounty modules
from modules.xss_scanner import XSSScanner
from modules.sqli_scanner import SQLiScanner
from modules.idor_advanced import IDORAdvanced
from modules.cors_advanced import CORSAdvanced
from modules.security_headers import SecurityHeaders
from modules.open_redirect_scanner import OpenRedirectScanner
from modules.info_disclosure import InfoDisclosure
from modules.auth_tester import AuthTester
from modules.network_web_correlator import NetworkWebCorrelator

MODULES = [
    # Core modules (existing)
    SSRFModule(),
    CORSModule(),
    JWTModule(),
    SubdomainModule(),
    IDORModule(),
    GraphQLFuzzModule(),
    HTTPSmugglingModule(),
    RaceConditionModule(),
    # Advanced bug-bounty modules (new)
    XSSScanner(),
    SQLiScanner(),
    IDORAdvanced(),
    CORSAdvanced(),
    SecurityHeaders(),
    OpenRedirectScanner(),
    InfoDisclosure(),
    AuthTester(),
    NetworkWebCorrelator(),
]


async def run_scan(target, selected_modules=None, threads=20, headers=None, crawl_depth=2):
    results = []

    if headers is None:
        headers = {}

    async with httpx.AsyncClient(verify=False, headers=headers, timeout=15) as session:
        # Initialize context store and crawler
        ctx_store = ContextStore()
        crawler = AsyncCrawler(target, session, ctx_store, max_depth=crawl_depth)

        from rich import print
        print(f"[bold cyan]Crawling {target} (depth={crawl_depth})...[/]")
        await crawler.crawl()

        context_data = ctx_store.dump()
        # Convert sets to lists for JSON serialisation and module usage
        context_data["endpoints"] = list(context_data.get("endpoints", set()))
        context_data["params"] = list(context_data.get("params", set()))
        context_data["technologies"] = list(context_data.get("technologies", set()))

        endpoints_found = len(context_data["endpoints"])
        params_found = len(context_data["params"])
        print(f"[bold green]Discovered {endpoints_found} endpoints and {params_found} parameters.[/]")

        # Filter modules if --modules flag provided
        modules = MODULES
        if selected_modules:
            modules = [m for m in MODULES if m.name in selected_modules]

        print(f"[bold yellow]Running {len(modules)} modules...[/]")

        # Pass populated context instead of empty dict
        tasks = [m.run(target, session, context_data) for m in modules]
        responses = await asyncio.gather(*tasks, return_exceptions=True)

        for i, r in enumerate(responses):
            if isinstance(r, Exception):
                print(f"[red]Module error ({modules[i].name}): {r}[/]")
            elif isinstance(r, list):
                results.extend(r)

    return results
