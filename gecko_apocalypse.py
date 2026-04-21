import asyncio
import os
import sys

import httpx

from dashboard import broadcast
from modules.cors import CORSModule
from modules.graphql_fuzz import GraphQLFuzzModule
from modules.http_smuggling import HTTPSmugglingModule
from modules.idor import IDORModule
from modules.jwt_scan import JWTModule
from modules.race_condition import RaceConditionModule
from modules.ssrf import SSRFModule
from modules.subdomain import SubdomainModule

MODULES = [
    SSRFModule(),
    CORSModule(),
    JWTModule(),
    SubdomainModule(),
    IDORModule(),
    GraphQLFuzzModule(),
    HTTPSmugglingModule(),
    RaceConditionModule(),
]


async def run_scan(target, selected_modules=None, threads=20):
    results = []

    async with httpx.AsyncClient(verify=False) as session:
        # filter modules if provided
        modules = MODULES

        if selected_modules:
            modules = [m for m in MODULES if m.name in selected_modules]

        # Note: We are using a simple dict {} for context as requested
        tasks = [m.run(target, session, {}) for m in modules]

        responses = await asyncio.gather(*tasks)

        for r in responses:
            results.extend(r)

    return results
