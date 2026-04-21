"""GECKO APOCALYPSE - GraphQL Fuzzer & Introspection"""
import asyncio, aiohttp, re, json, time
from typing import List, Dict, Optional
from urllib.parse import urlparse

class GraphQLFuzzer:
    def __init__(self, session, config, db):
        self.session = session; self.config = config; self.db = db

    async def scan(self, url, content, headers, response):
        findings = []
        if not self._is_gql(url, content, headers): return findings
        for test in [self._introspection, self._depth, self._batch, self._alias]:
            r = await test(url)
            if r: findings.append(r)
        return findings

    def _is_gql(self, url, content, headers):
        return any(['/graphql' in url.lower(), 'application/graphql' in headers.get('content-type',''),
                     '__schema' in content, '"data":' in content and '"errors":' in content])

    async def _introspection(self, url):
        q = {"query": "{ __schema { queryType { name } mutationType { name } types { name kind fields { name } } } }"}
        try:
            async with self.session.post(url, json=q, timeout=aiohttp.ClientTimeout(total=10)) as r:
                d = await r.json(content_type=None)
                if '__schema' in str(d):
                    return {'type':'GraphQL Introspection Enabled','severity':'MEDIUM','url':url,
                            'evidence':json.dumps(d)[:500],'description':'GraphQL introspection exposes full schema',
                            'remediation':'Disable introspection in production','cwe':'CWE-200','owasp':'A01:2021'}
        except: pass

    async def _depth(self, url):
        for d in [10, 25, 50, 100]:
            q = "{ user " + "{ friends " * d + "{ id } " + "} " * d + "}"
            try:
                async with self.session.post(url, json={"query":q}, timeout=aiohttp.ClientTimeout(total=15)) as r:
                    if r.status == 200:
                        return {'type':'GraphQL Query Depth DoS','severity':'HIGH','url':url,
                                'evidence':f'Server accepted depth {d}','cwe':'CWE-400','owasp':'A04:2021',
                                'remediation':'Implement query depth and complexity limits'}
            except asyncio.TimeoutError:
                return {'type':'GraphQL Query Depth DoS','severity':'HIGH','url':url,'evidence':f'Timeout at depth {d}'}
            except: pass

    async def _batch(self, url):
        for sz in [10, 50, 200]:
            try:
                async with self.session.post(url, json=[{"query":"{ __typename }"}]*sz, timeout=aiohttp.ClientTimeout(total=20)) as r:
                    if r.status == 200:
                        return {'type':'GraphQL Batch Query Abuse','severity':'MEDIUM','url':url,
                                'evidence':f'Processed {sz} batched queries','remediation':'Limit batch query size'}
            except: pass

    async def _alias(self, url):
        aliases = "\n".join([f"a{i}: __typename" for i in range(500)])
        t = time.time()
        try:
            async with self.session.post(url, json={"query":f"{{ {aliases} }}"}, timeout=aiohttp.ClientTimeout(total=30)) as r:
                el = time.time() - t
                if el > 5: return {'type':'GraphQL Alias Resource Exhaustion','severity':'HIGH','url':url,'evidence':f'{el:.1f}s with 500 aliases'}
        except asyncio.TimeoutError:
            return {'type':'GraphQL Alias Resource Exhaustion','severity':'HIGH','url':url,'evidence':'Timeout with 500 aliases'}
        except: pass
