"""GECKO APOCALYPSE - Cloud Hunter (AWS/GCP/Azure metadata, S3, subdomain takeover, K8s, serverless, CDN cache poisoning)"""
import asyncio, aiohttp, re
from typing import List, Dict, Optional
from urllib.parse import urlparse

class CloudHunter:
    def __init__(self, session, config, db):
        self.session = session; self.config = config; self.db = db

    async def scan(self, url, content, headers, response):
        findings = []
        for t in [self._s3_enum, self._takeover, self._k8s, self._docker, self._serverless,
                   self._cdn_poison, self._azure_blob, self._gcs]:
            r = await t(url, content)
            if r: findings.append(r) if isinstance(r, dict) else findings.extend(r)
        return findings

    async def _s3_enum(self, url, content):
        findings = []
        buckets = set(re.findall(r'([a-z0-9.-]+)\.s3\.amazonaws\.com', content))
        domain = urlparse(url).netloc.replace('www.','')
        buckets.update([domain, domain.replace('.','-'), f'{domain}-assets', f'{domain}-backup', f'{domain}-logs'])
        for b in list(buckets)[:10]:
            try:
                async with self.session.get(f'https://{b}.s3.amazonaws.com/', timeout=aiohttp.ClientTimeout(total=10)) as r:
                    c = await r.text(errors='ignore')
                    if r.status == 200 and '<ListBucketResult' in c:
                        findings.append({'type':'S3 Bucket Public','severity':'HIGH','url':f'https://{b}.s3.amazonaws.com/',
                                        'evidence':'Public listing','remediation':'Remove public access','cwe':'CWE-284'})
            except: pass
        return findings

    async def _azure_blob(self, url, content):
        blobs = re.findall(r'([a-z0-9]+)\.blob\.core\.windows\.net', content)
        for b in set(blobs)[:5]:
            try:
                async with self.session.get(f'https://{b}.blob.core.windows.net/?comp=list', timeout=aiohttp.ClientTimeout(total=10)) as r:
                    if r.status == 200:
                        return {'type':'Azure Blob Public','severity':'HIGH','url':f'https://{b}.blob.core.windows.net/',
                                'evidence':'Public blob storage','remediation':'Restrict blob access','cwe':'CWE-284'}
            except: pass

    async def _gcs(self, url, content):
        buckets = re.findall(r'storage\.googleapis\.com/([a-z0-9._-]+)', content)
        for b in set(buckets)[:5]:
            try:
                async with self.session.get(f'https://storage.googleapis.com/{b}', timeout=aiohttp.ClientTimeout(total=10)) as r:
                    if r.status == 200:
                        return {'type':'GCS Bucket Public','severity':'HIGH','url':f'https://storage.googleapis.com/{b}',
                                'evidence':'Public GCS bucket','cwe':'CWE-284'}
            except: pass

    async def _takeover(self, url, content):
        fps = {'heroku':'no-such-app','github':"There isn't a GitHub Pages",'shopify':'Sorry, this shop is currently unavailable',
               'azure':'Azure Web App - Error 404','aws':'NoSuchBucket','pantheon':'404 error unknown site',
               'tumblr':"There's nothing here",'wordpress.com':'Do you want to register'}
        try:
            async with self.session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as r:
                c = await r.text(errors='ignore')
                for svc, fp in fps.items():
                    if fp in c:
                        return {'type':'Subdomain Takeover','severity':'HIGH','url':url,
                                'evidence':f'Service: {svc}','remediation':'Remove unused DNS records','cwe':'CWE-284'}
        except: pass

    async def _k8s(self, url, content):
        base = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
        for p in ['/api/v1','/apis','/healthz','/version','/api/v1/namespaces']:
            try:
                async with self.session.get(f'{base}{p}', timeout=aiohttp.ClientTimeout(total=5)) as r:
                    if r.status == 200:
                        c = await r.text(errors='ignore')
                        if 'kind' in c and 'apiVersion' in c:
                            return {'type':'Kubernetes API Exposed','severity':'CRITICAL','url':f'{base}{p}',
                                    'evidence':'K8s API accessible','remediation':'Restrict K8s API access','cwe':'CWE-284'}
            except: pass

    async def _docker(self, url, content):
        base = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
        for p in ['/v2/','/v2/_catalog']:
            try:
                async with self.session.get(f'{base}{p}', timeout=aiohttp.ClientTimeout(total=5)) as r:
                    if r.status == 200:
                        return {'type':'Docker Registry Exposed','severity':'CRITICAL','url':f'{base}{p}',
                                'evidence':'Docker registry accessible','cwe':'CWE-284'}
            except: pass

    async def _serverless(self, url, content):
        patterns = [r'\.execute-api\.[a-z0-9-]+\.amazonaws\.com', r'\.cloudfunctions\.net',
                     r'\.azurewebsites\.net', r'\.netlify\.app']
        for p in patterns:
            if re.search(p, content):
                return {'type':'Serverless Function Detected','severity':'INFO','url':url,
                        'evidence':f'Serverless pattern: {p}','description':'Serverless infrastructure detected'}

    async def _cdn_poison(self, url, content):
        """Test CDN cache poisoning via unkeyed headers."""
        poison_headers = {'X-Forwarded-Host':'evil.com','X-Original-URL':'/admin',
                          'X-Forwarded-Scheme':'nothttps'}
        try:
            async with self.session.get(url, headers=poison_headers, timeout=aiohttp.ClientTimeout(total=10)) as r:
                c = await r.text(errors='ignore')
                if 'evil.com' in c:
                    return {'type':'CDN Cache Poisoning','severity':'HIGH','url':url,
                            'evidence':'Unkeyed header reflected in cached response',
                            'remediation':'Normalize cache keys, strip unkeyed headers','cwe':'CWE-444'}
        except: pass
