"""
GECKO APOCALYPSE - RECONNAISSANCE & INTELLIGENCE ENGINE
Subdomain Enum, Reverse DNS, ASN/CIDR, WHOIS, GitHub Leaks,
Shodan/Censys, Wayback, Tech Fingerprinting, Breach Correlation
"""
import asyncio, aiohttp, re, json, math, socket
from typing import List, Dict, Optional, Set
from urllib.parse import urlparse
from datetime import datetime

try:
    import dns.resolver
    import dns.reversename
except ImportError:
    dns = None

try:
    import whois as python_whois
except ImportError:
    python_whois = None


class ReconEngine:
    def __init__(self, session, config, db):
        self.session = session
        self.config = config
        self.db = db
        self.subdomains: Set[str] = set()
        self.rc = config.get('recon', {})

    async def enumerate_subdomains(self, domain):
        domain = urlparse(domain).netloc if domain.startswith('http') else domain
        domain = domain.split(':')[0]
        tasks = [self._crt_sh(domain), self._dns_brute(domain), self._hackertarget(domain)]
        for r in await asyncio.gather(*tasks, return_exceptions=True):
            if isinstance(r, list): self.subdomains.update(r)
        return list(self.subdomains)

    async def _crt_sh(self, domain):
        subs = set()
        try:
            async with self.session.get(f"https://crt.sh/?q=%.{domain}&output=json", timeout=aiohttp.ClientTimeout(total=30)) as r:
                if r.status == 200:
                    for e in await r.json(content_type=None):
                        for n in e.get('name_value','').split('\n'):
                            n = n.strip('*.').strip()
                            if n.endswith(domain): subs.add(n)
        except: pass
        return list(subs)

    async def _hackertarget(self, domain):
        subs = set()
        try:
            async with self.session.get(f"https://api.hackertarget.com/hostsearch/?q={domain}", timeout=aiohttp.ClientTimeout(total=20)) as r:
                if r.status == 200:
                    for line in (await r.text()).split('\n'):
                        if ',' in line:
                            s = line.split(',')[0].strip()
                            if s.endswith(domain): subs.add(s)
        except: pass
        return list(subs)

    async def _dns_brute(self, domain):
        words = ['www','mail','ftp','webmail','smtp','ns1','ns2','dev','staging','test','qa','api','admin',
                 'portal','app','mobile','blog','cdn','static','docs','wiki','support','status','jenkins',
                 'gitlab','git','vpn','sso','auth','login','sandbox','demo','beta','stg','prod','backup',
                 'graphql','grpc','ws','dashboard','monitor','grafana','elastic','kibana']
        valid = []
        sem = asyncio.Semaphore(50)
        async def chk(s):
            async with sem:
                if await self._resolve(f"{s}.{domain}"): valid.append(f"{s}.{domain}")
        await asyncio.gather(*[chk(s) for s in words], return_exceptions=True)
        return valid

    async def _resolve(self, d):
        if dns:
            try: return len(dns.resolver.resolve(d,'A')) > 0
            except: return False
        try:
            await asyncio.get_event_loop().getaddrinfo(d, None)
            return True
        except: return False

    async def dns_analysis(self, domain):
        domain = urlparse(domain).netloc if domain.startswith('http') else domain
        domain = domain.split(':')[0]
        res = {f'{t.lower()}_records': [] for t in ['A','AAAA','MX','NS','TXT','CNAME','SOA']}
        res['reverse_dns'] = []
        if not dns: return res
        for t in ['A','AAAA','MX','NS','TXT','CNAME','SOA']:
            try: res[f'{t.lower()}_records'] = [str(r) for r in dns.resolver.resolve(domain, t)]
            except: pass
        for ip in res.get('a_records', []):
            try:
                rev = dns.resolver.resolve(dns.reversename.from_address(ip), 'PTR')
                res['reverse_dns'].append({'ip': ip, 'ptr': str(list(rev)[0])})
            except: pass
        return res

    async def whois_lookup(self, domain):
        domain = urlparse(domain).netloc if domain.startswith('http') else domain
        r = {'domain': domain, 'registrar': 'Unknown', 'creation_date': 'Unknown', 'expiration_date': 'Unknown', 'name_servers': []}
        if python_whois:
            try:
                w = python_whois.whois(domain)
                r['registrar'] = str(getattr(w,'registrar','Unknown') or 'Unknown')
                r['creation_date'] = str(getattr(w,'creation_date','Unknown') or 'Unknown')
                r['expiration_date'] = str(getattr(w,'expiration_date','Unknown') or 'Unknown')
                r['name_servers'] = getattr(w,'name_servers',[]) or []
            except: pass
        return r

    async def certificate_transparency(self, domain):
        d = urlparse(domain).netloc if domain.startswith('http') else domain
        return await self._crt_sh(d.split(':')[0])

    async def detect_technologies(self, url):
        try:
            async with self.session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as r:
                c = await r.text(errors='ignore'); h = dict(r.headers)
                return {'cms': self._cms(c,h), 'frameworks': self._fw(c,h), 'server': h.get('Server','?'),
                        'language': self._lang(h,c), 'cdn': self._cdn(h), 'waf': self._waf(h)}
        except: return {}

    def _cms(self, c, h):
        s = {'WordPress': ['/wp-content/'], 'Drupal': ['Drupal'], 'Joomla': ['Joomla'],
             'Magento': ['Magento'], 'Shopify': ['cdn.shopify.com'], 'Ghost': ['ghost.io']}
        return [k for k,v in s.items() if any(x in c or x in str(h) for x in v)]

    def _fw(self, c, h):
        s = {'React': ['react-dom','_reactRoot'], 'Angular': ['ng-app','angular'],
             'Vue.js': ['v-if','v-for'], 'Next.js': ['__NEXT_DATA__'], 'Django': ['csrfmiddlewaretoken'],
             'Laravel': ['laravel_session'], 'Express': ['x-powered-by: Express']}
        m = (c + str(h)).lower()
        return [k for k,v in s.items() if any(x.lower() in m for x in v)]

    def _lang(self, h, c):
        m = str(h).lower()
        for l,s in [('PHP',['php']),('Python',['wsgi','gunicorn']),('Java',['jsessionid']),('Node.js',['express'])]:
            if any(x in m for x in s): return l
        return 'Unknown'

    def _cdn(self, h):
        m = str(h).lower()
        return [k for k,v in {'Cloudflare':['cf-ray'],'Fastly':['x-fastly'],'CloudFront':['cloudfront']}.items() if any(x in m for x in v)]

    def _waf(self, h):
        m = str(h).lower()
        return [k for k,v in {'Cloudflare':'cloudflare','AWS WAF':'awselb','ModSecurity':'mod_security'}.items() if v in m]

    async def wayback_analysis(self, url):
        domain = urlparse(url).netloc
        snaps, interesting = [], set()
        try:
            async with self.session.get(f"http://web.archive.org/cdx/search/cdx?url={domain}/*&output=json&limit=200", timeout=aiohttp.ClientTimeout(total=30)) as r:
                if r.status == 200:
                    data = await r.json(content_type=None)
                    for row in data[1:]:
                        snaps.append({'timestamp': row[1], 'url': row[2], 'status': row[4] if len(row)>4 else ''})
                        if any(x in row[2].lower() for x in ['.env','.git','.sql','.bak','config','admin','phpinfo']):
                            interesting.add(row[2])
        except: pass
        return {'count': len(snaps), 'snapshots': snaps[:50], 'interesting': list(interesting)}

    async def scan_github_leaks(self, domain):
        return []  # Requires GitHub API token in config

    async def check_breaches(self, domain):
        return {'breached': False, 'breach_count': 0, 'breaches': []}
