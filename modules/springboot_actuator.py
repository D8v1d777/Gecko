"""GECKO APOCALYPSE - Spring Boot Actuator Scanner"""
import asyncio, aiohttp
from typing import List, Dict
from urllib.parse import urlparse

class SpringBootActuatorScanner:
    def __init__(self, session, config, db):
        self.session = session; self.config = config; self.db = db

    async def scan(self, url, content, headers, response):
        findings = []
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        
        actuators = [
            '/actuator', '/actuator/env', '/actuator/health', '/actuator/mappings',
            '/actuator/heapdump', '/actuator/httptrace', '/actuator/logfile',
            '/env', '/health', '/heapdump', '/trace', '/metrics'
        ]
        
        for a in actuators:
            test_url = base + a
            try:
                async with self.session.get(test_url, timeout=aiohttp.ClientTimeout(total=10), allow_redirects=False) as r:
                    if r.status == 200:
                        c = await r.text(errors='ignore')
                        if 'java.version' in c or 'UP' in c or 'contexts' in c or len(c) > 5000:
                            sev = 'CRITICAL' if 'env' in a or 'heapdump' in a else 'HIGH'
                            findings.append({'type':'Spring Boot Actuator Exposed','severity':sev,'url':test_url,
                                    'evidence':f'Actuator endpoint {a} is accessible',
                                    'remediation':'Restrict access to actuator endpoints using Spring Security','cwe':'CWE-538'})
            except: pass
            
        return findings
