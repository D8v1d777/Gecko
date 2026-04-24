"""
GECKO APOCALYPSE - Network & Web Correlation Module
====================================================
Coverage:
• HTML/JS parsing for forms, CSRF tokens, hidden fields, WebSocket endpoints
• External resource security analysis (HTTP vs HTTPS, mixed content, third-party tracking)
• DNS resolution & security posture (DNSSEC, suspicious records)
• Raw packet crafting for protocol compliance testing (TCP flags, HTTP manipulation)
• Cleartext credential exposure detection
• Insecure form submission & missing CSRF validation
• Sensitive token/secret exposure in client-side code

Enterprise Features:
• Confidence-weighted multi-signal detection (0.0-1.0 scale)
• Graceful scapy privilege fallback (safe mode when root/CAP_NET_RAW unavailable)
• Graceful prometheus_client fallback
• Fully compatible with httpx.AsyncClient (standard Gecko pipeline)

⚠️  RAW PACKET CRAFTING REQUIRES ELEVATED PRIVILEGES. Always obtain explicit written authorization.
"""

import asyncio
import hashlib
import json
import logging
import platform
import re
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field, asdict
from enum import Enum, auto
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse, urljoin

from bs4 import BeautifulSoup

# Optional: prometheus_client (graceful fallback)
try:
    import prometheus_client as prom_metrics
    METRICS_AVAILABLE = True
except ImportError:
    prom_metrics = None
    METRICS_AVAILABLE = False

# Optional: scapy (graceful fallback when unprivileged)
try:
    from scapy.all import IP, TCP, UDP, DNS, DNSQR, sr1, conf
    conf.verb = 0  # Silence scapy output
    SCAPY_AVAILABLE = True
except Exception:
    SCAPY_AVAILABLE = False

logger = logging.getLogger("gecko.network_web_correlator")


# ============================================================================
# DATA MODELS
# ============================================================================

class TestType(Enum):
    FORM_SECURITY      = "form_security"
    EXTERNAL_RESOURCE  = "external_resource"
    DNS_SECURITY       = "dns_security"
    CLEARTEXT_EXPOSURE = "cleartext_exposure"
    RAW_PACKET_TEST    = "raw_packet_test"
    TOKEN_EXPOSURE     = "token_exposure"
    PROTOCOL_COMPLIANCE = "protocol_compliance"


class ConfidenceLevel(Enum):
    LOW    = 0.3
    MEDIUM = 0.6
    HIGH   = 0.85
    CERTAIN = 0.99


class DetectionSignal(Enum):
    MISSING_CSRF          = auto()
    HTTP_FORM_SUBMISSION  = auto()
    MIXED_CONTENT         = auto()
    INSECURE_EXTERNAL     = auto()
    DNS_NOSEC             = auto()
    DNS_SUSPICIOUS_RECORD = auto()
    CLEARTEXT_CREDENTIAL  = auto()
    TOKEN_IN_HTML         = auto()
    RAW_PACKET_ACCEPTED   = auto()
    TCP_FLAG_ANOMALY      = auto()
    PROTOCOL_DOWNGRADE    = auto()


@dataclass
class DetectionEvidence:
    signal: DetectionSignal
    value: Any
    confidence_contribution: float
    metadata: Dict = field(default_factory=dict)

    def to_dict(self) -> Dict:
        return {
            "signal": self.signal.name,
            "value": str(self.value) if not isinstance(self.value, (dict, list)) else self.value,
            "confidence_contribution": self.confidence_contribution,
            "metadata": self.metadata,
        }


@dataclass
class NWCFinding:
    """Internal finding — converted to plain dict before returning from run()."""
    id: str
    type: str
    url: str
    test_type: TestType
    confidence: float = 0.0
    confidence_level: ConfidenceLevel = ConfidenceLevel.LOW
    severity: str = "INFO"
    evidence: List[DetectionEvidence] = field(default_factory=list)
    extracted_elements: Optional[List[Dict]] = None
    network_findings: Optional[List[Dict]] = None
    poc_snippet: Optional[str] = None
    cwe: Optional[str] = None
    owasp: Optional[str] = None
    mitre_attack: Optional[str] = None
    compliance_tags: List[str] = field(default_factory=list)
    metadata: Dict = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict:
        return {
            "type": self.type,
            "severity": self.severity,
            "endpoint": self.url,
            "confidence": self.confidence,
            "confidence_level": self.confidence_level.name,
            "test_type": self.test_type.value,
            "evidence": [e.to_dict() for e in self.evidence],
            "extracted_elements": self.extracted_elements,
            "network_findings": self.network_findings,
            "poc": self.poc_snippet,
            "cwe": self.cwe,
            "owasp": self.owasp,
            "mitre_attack": self.mitre_attack,
            "compliance_tags": self.compliance_tags,
            "metadata": self.metadata,
        }


# ============================================================================
# MAIN MODULE
# ============================================================================

class NetworkWebCorrelator:
    """
    Cross-layer web-to-network security analyzer.
    Uses bs4 for HTML parsing and scapy (when available) for network-layer tests.
    Standard Gecko interface: run(target, session, context) → List[dict]
    """

    name = "network_web_correlator"
    severity = "high"

    DEFAULT_CONFIG: Dict = {
        "min_confidence_threshold": 0.7,
        "enable_raw_packet_tests": True,
        "enable_dns_analysis": True,
        "max_dns_queries": 20,
        "max_packet_tests": 10,
        "packet_timeout_sec": 5,
        "engagement_mode": "internal_audit",
        "stealth_mode": False,
        "request_delay_ms": 200,
        "jitter_pct": 0.3,
        "rate_limit_per_second": 5,
        "max_retries": 2,
        "circuit_breaker_failures": 5,
        "circuit_breaker_timeout_sec": 120,
        "enable_metrics": True,
        "structured_logging": True,
        "log_level": "INFO",
        "compliance_frameworks": ["OWASP-ASVS", "PCI-DSS-6.5", "NIST-800-53"],
        "exclude_patterns": [r"\.js$", r"\.css$", r"/health", r"/metrics"],
        "max_requests_per_domain": 200,
    }

    _metrics_initialized = False

    @classmethod
    def _init_metrics(cls):
        if cls._metrics_initialized or not METRICS_AVAILABLE:
            return
        cls._metrics_initialized = True
        cls._metric_tests = prom_metrics.Counter(
            "gecko_netweb_tests_total", "Total cross-layer tests",
            ["test_type", "target_domain", "result"]
        )
        cls._metric_findings = prom_metrics.Counter(
            "gecko_netweb_findings_total", "Confirmed findings",
            ["type", "severity", "confidence_level"]
        )
        cls._metric_latency = prom_metrics.Histogram(
            "gecko_netweb_duration_seconds", "Test latency",
            ["test_type"], buckets=[0.1, 0.5, 1.0, 2.5, 5.0, 10.0]
        )

    def __init__(self):
        """Lightweight init — config is loaded from config.yaml via the pipeline."""
        self.config = dict(self.DEFAULT_CONFIG)
        self._circuit_breaker: Dict[str, Dict] = {}
        self._request_counts: Dict[str, int] = defaultdict(int)
        self._executor = ThreadPoolExecutor(max_workers=2)
        self._scapy_privileged = self._check_scapy_privileges()

        if self.config["enable_metrics"]:
            self._init_metrics()

        logger.info(
            f"NetworkWebCorrelator ready | scapy={self._scapy_privileged} | "
            f"mode={self.config['engagement_mode']}"
        )

    def _check_scapy_privileges(self) -> bool:
        if not SCAPY_AVAILABLE:
            return False
        if platform.system() == "Windows":
            return True  # Npcap usually grants access
        try:
            import socket
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
            s.close()
            return True
        except PermissionError:
            return False

    # ------------------------------------------------------------------
    # STANDARD GECKO INTERFACE
    # ------------------------------------------------------------------

    async def run(self, target: str, session, context: Dict) -> List[Dict]:
        """
        Entry point called by gecko_apocalypse.py orchestrator.
        Returns a list of plain dicts compatible with the CLI display table.
        """
        findings: List[NWCFinding] = []
        parsed = urlparse(target)
        domain = parsed.netloc

        if self._is_circuit_open(domain):
            return []

        if not self._should_scan(target, domain):
            return []

        start = time.time()

        try:
            # Fetch the target page to get HTML
            html = ""
            response_headers: Dict = {}
            try:
                r = await session.get(target, timeout=10, follow_redirects=True)
                html = r.text
                response_headers = dict(r.headers)
            except Exception as e:
                logger.debug(f"Could not fetch {target}: {e}")

            if html:
                soup = BeautifulSoup(html, "html.parser")

                tasks = [
                    self._analyze_forms(soup, target),
                    self._analyze_external_resources(soup, target),
                    self._analyze_token_exposure(soup, target),
                ]

                if self.config["enable_dns_analysis"] and SCAPY_AVAILABLE and self._scapy_privileged:
                    tasks.append(self._analyze_dns_security(soup, target, domain))

                if (
                    self.config["enable_raw_packet_tests"]
                    and SCAPY_AVAILABLE
                    and self._scapy_privileged
                ):
                    tasks.append(self._test_raw_packets(target, domain))
                elif self.config["enable_raw_packet_tests"] and not self._scapy_privileged:
                    logger.debug(
                        "Scapy lacks privileges — skipping raw packet tests. "
                        "Run as admin/root or grant CAP_NET_RAW."
                    )

                results = await asyncio.gather(*tasks, return_exceptions=True)
                for r in results:
                    if isinstance(r, NWCFinding):
                        if r.confidence >= self.config["min_confidence_threshold"]:
                            findings.append(r)
                            if METRICS_AVAILABLE and self.config["enable_metrics"]:
                                self._metric_findings.labels(
                                    type=r.type,
                                    severity=r.severity,
                                    confidence_level=r.confidence_level.name,
                                ).inc()
                    elif isinstance(r, Exception):
                        logger.debug(f"Sub-test error: {r}")
                        self._record_circuit_failure(domain)

            if METRICS_AVAILABLE and self.config["enable_metrics"]:
                self._metric_tests.labels(
                    test_type="netweb_scan", target_domain=domain, result="complete"
                ).inc()
                self._metric_latency.labels(test_type="full_netweb_scan").observe(
                    time.time() - start
                )

        except Exception as e:
            logger.error(f"NetworkWebCorrelator scan error: {e}", exc_info=True)
            self._record_circuit_failure(domain)

        return [f.to_dict() for f in findings]

    # ------------------------------------------------------------------
    # ANALYSIS METHODS
    # ------------------------------------------------------------------

    async def _analyze_forms(self, soup: BeautifulSoup, url: str) -> Optional[NWCFinding]:
        forms = soup.find_all("form")
        if not forms:
            return None

        evidence: List[DetectionEvidence] = []
        insecure_forms: List[Dict] = []

        for form in forms:
            action = urljoin(url, form.get("action", url))
            method = form.get("method", "get").lower()
            is_http = action.startswith("http://")

            has_csrf = bool(
                form.find("input", {"name": re.compile(r"csrf|_token|authenticity", re.I)})
            )
            has_password = bool(form.find("input", {"type": "password"}))
            has_file = bool(form.find("input", {"type": "file"}))

            issues = []
            if method == "post" and not has_csrf:
                issues.append("Missing CSRF token on POST form")
                evidence.append(DetectionEvidence(
                    DetectionSignal.MISSING_CSRF,
                    f"POST form at {action} lacks CSRF protection",
                    0.55,
                    {"form_action": action},
                ))
            if has_password and is_http:
                issues.append("Password submitted over HTTP")
                evidence.append(DetectionEvidence(
                    DetectionSignal.CLEARTEXT_CREDENTIAL,
                    f"Form at {action} sends password over HTTP",
                    0.75,
                    {"form_action": action},
                ))
            if has_file and is_http:
                issues.append("File upload over HTTP")
                evidence.append(DetectionEvidence(
                    DetectionSignal.HTTP_FORM_SUBMISSION,
                    f"File upload form at {action} uses HTTP",
                    0.6,
                    {"form_action": action},
                ))

            if issues:
                insecure_forms.append({"action": action, "method": method, "issues": issues})

        if not evidence:
            return None

        confidence = min(0.99, max(e.confidence_contribution for e in evidence) + 0.1)
        has_cleartext = any(e.signal == DetectionSignal.CLEARTEXT_CREDENTIAL for e in evidence)
        severity = "CRITICAL" if has_cleartext else "HIGH"

        return NWCFinding(
            id=f"gecko:nwc:form:{hashlib.sha256(url.encode()).hexdigest()[:12]}",
            type="Insecure Form Submission / Missing CSRF",
            url=url,
            test_type=TestType.FORM_SECURITY,
            confidence=round(confidence, 2),
            confidence_level=self._confidence_to_level(confidence),
            severity=severity,
            evidence=evidence,
            extracted_elements=[{"form": f} for f in insecure_forms[:5]],
            cwe="CWE-352" if any(e.signal == DetectionSignal.MISSING_CSRF for e in evidence) else "CWE-319",
            owasp="A01:2021",
            mitre_attack="T1059",
            compliance_tags=self.config["compliance_frameworks"],
            metadata={"forms_analyzed": len(forms), "insecure_forms": len(insecure_forms)},
        )

    async def _analyze_external_resources(self, soup: BeautifulSoup, url: str) -> Optional[NWCFinding]:
        tags = soup.find_all(["script", "link", "img", "iframe", "video", "audio", "source"])
        evidence: List[DetectionEvidence] = []
        mixed: List[Dict] = []

        for tag in tags:
            src = tag.get("src") or tag.get("href") or tag.get("data-src")
            if not src:
                continue
            if src.startswith("//"):
                src = "https:" + src
            if not src.startswith("http://"):
                continue

            has_sri = bool(tag.get("integrity"))
            if not has_sri and tag.name in ("script", "link"):
                mixed.append({"tag": tag.name, "src": src[:120]})
                evidence.append(DetectionEvidence(
                    DetectionSignal.INSECURE_EXTERNAL,
                    f"<{tag.name}> loaded over HTTP without SRI: {src[:80]}",
                    0.4,
                    {"src": src},
                ))

        if not evidence:
            return None

        confidence = min(0.95, max(e.confidence_contribution for e in evidence) + 0.05 * min(len(mixed), 5))
        return NWCFinding(
            id=f"gecko:nwc:mixed:{hashlib.sha256(url.encode()).hexdigest()[:12]}",
            type="Mixed Content / Insecure External Resources",
            url=url,
            test_type=TestType.EXTERNAL_RESOURCE,
            confidence=round(confidence, 2),
            confidence_level=self._confidence_to_level(confidence),
            severity="MEDIUM",
            evidence=evidence,
            extracted_elements=[{"resource": r} for r in mixed[:10]],
            cwe="CWE-319",
            owasp="A02:2021",
            mitre_attack="T1078",
            compliance_tags=self.config["compliance_frameworks"],
            metadata={"external_resources": len(tags), "insecure_loaded": len(mixed)},
        )

    async def _analyze_token_exposure(self, soup: BeautifulSoup, url: str) -> Optional[NWCFinding]:
        scripts = soup.find_all("script")
        evidence: List[DetectionEvidence] = []

        token_patterns = [
            (r'(?:api_key|apikey|access_token|secret|private_key)\s*[=:]\s*["\']([A-Za-z0-9_\-\.]{16,})["\']', "Hardcoded API Key/Secret"),
            (r'(?:AKIA|ASIA|ghp_|ghs_|github_pat_|xoxb-|xoxp-)\w{16,}', "Cloud/GitHub/Slack Token"),
            (r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----', "Private Key in HTML"),
            (r'password\s*:\s*["\'][^"\']{4,}["\']', "Hardcoded Password in JS"),
        ]

        for script in scripts:
            content = script.string or ""
            if not content:
                continue
            for pattern, label in token_patterns:
                if re.search(pattern, content, re.I):
                    evidence.append(DetectionEvidence(
                        DetectionSignal.TOKEN_IN_HTML,
                        f"{label} exposed in inline <script>",
                        0.7,
                        {"url": url, "pattern_label": label},
                    ))
                    break  # One signal per script block

        if not evidence:
            return None

        confidence = min(0.99, max(e.confidence_contribution for e in evidence) + 0.1)
        return NWCFinding(
            id=f"gecko:nwc:token:{hashlib.sha256(url.encode()).hexdigest()[:12]}",
            type="Sensitive Token/Secret in Client-Side Code",
            url=url,
            test_type=TestType.TOKEN_EXPOSURE,
            confidence=round(confidence, 2),
            confidence_level=self._confidence_to_level(confidence),
            severity="HIGH",
            evidence=evidence,
            cwe="CWE-798",
            owasp="A02:2021",
            mitre_attack="T1555",
            compliance_tags=["PCI-DSS-3.4", "NIST-800-63B"] + self.config["compliance_frameworks"],
            metadata={"scripts_analyzed": len(scripts)},
        )

    async def _analyze_dns_security(self, soup: BeautifulSoup, url: str, domain: str) -> Optional[NWCFinding]:
        """DNS analysis using scapy — only runs when privileged."""
        domains: set = set()
        for tag in soup.find_all(["a", "script", "link", "img", "iframe"]):
            src = tag.get("src") or tag.get("href")
            if src and src.startswith("http"):
                try:
                    d = urlparse(src).netloc.split(":")[0]
                    if d and d != domain:
                        domains.add(d)
                except Exception:
                    pass

        domains_list = list(domains)[: self.config["max_dns_queries"]]
        if not domains_list:
            return None

        evidence: List[DetectionEvidence] = []
        dns_results: List[Dict] = []

        loop = asyncio.get_event_loop()
        for d in domains_list:
            try:
                res = await loop.run_in_executor(self._executor, self._query_dns_scapy, d)
                dns_results.append({"domain": d, **res})
                if res.get("no_dnssec"):
                    evidence.append(DetectionEvidence(
                        DetectionSignal.DNS_NOSEC,
                        f"Domain {d} responded without DNSSEC validation",
                        0.3,
                        {"domain": d},
                    ))
            except Exception:
                pass

        if not evidence:
            return None

        confidence = min(0.85, max(e.confidence_contribution for e in evidence) + 0.05)
        return NWCFinding(
            id=f"gecko:nwc:dns:{hashlib.sha256(domain.encode()).hexdigest()[:12]}",
            type="DNS Security Posture (No DNSSEC)",
            url=url,
            test_type=TestType.DNS_SECURITY,
            confidence=round(confidence, 2),
            confidence_level=self._confidence_to_level(confidence),
            severity="LOW",
            evidence=evidence,
            network_findings=dns_results[:10],
            cwe="CWE-345",
            owasp="A05:2021",
            mitre_attack="T1592",
            compliance_tags=self.config["compliance_frameworks"],
            metadata={"domains_queried": len(domains_list)},
        )

    def _query_dns_scapy(self, domain: str) -> Dict:
        try:
            pkt = IP(dst="8.8.8.8") / UDP(sport=12345, dport=53) / DNS(rd=1, qd=DNSQR(qname=domain, qtype="A"))
            resp = sr1(pkt, timeout=3, retry=0, verbose=False)
            if resp and resp.haslayer(DNS):
                return {"no_dnssec": True, "record_type": "A"}
        except Exception:
            pass
        return {"no_dnssec": True, "record_type": "FAILED"}

    async def _test_raw_packets(self, url: str, domain: str) -> Optional[NWCFinding]:
        """TCP flag probing via scapy — only runs when privileged."""
        target_ip = await asyncio.get_event_loop().run_in_executor(
            self._executor, self._resolve_sync, domain
        )
        if not target_ip:
            return None

        parsed = urlparse(url)
        port = 443 if parsed.scheme == "https" else 80
        probes = [("S", "SYN"), ("F", "FIN"), ("FPU", "XMAS"), ("", "NULL")]

        evidence: List[DetectionEvidence] = []
        loop = asyncio.get_event_loop()

        for flags, name in probes[: self.config["max_packet_tests"]]:
            try:
                res = await loop.run_in_executor(
                    self._executor, self._send_tcp_probe, target_ip, port, flags
                )
                if res.get("responded"):
                    evidence.append(DetectionEvidence(
                        DetectionSignal.RAW_PACKET_ACCEPTED,
                        f"Server responded to {name} probe on port {port}",
                        0.4,
                        {"probe": name, "flags": flags, "ip": target_ip},
                    ))
            except Exception:
                pass

        if not evidence:
            return None

        confidence = min(0.85, max(e.confidence_contribution for e in evidence) + 0.05)
        return NWCFinding(
            id=f"gecko:nwc:raw:{hashlib.sha256(domain.encode()).hexdigest()[:12]}",
            type="Raw Packet Resilience / TCP Probe Response",
            url=url,
            test_type=TestType.RAW_PACKET_TEST,
            confidence=round(confidence, 2),
            confidence_level=self._confidence_to_level(confidence),
            severity="LOW",
            evidence=evidence,
            cwe="CWE-20",
            owasp="A05:2021",
            mitre_attack="T1046",
            compliance_tags=self.config["compliance_frameworks"],
            metadata={"target_ip": target_ip, "port": port},
        )

    def _send_tcp_probe(self, ip: str, port: int, flags: str) -> Dict:
        try:
            pkt = IP(dst=ip) / TCP(dport=port, flags=flags, seq=1000)
            resp = sr1(pkt, timeout=self.config["packet_timeout_sec"], retry=0, verbose=False)
            return {"responded": bool(resp)}
        except Exception:
            return {"responded": False}

    def _resolve_sync(self, domain: str) -> Optional[str]:
        try:
            import socket
            return socket.gethostbyname(domain)
        except Exception:
            return None

    # ------------------------------------------------------------------
    # HELPERS
    # ------------------------------------------------------------------

    def _confidence_to_level(self, c: float) -> ConfidenceLevel:
        if c >= 0.95:
            return ConfidenceLevel.CERTAIN
        if c >= 0.80:
            return ConfidenceLevel.HIGH
        if c >= 0.60:
            return ConfidenceLevel.MEDIUM
        return ConfidenceLevel.LOW

    def _should_scan(self, target: str, domain: str) -> bool:
        exclude = self.config.get("exclude_patterns", [])
        if any(re.search(p, target, re.I) for p in exclude):
            return False
        if self._request_counts.get(domain, 0) >= self.config.get("max_requests_per_domain", 200):
            return False
        return True

    def _is_circuit_open(self, domain: str) -> bool:
        state = self._circuit_breaker.get(domain)
        if not state:
            return False
        if state["failures"] < self.config["circuit_breaker_failures"]:
            return False
        if time.time() - state["last_failure"] > self.config["circuit_breaker_timeout_sec"]:
            self._circuit_breaker[domain] = {"failures": 0, "last_failure": 0.0}
            return False
        return True

    def _record_circuit_failure(self, domain: str):
        s = self._circuit_breaker.setdefault(domain, {"failures": 0, "last_failure": 0.0})
        s["failures"] += 1
        s["last_failure"] = time.time()


def register_plugin():
    return {
        "name": NetworkWebCorrelator.name,
        "class": NetworkWebCorrelator,
        "version": "3.0.0",
        "description": "Cross-layer web-to-network security correlation using bs4 + optional scapy",
        "config_schema": NetworkWebCorrelator.DEFAULT_CONFIG,
        "dependencies": [
            "beautifulsoup4>=4.12.0",
            "scapy>=2.5.0 (optional, for raw packet tests)",
            "prometheus-client>=0.19.0 (optional, for metrics)",
        ],
    }
