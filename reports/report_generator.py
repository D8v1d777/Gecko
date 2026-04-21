"""GECKO APOCALYPSE - Report Generator (PDF, HTML, JSON, Markdown with CVSS, CWE, OWASP mapping, compliance)"""

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, List

# CVSS v3.1 scoring reference
CVSS_MAP = {
    "CRITICAL": {
        "score": 9.5,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    },
    "HIGH": {"score": 7.5, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
    "MEDIUM": {"score": 5.0, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N"},
    "LOW": {"score": 2.0, "vector": "CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N"},
    "INFO": {"score": 0.0, "vector": "N/A"},
}

OWASP_MAP = {
    "CWE-89": "A03:2021 - Injection",
    "CWE-79": "A03:2021 - Injection",
    "CWE-78": "A03:2021 - Injection",
    "CWE-94": "A03:2021 - Injection",
    "CWE-918": "A10:2021 - SSRF",
    "CWE-611": "A05:2021 - Security Misconfiguration",
    "CWE-327": "A02:2021 - Cryptographic Failures",
    "CWE-200": "A01:2021 - Broken Access Control",
    "CWE-284": "A01:2021 - Broken Access Control",
    "CWE-639": "A01:2021 - Broken Access Control",
    "CWE-16": "A05:2021 - Security Misconfiguration",
    "CWE-295": "A07:2021 - Identification Failures",
    "CWE-22": "A01:2021 - Broken Access Control",
    "CWE-362": "A04:2021 - Insecure Design",
    "CWE-942": "A05:2021 - Security Misconfiguration",
    "CWE-346": "A07:2021 - Identification Failures",
    "CWE-601": "A01:2021 - Broken Access Control",
    "CWE-269": "A01:2021 - Broken Access Control",
    "CWE-915": "A04:2021 - Insecure Design",
    "CWE-319": "A02:2021 - Cryptographic Failures",
}

COMPLIANCE_FLAGS = {
    "CWE-89": ["PCI-DSS 6.5.1", "GDPR Art.32"],
    "CWE-79": ["PCI-DSS 6.5.7"],
    "CWE-200": ["GDPR Art.5", "CCPA 1798.150"],
    "CWE-319": ["PCI-DSS 4.1", "GDPR Art.32"],
    "CWE-295": ["PCI-DSS 4.1"],
    "CWE-284": ["PCI-DSS 7.1", "GDPR Art.25"],
    "CWE-22": ["PCI-DSS 6.5.8"],
    "CWE-611": ["PCI-DSS 6.5.1"],
}


class ReportGenerator:
    def __init__(self, config, db, stats):
        self.config = config
        self.db = db
        self.stats = stats
        self.output_dir = Path("reports/output")
        self.output_dir.mkdir(parents=True, exist_ok=True)

    async def generate(self, fmt, target, findings):
        """Generate report in specified format."""
        # Enrich findings with CVSS/CWE/OWASP/compliance
        enriched = self._enrich_findings(findings)
        # Deduplicate
        enriched = self._deduplicate(enriched)

        generators = {
            "json": self._gen_json,
            "html": self._gen_html,
            "markdown": self._gen_markdown,
            "pdf": self._gen_pdf,
        }
        gen = generators.get(fmt, self._gen_json)
        return await gen(target, enriched)

    def _enrich_findings(self, findings):
        for f in findings:
            sev = f.get("severity", "INFO")
            f["cvss_score"] = CVSS_MAP.get(sev, CVSS_MAP["INFO"])["score"]
            f["cvss_vector"] = CVSS_MAP.get(sev, CVSS_MAP["INFO"])["vector"]
            cwe = f.get("cwe", "")
            if cwe and not f.get("owasp"):
                f["owasp"] = OWASP_MAP.get(cwe, "Unmapped")
            f["compliance_flags"] = COMPLIANCE_FLAGS.get(cwe, [])
        return findings

    def _deduplicate(self, findings):
        seen = set()
        unique = []
        for f in findings:
            key = f"{f.get('type')}-{f.get('url')}-{f.get('parameter','')}"
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique

    async def _gen_json(self, target, findings):
        path = (
            self.output_dir
            / f"gecko_report_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
        )
        report = {
            "meta": {
                "tool": "Gecko Apocalypse v10.0",
                "target": target,
                "timestamp": datetime.utcnow().isoformat(),
                "stats": self.stats,
            },
            "executive_summary": self._exec_summary(findings),
            "findings": findings,
        }
        path.write_text(json.dumps(report, indent=2, default=str))
        return str(path)

    async def _gen_html(self, target, findings):
        path = (
            self.output_dir
            / f"gecko_report_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.html"
        )
        sev_colors = {
            "CRITICAL": "#dc2626",
            "HIGH": "#ea580c",
            "MEDIUM": "#d97706",
            "LOW": "#65a30d",
            "INFO": "#2563eb",
        }
        rows = ""
        for i, f in enumerate(findings, 1):
            sev = f.get("severity", "INFO")
            color = sev_colors.get(sev, "#666")
            rows += f"""<tr>
                <td>{i}</td><td style="color:{color};font-weight:bold">{sev}</td>
                <td>{f.get('type','')}</td><td style="word-break:break-all">{f.get('url','')}</td>
                <td>{f.get('parameter','')}</td><td>{f.get('cvss_score',0)}</td>
                <td>{f.get('cwe','')}</td><td>{f.get('owasp','')}</td>
                <td>{f.get('evidence','')[:150]}</td><td>{f.get('remediation','')}</td>
                <td>{', '.join(f.get('compliance_flags',[]))}</td></tr>"""

        by_sev = {}
        for f in findings:
            s = f.get("severity", "INFO")
            by_sev[s] = by_sev.get(s, 0) + 1

        html = f"""<!DOCTYPE html><html><head><meta charset="utf-8">
<title>Gecko Apocalypse Report - {target}</title>
<style>
body{{font-family:'Segoe UI',sans-serif;margin:0;padding:20px;background:#0f172a;color:#e2e8f0}}
h1{{color:#22d3ee;text-align:center}} h2{{color:#38bdf8;border-bottom:1px solid #334155;padding-bottom:8px}}
table{{border-collapse:collapse;width:100%;margin:20px 0;font-size:13px}}
th{{background:#1e293b;color:#38bdf8;padding:10px;text-align:left;border:1px solid #334155}}
td{{padding:8px 10px;border:1px solid #1e293b;vertical-align:top}}
tr:nth-child(even){{background:#1e293b}} tr:hover{{background:#334155}}
.stats{{display:flex;gap:20px;justify-content:center;margin:20px 0}}
.stat{{background:#1e293b;border-radius:12px;padding:20px 30px;text-align:center;border:1px solid #334155}}
.stat .num{{font-size:36px;font-weight:bold}} .stat .label{{font-size:12px;color:#94a3b8}}
.critical .num{{color:#dc2626}} .high .num{{color:#ea580c}} .medium .num{{color:#d97706}}
.low .num{{color:#65a30d}} .info .num{{color:#2563eb}}
.summary{{background:#1e293b;border-radius:12px;padding:20px;margin:20px 0;border:1px solid #334155}}
</style></head><body>
<h1>🦎 GECKO APOCALYPSE - Security Assessment Report</h1>
<div class="summary"><strong>Target:</strong> {target} | <strong>Date:</strong> {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')} | <strong>Total Findings:</strong> {len(findings)}</div>
<div class="stats">
<div class="stat critical"><div class="num">{by_sev.get('CRITICAL',0)}</div><div class="label">CRITICAL</div></div>
<div class="stat high"><div class="num">{by_sev.get('HIGH',0)}</div><div class="label">HIGH</div></div>
<div class="stat medium"><div class="num">{by_sev.get('MEDIUM',0)}</div><div class="label">MEDIUM</div></div>
<div class="stat low"><div class="num">{by_sev.get('LOW',0)}</div><div class="label">LOW</div></div>
<div class="stat info"><div class="num">{by_sev.get('INFO',0)}</div><div class="label">INFO</div></div>
</div>
<h2>Executive Summary</h2><div class="summary">{self._exec_summary(findings)}</div>
<h2>Detailed Findings</h2>
<table><tr><th>#</th><th>Severity</th><th>Type</th><th>URL</th><th>Param</th><th>CVSS</th><th>CWE</th><th>OWASP</th><th>Evidence</th><th>Remediation</th><th>Compliance</th></tr>
{rows}</table>
<p style="text-align:center;color:#475569;margin-top:40px">Generated by Gecko Apocalypse Engine v10.0</p>
</body></html>"""
        path.write_text(html, encoding="utf-8")
        return str(path)

    async def _gen_markdown(self, target, findings):
        path = (
            self.output_dir
            / f"gecko_report_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.md"
        )
        by_sev = {}
        for f in findings:
            s = f.get("severity", "INFO")
            by_sev.setdefault(s, []).append(f)

        md = f"# 🦎 Gecko Apocalypse Security Report\n\n**Target:** {target}\n**Date:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}\n**Findings:** {len(findings)}\n\n"
        md += f"## Executive Summary\n\n{self._exec_summary(findings)}\n\n"
        md += "## Findings by Severity\n\n"
        md += "| Severity | Count |\n|---|---|\n"
        for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            md += f"| {s} | {len(by_sev.get(s, []))} |\n"

        md += "\n## Detailed Findings\n\n"
        for i, f in enumerate(findings, 1):
            md += f"### {i}. [{f.get('severity','')}] {f.get('type','')}\n\n"
            md += f"- **URL:** {f.get('url','')}\n"
            if f.get("parameter"):
                md += f"- **Parameter:** {f['parameter']}\n"
            if f.get("cvss_score"):
                md += f"- **CVSS:** {f['cvss_score']}\n"
            if f.get("cwe"):
                md += f"- **CWE:** {f['cwe']}\n"
            if f.get("owasp"):
                md += f"- **OWASP:** {f['owasp']}\n"
            md += f"- **Evidence:** {f.get('evidence','')}\n"
            if f.get("remediation"):
                md += f"- **Remediation:** {f['remediation']}\n"
            if f.get("compliance_flags"):
                md += f"- **Compliance:** {', '.join(f['compliance_flags'])}\n"
            md += "\n---\n\n"

        path.write_text(md, encoding="utf-8")
        return str(path)

    async def _gen_pdf(self, target, findings):
        """Generate PDF report (falls back to HTML if reportlab unavailable)."""
        try:
            from fpdf import FPDF

            path = (
                self.output_dir
                / f"gecko_report_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.pdf"
            )
            pdf = FPDF()
            pdf.add_page()
            pdf.set_font("Helvetica", "B", 20)
            pdf.cell(
                0,
                15,
                "Gecko Apocalypse Security Report",
                new_x="LMARGIN",
                new_y="NEXT",
                align="C",
            )
            pdf.set_font("Helvetica", "", 12)
            pdf.cell(0, 10, f"Target: {target}", new_x="LMARGIN", new_y="NEXT")
            pdf.cell(
                0,
                10,
                f'Date: {datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")}',
                new_x="LMARGIN",
                new_y="NEXT",
            )
            pdf.cell(
                0, 10, f"Total Findings: {len(findings)}", new_x="LMARGIN", new_y="NEXT"
            )
            pdf.ln(10)
            pdf.set_font("Helvetica", "B", 14)
            pdf.cell(0, 10, "Executive Summary", new_x="LMARGIN", new_y="NEXT")
            pdf.set_font("Helvetica", "", 10)
            pdf.multi_cell(0, 6, self._exec_summary(findings))
            pdf.ln(5)
            pdf.set_font("Helvetica", "B", 14)
            pdf.cell(0, 10, "Findings", new_x="LMARGIN", new_y="NEXT")
            for i, f in enumerate(findings, 1):
                pdf.set_font("Helvetica", "B", 10)
                pdf.cell(
                    0,
                    8,
                    f"{i}. [{f.get('severity','')}] {f.get('type','')}",
                    new_x="LMARGIN",
                    new_y="NEXT",
                )
                pdf.set_font("Helvetica", "", 9)
                pdf.cell(0, 6, f"URL: {f.get('url','')}", new_x="LMARGIN", new_y="NEXT")
                if f.get("evidence"):
                    pdf.multi_cell(0, 5, f"Evidence: {f['evidence'][:200]}")
                if f.get("remediation"):
                    pdf.cell(
                        0, 6, f"Fix: {f['remediation']}", new_x="LMARGIN", new_y="NEXT"
                    )
                pdf.ln(3)
                if pdf.get_y() > 260:
                    pdf.add_page()
            pdf.output(str(path))
            return str(path)
        except ImportError:
            return await self._gen_html(target, findings)

    def _exec_summary(self, findings):
        total = len(findings)
        by_sev = {}
        for f in findings:
            s = f.get("severity", "INFO")
            by_sev[s] = by_sev.get(s, 0) + 1
        crit = by_sev.get("CRITICAL", 0)
        high = by_sev.get("HIGH", 0)
        risk = (
            "CRITICAL"
            if crit > 0
            else (
                "HIGH"
                if high > 0
                else "MEDIUM" if by_sev.get("MEDIUM", 0) > 0 else "LOW"
            )
        )
        return (
            f"The security assessment identified {total} findings. "
            f"Overall risk level: {risk}. "
            f"Critical: {crit}, High: {high}, Medium: {by_sev.get('MEDIUM',0)}, "
            f"Low: {by_sev.get('LOW',0)}, Info: {by_sev.get('INFO',0)}. "
            f"{'Immediate remediation required for critical findings.' if crit > 0 else 'Review and remediate high-priority findings.'}"
        )
