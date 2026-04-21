import datetime
import os

from jinja2 import Environment, FileSystemLoader

from reports.utils import classify_severity, generate_recommendation


class ReportGenerator:

    def __init__(self, target, findings):
        self.target = target
        self.findings = findings
        self.timestamp = datetime.datetime.now()

        # Setup Jinja2 environment
        template_dir = os.path.join(os.path.dirname(__file__), "templates")
        self.env = Environment(loader=FileSystemLoader(template_dir))

    def build(self, output_format="dict"):
        structured = []

        for f in self.findings:
            # Note: After dedup, severity might already be set or overridden
            severity = f.get("severity") or classify_severity(f)

            structured.append(
                {
                    "title": f.get("type", "Unknown"),
                    "severity": severity,
                    "confidence": f.get("confidence", "LOW"),
                    "affected_count": f.get("count", 1),
                    "description": self.describe(f),
                    "evidence": f.get("evidence", f),
                    "recommendation": generate_recommendation(f),
                }
            )

        report_data = {
            "target": self.target,
            "date": self.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "summary": self.generate_summary(structured),
            "findings": structured,
        }

        if output_format == "html":
            template = self.env.get_template("report.html")
            return template.render(**report_data)

        return report_data

    def describe(self, finding):
        count = finding.get("count", 1)
        vuln_type = finding.get("type", "Unknown")
        desc = f"{vuln_type} found across {count} endpoints"

        # Add similarity info if diff engine was used
        diff_data = finding.get("diff")
        if not diff_data and finding.get("evidence"):
            ev = finding.get("evidence")
            if isinstance(ev, list) and len(ev) > 0:
                diff_data = ev[0].get("diff")
            elif isinstance(ev, dict):
                diff_data = ev.get("diff")

        if diff_data and "similarity" in diff_data:
            desc += f" | Similarity: {diff_data['similarity']:.2f}"

        return desc

    def generate_summary(self, findings):
        high = sum(1 for f in findings if f["severity"] == "HIGH")
        medium = sum(1 for f in findings if f["severity"] == "MEDIUM")

        return {
            "total": len(findings),
            "high": high,
            "medium": medium,
            "risk": "CRITICAL" if high > 3 else "MODERATE",
        }


def render_html(report_data):
    env = Environment(loader=FileSystemLoader("reports/templates"))

    template = env.get_template("report.html")
    html = template.render(**report_data)

    output_path = "reports/output/report.html"

    os.makedirs("reports/output", exist_ok=True)

    with open(output_path, "w") as f:
        f.write(html)

    return output_path
