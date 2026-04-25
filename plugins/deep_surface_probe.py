import re
from typing import List, Dict, Any

async def probe_hidden_parameters(url: str, html: str, headers: dict, extracted: dict, gate: str = "passive") -> List[Dict[str, Any]]:
    findings = []
    
    # Safe passive analysis: identify unvalidated input vectors
    for form in extracted["forms"]:
        for param in form["params"]:
            if param.lower() in {"file", "path", "redirect", "url", "callback", "debug", "test"}:
                findings.append({
                    "url": form["url"], "type": "sensitive_param", "severity": "medium",
                    "description": f"Potentially dangerous parameter '{param}' in {form['method']} form",
                    "evidence": f"Form action: {form['url']}, Params: {form['params']}"
                })

    # JS source analysis for hidden endpoints (passive only)
    js_hints = re.findall(r'(?:fetch|axios|\.get|\.post)\s*\(\s*["\']([^"\']+)["\']', html, re.I)
    if js_hints and gate == "passive":
        findings.append({
            "url": url, "type": "js_api_hint", "severity": "info",
            "description": "Client-side API calls detected in JS",
            "evidence": ", ".join(js_hints[:5])
        })

    # Active testing gate enforcement
    if gate == "active":
        # Example: Safe parameter reflection check (non-destructive)
        # In production, this would use authorized, monitored payloads with rollback
        pass

    return findings
