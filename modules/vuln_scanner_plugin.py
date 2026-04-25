from modules.vulnerability_scanner import VulnerabilityScanner
import asyncio

class VulnScannerModule:
    name = "vuln_scanner"
    severity = "medium"

    async def run(self, target, session, context):
        config = context.get("config", {})
        db = context.get("db", None)
        
        # Initialize the scanner
        scanner = VulnerabilityScanner(session, config, db)
        
        # Run the scan
        findings = await scanner.scan(target, "", {}, None)
        
        return findings
