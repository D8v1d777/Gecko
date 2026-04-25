from reconnaissance import ReconEngine, TechDetector, SecretScanner
import asyncio

class ReconModule:
    name = "recon"
    severity = "info"

    async def run(self, target, session, context):
        config = context.get("config", {})
        db = context.get("db", None)
        
        recon = ReconEngine(session, config, db)
        tech = TechDetector(session, config, db)
        secrets = SecretScanner(session, config, db)
        
        findings = []
        
        # 1. Tech Detection
        try:
            tech_results = await tech.scan(target, "", {}, None)
            findings.extend(tech_results)
        except:
            pass
            
        # 2. Subdomain Enumeration
        try:
            domain = target.replace("https://", "").replace("http://", "").split("/")[0]
            subs = await reconnaissance.enumerate_subdomains(domain)
            if subs:
                findings.append({
                    "type": "Subdomain Discovery",
                    "severity": "INFO",
                    "url": target,
                    "evidence": f"Discovered {len(subs)} subdomains",
                    "description": f"Subdomains: {', '.join(subs[:10])}..."
                })
        except:
            pass
            
        return findings
