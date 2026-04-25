class CrawlerModule:
    name = "crawler"
    severity = "info"

    async def run(self, target, session, context):
        endpoints = context.get("endpoints", [])
        params = context.get("params", [])
        
        findings = []
        
        if endpoints:
            findings.append({
                "type": "Discovered Endpoints",
                "severity": "INFO",
                "url": target,
                "evidence": f"Total: {len(endpoints)}",
                "description": f"Top Endpoints: {', '.join(list(endpoints)[:10])}..."
            })
            
        if params:
            findings.append({
                "type": "Discovered Parameters",
                "severity": "INFO",
                "url": target,
                "evidence": f"Total: {len(params)}",
                "description": f"Parameters: {', '.join(list(params)[:20])}"
            })
            
        return findings
