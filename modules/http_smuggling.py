class HTTPSmugglingModule:
    name = "http_smuggling"
    severity = "high"

    async def run(self, target, session, context):
        findings = []
        test_headers = {
            "Transfer-Encoding": "chunked",
            "Content-Length": "4",
        }

        try:
            resp = await session.get(target, headers=test_headers, timeout=10.0)
            server_hdr = str(resp.headers.get("server", "")).lower()

            # Heuristic signal only; not a confirmation.
            if resp.status_code in (400, 411, 413, 500, 501):
                findings.append(
                    {
                        "type": "Potential HTTP Request Smuggling Signal",
                        "severity": self.severity.upper(),
                        "endpoint": target,
                        "confidence": "MEDIUM",
                        "evidence": f"Ambiguous TE/CL probe returned status {resp.status_code}",
                        "server": server_hdr or "unknown",
                    }
                )
        except Exception:
            pass

        return findings
