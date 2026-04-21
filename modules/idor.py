class IDORModule:
    name = "idor"
    severity = "high"

    async def run(self, target, session, context):
        import time

        from core.diff_engine import ResponseDiff, TimedResponse

        findings = []

        # Step 1: Use discovered endpoints from context
        endpoints = context.get("endpoints") or []
        scores = context.get("endpoint_scores") or {}

        user_endpoints = [ep for ep in endpoints if "/user/" in ep.lower()]
        # Sort by score (High priority first)
        user_endpoints.sort(key=lambda x: scores.get(x, 1), reverse=True)

        # fallback if no endpoints discovered yet
        if not user_endpoints:
            user_endpoints = ["/api/user/1"]

        for ep in user_endpoints:
            # Normalize endpoint
            if not ep.startswith("http"):
                url_base = f"{target.rstrip('/')}/{ep.lstrip('/')}"
            else:
                url_base = ep

            try:
                # Establish baseline
                start = time.time()
                res = await session.get(url_base)
                baseline = TimedResponse(res, time.time() - start)

                # Probe variations
                for i in range(1, 10):
                    # Intelligent replacement (e.g., /api/user/1 -> /api/user/2)
                    import re

                    url = re.sub(r"/\d+", f"/{i}", url_base)
                    if url == url_base:
                        continue  # skip baseline

                    start = time.time()
                    res = await session.get(url)
                    probe = TimedResponse(res, time.time() - start)

                    diff = ResponseDiff(baseline, probe)

                    if diff.significant_change():
                        findings.append(
                            {"type": "IDOR", "endpoint": url, "evidence": diff.report()}
                        )
            except:
                continue

        return findings
