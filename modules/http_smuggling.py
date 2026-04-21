import asyncio
import time


class HTTPSmugglingModule:
    name = "http_smuggling"
    severity = "high"

    async def run(self, target, session, context):
        if not context.get("authorized"):
            return []

        if not context.get("aggressive"):
            return []

        findings = []

        tests = [self.te_cl_probe, self.cl_te_probe]

        for test in tests:
            result = await test(target, session)
            if result:
                findings.append(result)

        return findings

    async def te_cl_probe(self, target, session):
        """
        Safe TE.CL desync detection
        """
        from core.diff_engine import ResponseDiff, TimedResponse

        headers = {"Transfer-Encoding": "chunked", "Content-Length": "6"}

        payload = "0\r\n\r\nX"

        try:
            start = time.time()
            res_base = await session.get(target)
            baseline = TimedResponse(res_base, time.time() - start)

            start = time.time()
            res_probe = await session.post(
                target, headers=headers, content=payload, timeout=10
            )
            elapsed = time.time() - start
            probe = TimedResponse(res_probe, elapsed)

            diff = ResponseDiff(baseline, probe)

            # Indicators of desync behavior: Significant diff OR timeout
            if diff.significant_change() or elapsed > 5:
                return {
                    "type": "HTTP Smuggling",
                    "vector": "TE.CL",
                    "confidence": "medium",
                    "evidence": {
                        "status": probe.status_code,
                        "response_time": elapsed,
                        "diff": diff.report(),
                    },
                }

        except Exception:
            pass

        return None

    async def cl_te_probe(self, target, session):
        """
        Safe CL.TE desync detection
        """
        from core.diff_engine import ResponseDiff, TimedResponse

        headers = {"Content-Length": "4", "Transfer-Encoding": "chunked"}

        payload = "0\r\n\r\n"

        try:
            start = time.time()
            res_base = await session.get(target)
            baseline = TimedResponse(res_base, time.time() - start)

            start = time.time()
            res_probe = await session.post(
                target, headers=headers, content=payload, timeout=10
            )
            elapsed = time.time() - start
            probe = TimedResponse(res_probe, elapsed)

            diff = ResponseDiff(baseline, probe)

            if diff.significant_change() or elapsed > 5:
                return {
                    "type": "HTTP Smuggling",
                    "vector": "CL.TE",
                    "confidence": "medium",
                    "evidence": {
                        "status": probe.status_code,
                        "response_time": elapsed,
                        "diff": diff.report(),
                    },
                }

        except Exception:
            pass

        return None
