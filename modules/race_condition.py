import asyncio


class RaceConditionModule:
    name = "race_condition"
    severity = "high"

    async def run(self, target, session, context):
        if not context.get("authorized"):
            return []

        if not context.get("aggressive"):
            return []

        findings = []

        async def send_request():
            try:
                # Note: httpx uses status_code
                return await session.post(target, json={"amount": 1})
            except:
                return None

        tasks = [send_request() for _ in range(20)]

        responses = await asyncio.gather(*tasks)

        success = sum(1 for r in responses if r and r.status_code == 200)

        if success > 1:
            findings.append(
                {
                    "type": "Race Condition",
                    "issue": f"{success} simultaneous successes detected",
                }
            )

        return findings
