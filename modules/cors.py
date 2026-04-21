class CORSModule:
    name = "cors"
    severity = "medium"

    async def run(self, target, session, context):
        headers = {"Origin": "http://evil.com"}

        findings = []

        try:
            r = await session.get(target, headers=headers)

            if "Access-Control-Allow-Origin" in r.headers:
                if r.headers["Access-Control-Allow-Origin"] == "*":
                    findings.append(
                        {"type": "CORS Misconfig", "issue": "Wildcard origin allowed"}
                    )

                if r.headers.get("Access-Control-Allow-Credentials") == "true":
                    findings.append(
                        {
                            "type": "CORS Misconfig",
                            "issue": "Credentials allowed with external origin",
                        }
                    )
        except:
            pass

        return findings
