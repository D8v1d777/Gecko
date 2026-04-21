import jwt


class JWTModule:
    name = "jwt"
    severity = "high"

    async def run(self, target, session, context):
        findings = []

        token = context.get("jwt")
        if not token:
            return findings

        try:
            decoded = jwt.decode(token, options={"verify_signature": False})

            findings.append(
                {
                    "type": "JWT",
                    "issue": "Token decoded without verification",
                    "data": decoded,
                }
            )

        except Exception:
            pass

        return findings
