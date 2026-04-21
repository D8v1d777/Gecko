import socket


class SubdomainModule:
    name = "subdomain"
    severity = "info"

    async def run(self, target, session, context):
        subs = ["api", "dev", "test", "admin"]
        findings = []

        domain = target.replace("https://", "").replace("http://", "")

        for sub in subs:
            host = f"{sub}.{domain}"
            try:
                ip = socket.gethostbyname(host)
                findings.append({"subdomain": host, "ip": ip})
            except:
                continue

        return findings
