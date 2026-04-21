import re


class Extractor:

    def __init__(self, context):
        self.ctx = context

    def process(self, response, url):
        # Handle cases where response might be a TimedResponse or httpx.Response
        text = getattr(response, "text", "")
        headers = getattr(response, "headers", {})

        # endpoints
        links = re.findall(r'href="(.*?)"', text)
        for l in links:
            self.ctx.add_endpoint(l)

        # params
        params = re.findall(r"[?&](\w+)=", url)
        for p in params:
            self.ctx.add_param(p)

        # JWT tokens
        auth = headers.get("Authorization")
        if auth and "Bearer" in auth:
            try:
                self.ctx.add_token("jwt", auth.split()[1])
            except:
                pass

        # technologies
        server = headers.get("Server")
        if server:
            self.ctx.add_tech(server)
