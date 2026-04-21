class ContextStore:

    def __init__(self):
        self.data = {
            "endpoints": set(),
            "endpoint_scores": {},
            "params": set(),
            "tokens": {},
            "headers": {},
            "technologies": set(),
        }

    def add_endpoint(self, url):
        self.data["endpoints"].add(url)
        # Score the endpoint based on sensitivity
        score = 1  # default
        url_lower = url.lower()

        if "/admin" in url_lower or "/config" in url_lower:
            score = 10
        elif "/api" in url_lower or "/v1" in url_lower:
            score = 5
        elif ".js" in url_lower or ".css" in url_lower or "/static" in url_lower:
            score = 0

        self.data["endpoint_scores"][url] = score

    def add_param(self, param):
        self.data["params"].add(param)

    def add_token(self, key, value):
        self.data["tokens"][key] = value

    def add_header(self, key, value):
        self.data["headers"][key] = value

    def add_tech(self, tech):
        self.data["technologies"].add(tech)

    def get(self, key):
        return self.data.get(key)

    def dump(self):
        return self.data
