import re


class Fingerprint:

    def __init__(self, response):
        self.response = response
        self.text = response.text.lower()
        self.headers = response.headers

    def detect(self):
        features = {
            "graphql": self.is_graphql(),
            "api": self.is_api(),
            "jwt": self.has_jwt(),
            "cors": self.has_cors(),
            "json": self.is_json(),
        }

        return features

    def is_graphql(self):
        return "graphql" in self.text or "/graphql" in self.text

    def is_api(self):
        return "/api/" in self.text or "application/json" in self.headers.get(
            "content-type", ""
        )

    def has_jwt(self):
        auth = self.headers.get("authorization", "")
        return "bearer" in auth.lower()

    def has_cors(self):
        return "access-control-allow-origin" in self.headers

    def is_json(self):
        return "application/json" in self.headers.get("content-type", "")
