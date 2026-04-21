class Scheduler:

    def __init__(self, modules):
        self.modules = modules

    def select(self, features, context=None):
        """
        Scoring-based module selection.
        Higher score = higher relevance to the target.
        Threshold: 5
        """
        context = context or {}

        score_map = {
            "graphql_fuzz": 0,
            "idor": 0,
            "jwt": 0,
            "cors": 0,
            "ssrf": 10,  # Always relevant
            "http_smuggling": 10,  # Infra-level
            "subdomain": 10,  # Recon-level
            "race_condition": 10,  # Logic-level
        }

        if features.get("graphql"):
            score_map["graphql_fuzz"] += 10

        if features.get("api"):
            score_map["idor"] += 8

        if features.get("jwt") or context.get("jwt"):
            score_map["jwt"] += 8

        if features.get("cors"):
            score_map["cors"] += 8

        # Add more logic here (e.g., if technology == "Node.js" -> add specific module points)

        selected = [m for m in self.modules if score_map.get(m.name, 0) > 5]

        return selected
