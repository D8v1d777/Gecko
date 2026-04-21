def classify_severity(f):
    t = f.get("type", "").lower()

    if "ssrf" in t or "idor" in t:
        return "HIGH"
    if "cors" in t or "graphql" in t:
        return "MEDIUM"
    return "LOW"


def generate_recommendation(f):
    t = f.get("type", "").lower()

    if "ssrf" in t:
        return "Restrict server-side requests and validate URLs."

    if "idor" in t:
        return "Implement proper authorization checks."

    if "cors" in t:
        return "Restrict allowed origins and disable credentials."

    return "Review and patch the vulnerability."
