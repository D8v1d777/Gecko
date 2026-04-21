import hashlib
from collections import defaultdict


class Deduplicator:

    def __init__(self, findings):
        self.findings = findings

    def normalize(self, f):
        """
        Normalize finding to create a stable fingerprint
        """
        import re

        vuln_type = f.get("type", "").lower()

        # strip dynamic parts from URLs
        endpoint = f.get("endpoint", "") or f.get("url", "")

        # Fuzzy matching: /api/user/1 -> /api/user/{id}
        endpoint = re.sub(r"/\d+", "/{id}", endpoint)

        # Parameter-based grouping: ?id=1 -> ?id={id}
        endpoint = re.sub(r"id=\d+", "id={id}", endpoint)

        return f"{vuln_type}:{endpoint}"

    def fingerprint(self, f):
        base = self.normalize(f)
        return hashlib.md5(base.encode()).hexdigest()

    def deduplicate(self):
        buckets = defaultdict(list)

        for f in self.findings:
            fp = self.fingerprint(f)
            buckets[fp].append(f)

        deduped = []

        for fp, group in buckets.items():
            merged = self.merge_group(group)
            deduped.append(merged)

        return deduped

    def merge_group(self, group):
        """
        Merge similar findings into one
        """
        base = group[0]

        endpoints = set()
        evidences = []

        for f in group:
            ep = f.get("endpoint") or f.get("url")
            if ep:
                endpoints.add(ep)

            evidences.append(f)

        severity = base.get("severity", "unknown")

        # Severity Override: High volume of occurrences = Higher risk
        if len(group) > 10:
            severity = "CRITICAL"

        return {
            "type": base.get("type"),
            "severity": severity,
            "endpoints": list(endpoints),
            "count": len(group),
            "evidence": evidences,
            "confidence": self.calculate_confidence(group),
        }

    def calculate_confidence(self, group):
        """
        More occurrences = higher confidence
        """
        n = len(group)

        if n > 5:
            return "HIGH"
        elif n > 2:
            return "MEDIUM"
        return "LOW"
