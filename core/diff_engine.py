import difflib
import hashlib
import time


class TimedResponse:
    def __init__(self, response, elapsed):
        self.response = response
        self.elapsed = elapsed
        self.status_code = response.status_code
        self.headers = response.headers
        self.text = response.text


class ResponseDiff:

    def __init__(self, baseline: TimedResponse, probe: TimedResponse):
        self.baseline = baseline
        self.probe = probe

    def hash(self, text):
        return hashlib.md5(text.encode()).hexdigest()

    def similarity(self):
        return difflib.SequenceMatcher(
            None, self.baseline.text, self.probe.text
        ).ratio()

    def length_diff(self):
        return abs(len(self.baseline.text) - len(self.probe.text))

    def status_diff(self):
        return self.baseline.status_code != self.probe.status_code

    def header_diff(self):
        return dict(self.baseline.headers) != dict(self.probe.headers)

    def timing_diff(self):
        return abs(self.baseline.elapsed - self.probe.elapsed)

    def raw_diff(self):
        import difflib

        return "\n".join(
            difflib.unified_diff(
                self.baseline.text.splitlines(), self.probe.text.splitlines()
            )
        )

    def significant_change(self):
        score = self.similarity()

        if score < 0.85:
            return True

        if self.status_diff():
            return True

        if self.length_diff() > 50:
            return True

        if self.timing_diff() > 5:
            return True

        return False

    def report(self):
        return {
            "similarity": self.similarity(),
            "length_diff": self.length_diff(),
            "status_changed": self.status_diff(),
            "headers_changed": self.header_diff(),
            "timing_diff": self.timing_diff(),
            "raw_diff": self.raw_diff(),
            "significant": self.significant_change(),
        }
