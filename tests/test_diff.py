import pytest

from core.diff_engine import ResponseDiff, TimedResponse


class DummyResponse:
    def __init__(self, text, status_code=200, headers={}):
        self.text = text
        self.status_code = status_code
        self.headers = headers


def test_similarity():
    # Wrap dummy responses in TimedResponse as required by the latest ResponseDiff engine
    a = TimedResponse(DummyResponse("hello world"), 0.1)
    b = TimedResponse(DummyResponse("hello world!!"), 0.12)

    diff = ResponseDiff(a, b)

    assert diff.similarity() > 0.8
    assert diff.significant_change() is False  # Minor change


def test_significant_change():
    a = TimedResponse(DummyResponse("A" * 100), 0.1)
    b = TimedResponse(DummyResponse("B" * 100), 0.1)

    diff = ResponseDiff(a, b)
    assert diff.significant_change() is True  # Content mismatch


def test_timing_significant_change():
    a = TimedResponse(DummyResponse("hello"), 0.1)
    b = TimedResponse(DummyResponse("hello"), 6.0)  # > 5s delay

    diff = ResponseDiff(a, b)
    assert diff.significant_change() is True  # Timing anomaly
