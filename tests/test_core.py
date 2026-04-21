import pytest

from gecko_apocalypse import MODULES


def test_modules_exist():
    assert len(MODULES) > 0


def test_module_names():
    names = [m.name for m in MODULES]
    assert "ssrf" in names
    assert "idor" in names
