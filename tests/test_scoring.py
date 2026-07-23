"""Tests for the scoring/verdict classification."""

from phishvane import scoring


def test_clamp_score():
    assert scoring.clamp_score(-10) == 0
    assert scoring.clamp_score(250) == 100
    assert scoring.clamp_score(37) == 37


def test_classify_bands():
    assert scoring.classify(0).level == "safe"
    assert scoring.classify(20).level == "safe"
    assert scoring.classify(21).level == "suspicious"
    assert scoring.classify(45).level == "suspicious"
    assert scoring.classify(46).level == "likely"
    assert scoring.classify(70).level == "likely"
    assert scoring.classify(71).level == "dangerous"
    assert scoring.classify(100).level == "dangerous"
