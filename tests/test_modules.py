"""Tests for the offline detection modules."""

from phishvane.modules import lexical, typosquat, tld
from phishvane.utils import URLContext


def codes(result):
    return {s.code for s in result.signals}


# --------------------------- lexical ---------------------------------------- #
def test_lexical_ip_host():
    res = lexical.analyze(URLContext.parse("http://192.168.10.5/login"))
    assert "lexical.ip_host" in codes(res)


def test_lexical_at_symbol():
    res = lexical.analyze(URLContext.parse("http://good.com@evil.com/login"))
    assert "lexical.at_symbol" in codes(res)


def test_lexical_keywords_and_shortener():
    res = lexical.analyze(URLContext.parse("https://bit.ly/verify-login"))
    c = codes(res)
    assert "lexical.shortener" in c
    assert "lexical.keywords" in c


def test_lexical_no_https():
    res = lexical.analyze(URLContext.parse("http://example.org"))
    assert "lexical.no_https" in codes(res)


# --------------------------- typosquat -------------------------------------- #
def test_typosquat_combosquat():
    res = typosquat.analyze(URLContext.parse("http://paypal-login.tk/verify"))
    assert "typosquat.combosquat" in codes(res)


def test_typosquat_lookalike():
    res = typosquat.analyze(URLContext.parse("http://goggle.com"))
    assert "typosquat.lookalike" in codes(res)


def test_typosquat_leetspeak_combosquat():
    # 'amaz0n' (zero for o) inside a longer domain must still match 'amazon'.
    res = typosquat.analyze(URLContext.parse("http://amaz0n-account-update.xyz/confirm"))
    assert "typosquat.combosquat" in codes(res)


def test_typosquat_leetspeak_exact():
    # 'paypa1' de-leets to exactly 'paypal'.
    res = typosquat.analyze(URLContext.parse("https://paypa1.com/webscr"))
    assert "typosquat.brand_wrong_tld" in codes(res)


def test_typosquat_brand_subdomain():
    res = typosquat.analyze(
        URLContext.parse("https://paypal.com.login-secure.ru/signin"))
    assert "typosquat.brand_subdomain" in codes(res)


def test_typosquat_trusted_skipped():
    res = typosquat.analyze(URLContext.parse("https://www.google.com"))
    # Trusted official domain must not be flagged as impersonating itself.
    assert res.signals == []
    assert res.facts.get("trusted") is True


def test_typosquat_homoglyph():
    res = typosquat.analyze(URLContext.parse("http://pаypal.com"))  # Cyrillic 'а'
    assert any(c.startswith("typosquat.") for c in codes(res))


# --------------------------- tld -------------------------------------------- #
def test_tld_suspicious():
    res = tld.analyze(URLContext.parse("http://example.xyz"))
    assert "tld.suspicious" in codes(res)


def test_tld_clean():
    res = tld.analyze(URLContext.parse("http://example.com"))
    assert res.signals == []
