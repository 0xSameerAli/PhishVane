"""Tests for URL parsing and the small algorithm helpers."""

from phishvane.utils import URLContext, levenshtein, shannon_entropy, is_ip_address


def test_levenshtein_basic():
    assert levenshtein("paypal", "paypal") == 0
    assert levenshtein("paypal", "paypa1") == 1
    assert levenshtein("google", "goggle") == 1
    assert levenshtein("", "abc") == 3


def test_shannon_entropy_monotonic():
    # A repeated character has zero entropy; a varied string has more.
    assert shannon_entropy("aaaaaa") == 0.0
    assert shannon_entropy("x8f2q9zk") > shannon_entropy("google")


def test_is_ip_address():
    assert is_ip_address("192.168.0.1")
    assert is_ip_address("::1")
    assert not is_ip_address("example.com")


def test_context_parses_scheme_and_host():
    ctx = URLContext.parse("paypal-login.tk/verify")
    assert ctx.scheme == "http"          # scheme inferred
    assert ctx.had_scheme is False
    assert ctx.host == "paypal-login.tk"
    assert ctx.registrable_domain == "paypal-login.tk"
    assert ctx.domain == "paypal-login"
    assert ctx.suffix == "tk"


def test_context_subdomain_and_registrable():
    ctx = URLContext.parse("https://login.secure.example.co.uk/path")
    assert ctx.registrable_domain == "example.co.uk"
    assert ctx.subdomain == "login.secure"
    assert ctx.suffix == "co.uk"


def test_context_ip_host():
    ctx = URLContext.parse("http://192.168.10.5/login")
    assert ctx.is_ip is True
    assert ctx.registrable_domain == ""


def test_context_idn_flag():
    ctx = URLContext.parse("http://pаypal.com")  # Cyrillic 'а'
    assert ctx.is_idn is True
