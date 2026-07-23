"""End-to-end analyzer tests (offline mode for determinism - no network)."""

from phishvane import Analyzer


def analyze(url):
    return Analyzer(online=False).analyze(url)


def test_trusted_domain_is_safe():
    res = analyze("https://accounts.google.com/signin")
    assert res.trusted is True
    assert res.score <= 5
    assert res.verdict.level == "safe"


def test_phishing_url_scores_high():
    res = analyze("http://paypal-login.tk/verify-account")
    assert res.score >= 46
    assert res.verdict.level in ("likely", "dangerous")


def test_blocklisted_domain_is_dangerous():
    res = analyze("http://account-verify-appleid.com/login")
    assert res.verdict.level == "dangerous"
    assert any(s.code == "reputation.blocklist" for s in res.signals)


def test_ip_login_page_flagged():
    res = analyze("http://192.168.10.5/secure/login.php")
    codes = {s.code for s in res.signals}
    assert "lexical.ip_host" in codes
    assert res.score >= 21


def test_empty_host_is_handled():
    res = analyze("not a url")
    # Should not raise; produces a clean result even if unparseable.
    assert res.score == 0 or res.error


def test_result_serialises_to_dict():
    res = analyze("http://paypal-login.tk/verify")
    d = res.to_dict()
    assert "score" in d and "verdict" in d and "signals" in d
    assert isinstance(d["signals"], list)
