"""Lexical / structural analysis of the URL string itself (fully offline).

These checks need no network access - they inspect how the URL is *shaped*.
Attackers routinely rely on structural tricks (raw IPs, ``@`` credentials,
deeply nested subdomains, embedded second URLs, random-looking hosts) that this
module turns into weighted risk signals.
"""

from __future__ import annotations

from .. import dataloader
from ..signals import ModuleResult, Severity, Signal
from ..utils import URLContext, shannon_entropy

MODULE_NAME = "Lexical"


def analyze(ctx: URLContext, online: bool = True) -> ModuleResult:
    result = ModuleResult(module=MODULE_NAME)
    add = lambda **kw: result.signals.append(Signal(category=MODULE_NAME, **kw))

    full_url = ctx.url.lower()

    # 1. Raw IP address used as the host instead of a domain name.
    if ctx.is_ip:
        add(code="lexical.ip_host", title="IP address used as host",
            detail=f"Host is a raw IP ({ctx.host}) - legitimate brands use domain names.",
            points=25, severity=Severity.HIGH)

    # 2. '@' in the URL - everything before it is treated as userinfo and the
    #    real host is what follows, a classic obfuscation trick.
    if "@" in ctx.url.split("//", 1)[-1]:
        add(code="lexical.at_symbol", title="'@' symbol in URL",
            detail="An '@' makes the browser ignore text before it and use the host after it.",
            points=18, severity=Severity.HIGH)

    # 3. Overall URL length.
    length = len(ctx.url)
    if length > 100:
        add(code="lexical.very_long", title="Very long URL",
            detail=f"URL is {length} characters; long URLs hide the true destination.",
            points=10, severity=Severity.MEDIUM)
    elif length > 75:
        add(code="lexical.long", title="Long URL",
            detail=f"URL is {length} characters, longer than typical legitimate links.",
            points=6, severity=Severity.LOW)

    # 4. Subdomain depth (e.g. login.secure.paypal.example.com).
    if ctx.subdomain:
        depth = ctx.subdomain.count(".") + 1
        if depth >= 3:
            add(code="lexical.deep_subdomain", title="Excessive subdomain nesting",
                detail=f"{depth} subdomain levels ('{ctx.subdomain}') - used to look legitimate.",
                points=12, severity=Severity.MEDIUM)
        elif depth == 2:
            add(code="lexical.subdomain", title="Multiple subdomains",
                detail=f"Subdomain chain '{ctx.subdomain}' adds structure that can mislead.",
                points=6, severity=Severity.LOW)

    # 5. Sensitive keywords embedded anywhere in the URL.
    hits = [kw for kw in dataloader.keywords() if kw in full_url]
    if hits:
        counted = hits[:3]
        pts = 5 * len(counted)
        sev = Severity.MEDIUM if len(counted) >= 2 else Severity.LOW
        add(code="lexical.keywords", title="Phishing-related keywords",
            detail="Contains sensitive words: " + ", ".join(counted) +
                   (" (+more)" if len(hits) > 3 else ""),
            points=pts, severity=sev)

    # 6. Many hyphens in the registered domain name.
    if ctx.domain and ctx.domain.count("-") >= 2:
        add(code="lexical.hyphens", title="Multiple hyphens in domain",
            detail=f"Domain '{ctx.domain}' uses several hyphens, common in fake brand names.",
            points=6, severity=Severity.LOW)

    # 7. High digit ratio in the registered domain name.
    if ctx.domain:
        digits = sum(c.isdigit() for c in ctx.domain)
        ratio = digits / len(ctx.domain)
        if ratio > 0.30:
            add(code="lexical.digits", title="Many digits in domain",
                detail=f"{digits}/{len(ctx.domain)} characters of '{ctx.domain}' are digits.",
                points=8, severity=Severity.LOW)

    # 8. High-entropy (random-looking) domain name.
    if ctx.domain and len(ctx.domain) >= 8:
        entropy = shannon_entropy(ctx.domain)
        if entropy > 3.6:
            add(code="lexical.entropy", title="Random-looking domain",
                detail=f"Domain '{ctx.domain}' has high entropy ({entropy:.2f} bits/char).",
                points=8, severity=Severity.LOW)

    # 9. Non-standard port.
    if ctx.port is not None and ctx.port not in (80, 443):
        add(code="lexical.port", title="Non-standard port",
            detail=f"Connects on port {ctx.port} instead of 80/443.",
            points=6, severity=Severity.LOW)

    # 10. URL-shortening service (hides the real destination).
    if ctx.registrable_domain in dataloader.shorteners():
        add(code="lexical.shortener", title="URL shortener",
            detail=f"'{ctx.registrable_domain}' is a link shortener that hides the true target.",
            points=12, severity=Severity.MEDIUM)

    # 11. Internationalised / punycode host (possible homoglyph attack).
    if ctx.is_idn:
        add(code="lexical.idn", title="Internationalised / punycode host",
            detail="Host uses non-ASCII or 'xn--' punycode; may impersonate a brand visually.",
            points=12, severity=Severity.MEDIUM)

    # 12. A second URL embedded inside this one (open-redirect / obfuscation).
    embedded = full_url.count("http://") + full_url.count("https://")
    if embedded > 1:
        add(code="lexical.embedded_url", title="Embedded second URL",
            detail="Another 'http(s)://' appears inside the URL (redirect/obfuscation).",
            points=12, severity=Severity.MEDIUM)

    # 13. Plain HTTP (no transport encryption).
    if ctx.scheme == "http":
        add(code="lexical.no_https", title="No HTTPS",
            detail="URL uses plain HTTP; credentials would be sent unencrypted.",
            points=5, severity=Severity.LOW)

    return result
