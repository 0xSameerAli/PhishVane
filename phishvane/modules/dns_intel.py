"""DNS resolution check (online, optional).

A domain that does not resolve to any address may be a dead phishing site, a
mistyped host, or infrastructure that is not yet (or no longer) live. It is a
modest signal that complements the other modules. Fails safe on any error.
"""

from __future__ import annotations

from ..signals import ModuleResult, Severity, Signal
from ..utils import URLContext

MODULE_NAME = "DNS Intel"
_TIMEOUT = 5


def analyze(ctx: URLContext, online: bool = True) -> ModuleResult:
    result = ModuleResult(module=MODULE_NAME)

    if not online:
        result.status = "skipped"
        result.note = "Offline mode - DNS lookup not performed."
        return result
    if ctx.is_ip:
        result.status = "skipped"
        result.note = "Host is already an IP address."
        return result
    if not ctx.host:
        result.status = "skipped"
        result.note = "No host to resolve."
        return result

    try:
        import dns.resolver
    except ImportError:
        result.status = "skipped"
        result.note = "dnspython not installed."
        return result

    resolver = dns.resolver.Resolver()
    resolver.lifetime = _TIMEOUT
    resolver.timeout = _TIMEOUT

    try:
        answers = resolver.resolve(ctx.host, "A")
        addresses = sorted({r.address for r in answers})
        result.facts["a_records"] = addresses
        result.facts["resolves"] = True
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        result.facts["resolves"] = False
        result.signals.append(Signal(
            code="dns.no_resolve", category=MODULE_NAME,
            title="Domain does not resolve",
            detail="No DNS A record found - the host may be inactive or newly staged.",
            points=8, severity=Severity.LOW))
    except Exception as exc:  # timeout, no nameservers, network down...
        result.status = "error"
        result.note = f"DNS lookup failed: {exc}".strip()

    return result
