"""WHOIS domain-age & registrar intelligence (online, optional).

Freshly-registered domains are one of the strongest phishing indicators: most
phishing infrastructure is used within days of registration. This module looks
up the domain's creation date and converts its age into a risk signal. It fails
safe - any lookup problem simply skips the module rather than raising.
"""

from __future__ import annotations

import socket
from datetime import datetime

from ..signals import ModuleResult, Severity, Signal
from ..utils import URLContext

MODULE_NAME = "WHOIS Intel"
_TIMEOUT = 8


def _first(value):
    """WHOIS libraries may return a single value or a list; take the first."""
    if isinstance(value, (list, tuple)):
        return value[0] if value else None
    return value


def analyze(ctx: URLContext, online: bool = True) -> ModuleResult:
    result = ModuleResult(module=MODULE_NAME)

    if not online:
        result.status = "skipped"
        result.note = "Offline mode - WHOIS lookup not performed."
        return result
    if ctx.is_ip or not ctx.registrable_domain:
        result.status = "skipped"
        result.note = "No registrable domain to look up."
        return result

    try:
        import whois  # python-whois
    except ImportError:
        result.status = "skipped"
        result.note = "python-whois not installed."
        return result

    old_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(_TIMEOUT)
    try:
        record = whois.whois(ctx.registrable_domain)
    except Exception as exc:  # network error, no whois server, parse error...
        result.status = "error"
        result.note = f"WHOIS lookup failed: {exc}".strip()
        return result
    finally:
        socket.setdefaulttimeout(old_timeout)

    created = _first(getattr(record, "creation_date", None))
    registrar = _first(getattr(record, "registrar", None))
    expires = _first(getattr(record, "expiration_date", None))

    if registrar:
        result.facts["registrar"] = str(registrar)
    if expires:
        result.facts["expiration_date"] = str(expires)

    if not isinstance(created, datetime):
        result.facts["creation_date"] = None
        result.note = "Creation date not available in WHOIS record."
        return result

    if created.tzinfo is not None:
        created = created.replace(tzinfo=None)
    age_days = (datetime.utcnow() - created).days
    result.facts["creation_date"] = created.strftime("%Y-%m-%d")
    result.facts["age_days"] = age_days

    if age_days < 30:
        result.signals.append(Signal(
            code="whois.very_new", category=MODULE_NAME,
            title="Domain registered very recently",
            detail=f"Registered {age_days} day(s) ago - typical of throwaway phishing domains.",
            points=20, severity=Severity.HIGH))
    elif age_days < 90:
        result.signals.append(Signal(
            code="whois.new", category=MODULE_NAME,
            title="Newly registered domain",
            detail=f"Registered {age_days} days ago (< 90 days).",
            points=12, severity=Severity.MEDIUM))
    elif age_days < 180:
        result.signals.append(Signal(
            code="whois.recent", category=MODULE_NAME,
            title="Relatively new domain",
            detail=f"Registered {age_days} days ago (< 180 days).",
            points=6, severity=Severity.LOW))

    return result
