"""Threat-intelligence reputation check.

Two sources, checked in order:

1. **Local blocklist** (``data/blocklist.txt``) - always consulted, works fully
   offline. Analysts append confirmed-malicious hosts/domains here.
2. **Google Safe Browsing** - queried only when online *and* an API key is
   supplied via the ``PHISHVANE_GSB_KEY`` environment variable. Absent a key,
   this source is silently skipped so the tool needs no secrets to run.

A blocklist / feed hit is the single most decisive signal PhishVane produces.
"""

from __future__ import annotations

import os

from .. import dataloader
from ..signals import ModuleResult, Severity, Signal
from ..utils import URLContext

MODULE_NAME = "Reputation"
_GSB_ENDPOINT = "https://safebrowsing.googleapis.com/v4/threatMatches:find"


def _check_local(ctx: URLContext, result: ModuleResult) -> bool:
    blocked = dataloader.blocklist()
    hit = None
    if ctx.host and ctx.host in blocked:
        hit = ctx.host
    elif ctx.registrable_domain and ctx.registrable_domain in blocked:
        hit = ctx.registrable_domain
    if hit:
        result.facts["blocklist_hit"] = hit
        result.signals.append(Signal(
            code="reputation.blocklist", category=MODULE_NAME,
            title="Listed on threat blocklist",
            detail=f"'{hit}' matches a known-malicious entry in the local threat blocklist.",
            points=40, severity=Severity.HIGH))
        return True
    return False


def _check_safe_browsing(ctx: URLContext, result: ModuleResult) -> None:
    api_key = os.environ.get("PHISHVANE_GSB_KEY")
    if not api_key:
        return
    try:
        import requests
    except ImportError:
        return

    payload = {
        "client": {"clientId": "phishvane", "clientVersion": "1.0.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": ctx.url}],
        },
    }
    try:
        resp = requests.post(_GSB_ENDPOINT, params={"key": api_key},
                             json=payload, timeout=8)
        resp.raise_for_status()
        matches = resp.json().get("matches", [])
    except Exception as exc:
        result.note = (result.note + f" Safe Browsing error: {exc}").strip()
        return

    if matches:
        threat = matches[0].get("threatType", "THREAT")
        result.facts["safe_browsing"] = threat
        result.signals.append(Signal(
            code="reputation.safe_browsing", category=MODULE_NAME,
            title="Flagged by Google Safe Browsing",
            detail=f"Google Safe Browsing classifies this URL as {threat}.",
            points=40, severity=Severity.HIGH))
    else:
        result.facts["safe_browsing"] = "clean"


def analyze(ctx: URLContext, online: bool = True) -> ModuleResult:
    result = ModuleResult(module=MODULE_NAME)

    # Local blocklist is always available; a hit is decisive on its own.
    hit = _check_local(ctx, result)

    if online and not hit:
        _check_safe_browsing(ctx, result)
    elif not online:
        result.note = "Offline mode - only local blocklist consulted."

    return result
