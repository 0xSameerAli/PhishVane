"""PhishVane detection modules.

Each module exposes a single ``analyze(ctx, online=...)`` function that returns
a :class:`~phishvane.signals.ModuleResult`. Modules are intentionally
independent so the scoring engine can combine them and so new detectors can be
added without touching existing ones.
"""

from . import lexical, typosquat, tld, whois_intel, dns_intel, tls_intel, reputation

# BASE_MODULES always run (they either need no network, or degrade gracefully -
# reputation's local blocklist works offline; its Safe Browsing lookup only
# fires when online). NETWORK_MODULES run only when online mode is enabled.
BASE_MODULES = [lexical, typosquat, tld, reputation]
NETWORK_MODULES = [whois_intel, dns_intel, tls_intel]
ALL_MODULES = BASE_MODULES + NETWORK_MODULES

__all__ = [
    "lexical", "typosquat", "tld", "whois_intel", "dns_intel", "tls_intel",
    "reputation", "BASE_MODULES", "NETWORK_MODULES", "ALL_MODULES",
]
