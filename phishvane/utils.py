"""URL parsing helpers and small algorithms shared by the detection modules.

The centrepiece is :class:`URLContext`, which parses a raw URL string exactly
once (scheme, host, port, path, registrable domain, subdomain, TLD, IP/IDN
flags). Every module receives the same pre-parsed context, keeping the modules
focused purely on detection logic.
"""

from __future__ import annotations

import ipaddress
import math
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

import tldextract

# Offline-safe extractor: `suffix_list_urls=()` disables network fetches and
# uses tldextract's bundled Public Suffix List snapshot, so PhishVane works
# without internet access and never blocks on a slow suffix-list download.
_EXTRACT = tldextract.TLDExtract(suffix_list_urls=())

_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://")


def normalize_url(raw: str) -> tuple[str, bool]:
    """Return ``(parseable_url, had_explicit_scheme)``.

    Phishing URLs are frequently reported without a scheme (``paypal.tk/login``).
    We prepend ``http://`` so the URL parses, while remembering that the original
    input lacked a scheme (used later as a minor signal).
    """
    raw = raw.strip()
    if _SCHEME_RE.match(raw):
        return raw, True
    return "http://" + raw, False


def shannon_entropy(text: str) -> float:
    """Shannon entropy (bits per character) of ``text`` - a randomness measure.

    Algorithmically-generated phishing domains (e.g. ``x8f2q9zk.com``) tend to
    have noticeably higher entropy than real, pronounceable brand domains.
    """
    if not text:
        return 0.0
    counts: dict[str, int] = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    length = len(text)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def levenshtein(a: str, b: str) -> int:
    """Edit distance between two strings (insertions/deletions/substitutions)."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        current = [i]
        for j, cb in enumerate(b, start=1):
            cost = 0 if ca == cb else 1
            current.append(min(
                previous[j] + 1,        # deletion
                current[j - 1] + 1,     # insertion
                previous[j - 1] + cost, # substitution
            ))
        previous = current
    return previous[-1]


def is_ip_address(host: str) -> bool:
    """True if ``host`` is a literal IPv4/IPv6 address rather than a domain."""
    candidate = host.strip("[]")
    try:
        ipaddress.ip_address(candidate)
        return True
    except ValueError:
        return False


@dataclass
class URLContext:
    """A fully pre-parsed view of a single URL, shared across all modules."""

    raw: str
    url: str                 # normalized, always has a scheme
    had_scheme: bool
    scheme: str
    host: str                # hostname without port (lowercased)
    port: int | None
    path: str
    query: str
    fragment: str
    registrable_domain: str  # e.g. "example.co.uk"  ("" for IP hosts)
    subdomain: str           # e.g. "login.secure"
    domain: str              # registered name without suffix, e.g. "example"
    suffix: str              # public suffix / TLD, e.g. "co.uk"
    is_ip: bool
    is_idn: bool             # host contains non-ASCII or punycode ("xn--")

    @property
    def netloc_host(self) -> str:
        return self.host

    @classmethod
    def parse(cls, raw: str) -> "URLContext":
        url, had_scheme = normalize_url(raw)
        parts = urlsplit(url)

        host = (parts.hostname or "").lower()
        try:
            port = parts.port
        except ValueError:
            port = None

        is_ip = is_ip_address(host)
        is_idn = bool(host) and (
            "xn--" in host or any(ord(ch) > 127 for ch in host)
        )

        if is_ip or not host:
            registrable = subdomain = domain = suffix = ""
        else:
            ext = _EXTRACT(host)
            domain = ext.domain
            suffix = ext.suffix
            subdomain = ext.subdomain
            # Build the registrable domain manually (works across tldextract
            # versions regardless of property renames).
            if domain and suffix:
                registrable = f"{domain}.{suffix}"
            else:
                registrable = host

        return cls(
            raw=raw,
            url=url,
            had_scheme=had_scheme,
            scheme=parts.scheme.lower(),
            host=host,
            port=port,
            path=parts.path or "",
            query=parts.query or "",
            fragment=parts.fragment or "",
            registrable_domain=registrable,
            subdomain=subdomain,
            domain=domain,
            suffix=suffix,
            is_ip=is_ip,
            is_idn=is_idn,
        )

    def to_dict(self) -> dict:
        return {
            "raw": self.raw,
            "url": self.url,
            "scheme": self.scheme,
            "host": self.host,
            "port": self.port,
            "path": self.path,
            "query": self.query,
            "registrable_domain": self.registrable_domain,
            "subdomain": self.subdomain,
            "suffix": self.suffix,
            "is_ip": self.is_ip,
            "is_idn": self.is_idn,
        }
