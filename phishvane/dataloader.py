"""Loads the bundled detection knowledge-base files (data/*.txt).

Files are read once and cached. Each file is a simple newline-delimited list
where blank lines and ``#`` comments are ignored, so analysts can extend the
brand list, blocklist or TLD list without touching any code.
"""

from __future__ import annotations

import functools
from pathlib import Path

_DATA_DIR = Path(__file__).resolve().parent / "data"


def _read_list(filename: str) -> list[str]:
    """Return the non-comment, non-blank, lowercased lines of a data file."""
    path = _DATA_DIR / filename
    items: list[str] = []
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            items.append(line.lower())
    return items


@functools.lru_cache(maxsize=None)
def brands() -> tuple[str, ...]:
    """Commonly-impersonated brand keywords."""
    return tuple(_read_list("brands.txt"))


@functools.lru_cache(maxsize=None)
def trusted_domains() -> frozenset[str]:
    """Registrable domains treated as known-legitimate."""
    return frozenset(_read_list("trusted_domains.txt"))


@functools.lru_cache(maxsize=None)
def suspicious_tlds() -> frozenset[str]:
    """TLDs disproportionately abused for phishing."""
    return frozenset(_read_list("suspicious_tlds.txt"))


@functools.lru_cache(maxsize=None)
def keywords() -> tuple[str, ...]:
    """Sensitive words often embedded in phishing URLs."""
    return tuple(_read_list("keywords.txt"))


@functools.lru_cache(maxsize=None)
def shorteners() -> frozenset[str]:
    """Known URL-shortening service domains."""
    return frozenset(_read_list("shorteners.txt"))


@functools.lru_cache(maxsize=None)
def blocklist() -> frozenset[str]:
    """Locally-maintained known-malicious hosts / domains."""
    return frozenset(_read_list("blocklist.txt"))
