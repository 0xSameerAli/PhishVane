"""Typosquatting, combosquatting and homoglyph (look-alike) detection (offline).

Attackers register domains that *look* like a trusted brand:
  * typosquatting   - ``paypa1.com``, ``goggle.com``     (small edit distance)
  * combosquatting  - ``secure-paypal.com``, ``paypal-login.net``
  * wrong TLD       - ``paypal.tk`` instead of ``paypal.com``
  * subdomain trick - ``paypal.com.login-secure.ru``
  * homoglyph/IDN   - ``pа​ypal.com`` using a Cyrillic 'а'

This module compares the URL's domain against a curated brand list and reports
the single strongest impersonation signal in each category.
"""

from __future__ import annotations

from .. import dataloader
from ..signals import ModuleResult, Severity, Signal
from ..utils import URLContext, levenshtein

MODULE_NAME = "Typosquatting"

# A small map of characters commonly used to visually impersonate ASCII letters
# (Cyrillic / Greek look-alikes and digit substitutions). "Skeletonising" a host
# with this map lets us compare confusable domains against real brands.
_CONFUSABLES = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y",
    "ѕ": "s", "і": "i", "ј": "j", "ԛ": "q", "ԝ": "w", "ɡ": "g",
    "α": "a", "ο": "o", "ρ": "p", "ν": "v", "ι": "i", "κ": "k",
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t",
}


# Digit / symbol substitutions used in ASCII "leetspeak" impersonation.
_LEET = {"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "$": "s"}


def _skeleton(text: str) -> str:
    return "".join(_CONFUSABLES.get(ch, ch) for ch in text.lower())


def _deleet(text: str) -> str:
    return "".join(_LEET.get(ch, ch) for ch in text.lower())


def _decode_idn(host: str) -> str:
    """Best-effort decode of a punycode host to its Unicode form."""
    labels = []
    for label in host.split("."):
        if label.startswith("xn--"):
            try:
                labels.append(label[4:].encode("ascii").decode("punycode"))
                continue
            except Exception:
                pass
        labels.append(label)
    return ".".join(labels)


def analyze(ctx: URLContext, online: bool = True) -> ModuleResult:
    result = ModuleResult(module=MODULE_NAME)
    add = lambda **kw: result.signals.append(Signal(category=MODULE_NAME, **kw))

    if ctx.is_ip or not ctx.domain:
        result.status = "skipped"
        result.note = "No domain name to evaluate (IP host or empty host)."
        return result

    # Trusted, exact-official domains are not impersonations of themselves.
    if ctx.registrable_domain in dataloader.trusted_domains():
        result.facts["trusted"] = True
        return result

    brands = dataloader.brands()
    domain = ctx.domain.lower()
    # Also test a "de-leetspeaked" form so digit-for-letter swaps such as
    # amaz0n / paypa1 / g00gle are matched against real brand names.
    deleet = _deleet(domain)
    variants = (domain,) if deleet == domain else (domain, deleet)
    leet_note = "" if deleet == domain else " (after normalising look-alike characters)"

    # --- Domain-name based checks: keep only the strongest single signal. ---
    best: Signal | None = None

    def consider(sig: Signal) -> None:
        nonlocal best
        if best is None or sig.points > best.points:
            best = sig

    for brand in brands:
        if len(brand) < 4:
            continue
        if any(v == brand for v in variants):
            consider(Signal(
                code="typosquat.brand_wrong_tld", category=MODULE_NAME,
                title=f"Brand name on unofficial domain ('{brand}')",
                detail=f"Domain '{domain}' equals the brand '{brand}'{leet_note} but is not "
                       f"the official domain ({ctx.registrable_domain}).",
                points=30, severity=Severity.HIGH))
        elif any(brand in v for v in variants):
            consider(Signal(
                code="typosquat.combosquat", category=MODULE_NAME,
                title=f"Brand name embedded in domain ('{brand}')",
                detail=f"Registered domain '{domain}' contains the brand '{brand}'{leet_note} "
                       f"with extra text - classic combosquatting.",
                points=24, severity=Severity.HIGH))
        else:
            dist = min(levenshtein(v, brand) for v in variants)
            if 1 <= dist <= 2 and any(abs(len(v) - len(brand)) <= 2 for v in variants) \
                    and len(brand) >= 5:
                consider(Signal(
                    code="typosquat.lookalike", category=MODULE_NAME,
                    title=f"Look-alike of '{brand}'",
                    detail=f"Domain '{domain}' is only {dist} edit(s) from the brand '{brand}'.",
                    points=28, severity=Severity.HIGH))

    if best is not None:
        result.signals.append(best)

    # --- Brand hidden in the subdomain while the real domain is elsewhere. ---
    if ctx.subdomain:
        sub_labels = ctx.subdomain.lower().replace("-", ".").split(".")
        for brand in brands:
            if len(brand) >= 4 and brand in sub_labels:
                add(code="typosquat.brand_subdomain",
                    title=f"Brand '{brand}' in subdomain",
                    detail=f"'{brand}' appears in the subdomain, but the real domain is "
                           f"'{ctx.registrable_domain}'.",
                    points=25, severity=Severity.HIGH)
                break

    # --- Brand only in the path (weaker signal). ---
    if best is None:
        path_l = ctx.path.lower()
        for brand in brands:
            if len(brand) >= 4 and brand in path_l:
                add(code="typosquat.brand_path",
                    title=f"Brand '{brand}' in URL path",
                    detail=f"'{brand}' appears in the path on unrelated domain "
                           f"'{ctx.registrable_domain}'.",
                    points=10, severity=Severity.LOW)
                break

    # --- Homoglyph / IDN look-alike of a brand. ---
    if ctx.is_idn:
        decoded = _decode_idn(ctx.host)
        skeleton_domain = _skeleton(decoded.split(".")[0]) if "." in decoded else _skeleton(decoded)
        for brand in brands:
            if len(brand) < 4:
                continue
            if skeleton_domain == brand or levenshtein(skeleton_domain, brand) <= 1:
                add(code="typosquat.homoglyph",
                    title=f"Homoglyph impersonation of '{brand}'",
                    detail=f"Punycode host decodes to '{decoded}', visually mimicking '{brand}'.",
                    points=30, severity=Severity.HIGH)
                result.facts["decoded_host"] = decoded
                break

    return result
