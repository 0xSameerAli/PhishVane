"""Top-level-domain reputation check (offline).

Some TLDs are disproportionately abused for phishing because they are free or
have lax registration controls (e.g. ``.tk``, ``.xyz``, ``.zip``). A suspicious
TLD is a weak-to-moderate signal on its own but meaningful in combination.
"""

from __future__ import annotations

from .. import dataloader
from ..signals import ModuleResult, Severity, Signal
from ..utils import URLContext

MODULE_NAME = "TLD Reputation"


def analyze(ctx: URLContext, online: bool = True) -> ModuleResult:
    result = ModuleResult(module=MODULE_NAME)

    if ctx.is_ip or not ctx.suffix:
        result.status = "skipped"
        result.note = "No TLD to evaluate."
        return result

    # For multi-label suffixes (e.g. "co.uk") the effective TLD is the last label.
    effective_tld = ctx.suffix.split(".")[-1]
    result.facts["tld"] = ctx.suffix

    if effective_tld in dataloader.suspicious_tlds():
        result.signals.append(Signal(
            code="tld.suspicious", category=MODULE_NAME,
            title=f"High-abuse TLD (.{effective_tld})",
            detail=f"The '.{effective_tld}' TLD is frequently used for phishing/malware "
                   "due to free or unrestricted registration.",
            points=12, severity=Severity.MEDIUM))

    return result
