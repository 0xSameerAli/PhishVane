"""The analysis orchestrator - the heart of PhishVane.

:class:`Analyzer` parses a URL once, runs every detection module against the
shared context, aggregates their weighted signals into a single risk score,
applies a trusted-domain safeguard, and returns a fully explainable
:class:`AnalysisResult`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from . import dataloader, scoring
from .modules import BASE_MODULES, NETWORK_MODULES
from .signals import ModuleResult, Severity, Signal
from .utils import URLContext

# When a URL is on the trusted allow-list, its score is capped here so incidental
# signals (e.g. the word "login") can never push a known-good site into a scary
# band. The individual signals are still shown for full transparency.
TRUSTED_SCORE_CAP = 5


@dataclass
class AnalysisResult:
    """Complete, serialisable outcome of analysing a single URL."""

    input_url: str
    normalized_url: str
    context: dict
    score: int
    verdict: scoring.Verdict
    signals: list[Signal]              # flat, sorted by points (desc)
    modules: list[ModuleResult]
    online: bool
    trusted: bool
    trust_capped: bool
    timestamp: str
    error: str = ""

    def to_dict(self) -> dict:
        return {
            "input_url": self.input_url,
            "normalized_url": self.normalized_url,
            "timestamp": self.timestamp,
            "online": self.online,
            "score": self.score,
            "verdict": {
                "level": self.verdict.level,
                "label": self.verdict.label,
                "emoji": self.verdict.emoji,
                "hex": self.verdict.hex,
            },
            "trusted": self.trusted,
            "trust_capped": self.trust_capped,
            "error": self.error,
            "context": self.context,
            "signals": [s.to_dict() for s in self.signals],
            "modules": [m.to_dict() for m in self.modules],
        }


class Analyzer:
    """Runs the full detection pipeline over URLs."""

    def __init__(self, online: bool = True):
        self.online = online

    def analyze(self, url: str) -> AnalysisResult:
        ctx = URLContext.parse(url)
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        # A URL with no host, or a host containing whitespace (never valid), is
        # unusable - report cleanly rather than producing a misleading score.
        if not ctx.host or any(ch.isspace() for ch in ctx.host):
            return AnalysisResult(
                input_url=url, normalized_url=ctx.url, context=ctx.to_dict(),
                score=0, verdict=scoring.SAFE, signals=[], modules=[],
                online=self.online, trusted=False, trust_capped=False,
                timestamp=timestamp,
                error="Input does not contain a valid host / URL.",
            )

        modules = list(BASE_MODULES)
        if self.online:
            modules += list(NETWORK_MODULES)

        module_results: list[ModuleResult] = []
        all_signals: list[Signal] = []
        for module in modules:
            try:
                res = module.analyze(ctx, online=self.online)
            except Exception as exc:  # a module must never break the whole scan
                res = ModuleResult(module=getattr(module, "MODULE_NAME", module.__name__),
                                   status="error", note=f"Module crashed: {exc}")
            module_results.append(res)
            all_signals.extend(res.signals)

        raw_score = sum(s.points for s in all_signals)
        score = scoring.clamp_score(raw_score)

        trusted = ctx.registrable_domain in dataloader.trusted_domains()
        trust_capped = False
        if trusted and score > TRUSTED_SCORE_CAP:
            score = TRUSTED_SCORE_CAP
            trust_capped = True

        if trusted:
            all_signals.insert(0, Signal(
                code="analyzer.trusted", title="Domain on trusted allow-list",
                detail=f"'{ctx.registrable_domain}' is a recognised legitimate domain; "
                       "risk score has been capped.",
                points=0, category="Reputation", severity=Severity.INFO))

        all_signals.sort(key=lambda s: s.points, reverse=True)

        return AnalysisResult(
            input_url=url,
            normalized_url=ctx.url,
            context=ctx.to_dict(),
            score=score,
            verdict=scoring.classify(score),
            signals=all_signals,
            modules=module_results,
            online=self.online,
            trusted=trusted,
            trust_capped=trust_capped,
            timestamp=timestamp,
        )
