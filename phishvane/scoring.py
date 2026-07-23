"""Risk aggregation and verdict classification.

The scoring model is deliberately simple and transparent: every module emits
signals worth a fixed number of risk points; PhishVane sums them, caps the total
at 100, and maps the result onto four verdict bands. Transparency matters more
than a black-box classifier for analyst trust and for this project's report.
"""

from __future__ import annotations

from dataclasses import dataclass

# Verdict band thresholds (inclusive lower bound).
SAFE_MAX = 20
SUSPICIOUS_MAX = 45
LIKELY_MAX = 70
# 71-100 => Dangerous


@dataclass(frozen=True)
class Verdict:
    level: str        # machine key: safe | suspicious | likely | dangerous
    label: str        # human label
    emoji: str
    color: str        # rich/web colour name
    hex: str          # web hex colour


SAFE = Verdict("safe", "Safe", "🟢", "green", "#2ecc71")
SUSPICIOUS = Verdict("suspicious", "Suspicious", "🟡", "yellow", "#f1c40f")
LIKELY = Verdict("likely", "Likely Phishing", "🟠", "dark_orange", "#e67e22")
DANGEROUS = Verdict("dangerous", "Dangerous", "🔴", "red", "#e74c3c")


def classify(score: int) -> Verdict:
    """Map a 0-100 risk score to a verdict band."""
    if score <= SAFE_MAX:
        return SAFE
    if score <= SUSPICIOUS_MAX:
        return SUSPICIOUS
    if score <= LIKELY_MAX:
        return LIKELY
    return DANGEROUS


def clamp_score(raw: int) -> int:
    """Constrain a raw point total to the 0-100 range."""
    return max(0, min(100, raw))
