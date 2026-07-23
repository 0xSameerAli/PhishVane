"""PhishVane - a defensive phishing-URL threat-analysis tool.

PhishVane inspects a URL through several independent detection modules
(lexical structure, typosquatting, TLD reputation, WHOIS/DNS/TLS intelligence
and threat-feed reputation), aggregates weighted risk signals into a single
0-100 score, and returns an explainable verdict for CERT/SOC triage.
"""

from .signals import Signal, Severity
from .analyzer import Analyzer, AnalysisResult

__version__ = "1.0.0"
__all__ = ["Analyzer", "AnalysisResult", "Signal", "Severity", "__version__"]
