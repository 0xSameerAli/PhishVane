"""TLS/SSL certificate check (online, optional).

Connects to the host on port 443 and performs a *validating* TLS handshake.
A failed validation (expired, self-signed, or hostname-mismatched certificate)
is a meaningful phishing indicator. A clean handshake is recorded as reassuring
context. Connection-level problems fail safe (module skipped, no score impact).
"""

from __future__ import annotations

import socket
import ssl

from ..signals import ModuleResult, Severity, Signal
from ..utils import URLContext

MODULE_NAME = "TLS Intel"
_TIMEOUT = 6


def _issuer_org(cert: dict) -> str:
    for rdn in cert.get("issuer", ()):  # tuple of ((key, value), ...)
        for key, value in rdn:
            if key in ("organizationName", "commonName"):
                return value
    return "unknown"


def analyze(ctx: URLContext, online: bool = True) -> ModuleResult:
    result = ModuleResult(module=MODULE_NAME)

    if not online:
        result.status = "skipped"
        result.note = "Offline mode - TLS check not performed."
        return result
    if ctx.is_ip or not ctx.host:
        result.status = "skipped"
        result.note = "TLS check requires a domain name host."
        return result

    context = ssl.create_default_context()
    try:
        with socket.create_connection((ctx.host, 443), timeout=_TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=ctx.host) as ssock:
                cert = ssock.getpeercert()
        result.facts["tls_valid"] = True
        result.facts["issuer"] = _issuer_org(cert)
        result.facts["not_after"] = cert.get("notAfter")
    except ssl.SSLCertVerificationError as exc:
        reason = getattr(exc, "verify_message", None) or str(exc)
        result.facts["tls_valid"] = False
        result.signals.append(Signal(
            code="tls.invalid_cert", category=MODULE_NAME,
            title="Invalid TLS certificate",
            detail=f"Certificate failed validation ({reason}). "
                   "Legitimate login pages present valid certificates.",
            points=15, severity=Severity.HIGH))
    except (socket.timeout, ConnectionRefusedError, OSError) as exc:
        result.status = "skipped"
        result.note = f"Could not establish TLS on port 443: {exc}".strip()

    return result
