"""Report generation: machine-readable JSON and a standalone HTML report.

The JSON output is intended for SOC pipelines / ticketing systems, while the
self-contained HTML report is easy to attach to an incident or drop into
documentation (and photographs well for screenshots).
"""

from __future__ import annotations

import html
import json
from pathlib import Path

from .analyzer import AnalysisResult
from .signals import Severity

_SEVERITY_COLORS = {
    Severity.HIGH.value: "#e74c3c",
    Severity.MEDIUM.value: "#e67e22",
    Severity.LOW.value: "#f1c40f",
    Severity.INFO.value: "#3498db",
}


# --------------------------------------------------------------------------- #
# JSON
# --------------------------------------------------------------------------- #
def to_json(results: list[AnalysisResult]) -> str:
    payload = [r.to_dict() for r in results]
    if len(payload) == 1:
        payload = payload[0]
    return json.dumps(payload, indent=2, ensure_ascii=False)


def write_json(results: list[AnalysisResult], path: str | Path) -> Path:
    path = Path(path)
    path.write_text(to_json(results), encoding="utf-8")
    return path


# --------------------------------------------------------------------------- #
# HTML
# --------------------------------------------------------------------------- #
def _esc(value) -> str:
    return html.escape(str(value), quote=True)


def _render_card(result: AnalysisResult) -> str:
    v = result.verdict
    ctx = result.context

    context_rows = "".join(
        f"<tr><th>{_esc(k)}</th><td>{_esc(val)}</td></tr>"
        for k, val in [
            ("Input URL", result.input_url),
            ("Host", ctx.get("host")),
            ("Registrable domain", ctx.get("registrable_domain") or "-"),
            ("Subdomain", ctx.get("subdomain") or "-"),
            ("TLD / suffix", ctx.get("suffix") or "-"),
            ("Scheme", ctx.get("scheme")),
            ("Analysed at", result.timestamp),
            ("Mode", "Online" if result.online else "Offline"),
        ]
    )

    if result.signals:
        signal_rows = "".join(
            f"<tr>"
            f"<td><span class='dot' style='background:{_SEVERITY_COLORS.get(s.severity.value, '#888')}'></span>"
            f"{_esc(s.severity.value.title())}</td>"
            f"<td>{_esc(s.category)}</td>"
            f"<td><strong>{_esc(s.title)}</strong><br><span class='muted'>{_esc(s.detail)}</span></td>"
            f"<td class='pts'>{'+' if s.points else ''}{s.points}</td>"
            f"</tr>"
            for s in result.signals
        )
    else:
        signal_rows = "<tr><td colspan='4' class='muted'>No risk signals were raised.</td></tr>"

    error_banner = (
        f"<div class='error'>{_esc(result.error)}</div>" if result.error else ""
    )
    trust_note = (
        "<div class='note'>Score capped: registrable domain is on the trusted allow-list.</div>"
        if result.trust_capped else ""
    )

    return f"""
    <section class="card">
      <div class="head" style="border-color:{v.hex}">
        <div class="url" title="{_esc(result.input_url)}">{_esc(result.input_url)}</div>
        <div class="verdict" style="color:{v.hex}">{v.emoji} {_esc(v.label)}</div>
      </div>
      {error_banner}
      <div class="gauge">
        <div class="bar"><div class="fill" style="width:{result.score}%;background:{v.hex}"></div></div>
        <div class="score" style="color:{v.hex}">{result.score}<span>/100</span></div>
      </div>
      {trust_note}
      <div class="grid">
        <div>
          <h3>URL details</h3>
          <table class="ctx">{context_rows}</table>
        </div>
        <div>
          <h3>Risk signals ({len(result.signals)})</h3>
          <table class="sig">
            <thead><tr><th>Severity</th><th>Module</th><th>Finding</th><th>Pts</th></tr></thead>
            <tbody>{signal_rows}</tbody>
          </table>
        </div>
      </div>
    </section>
    """


_PAGE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>PhishVane Report</title>
<style>
  :root {{ color-scheme: light dark; }}
  * {{ box-sizing: border-box; }}
  body {{ font-family: -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif;
         margin: 0; background: #0f1419; color: #e6e6e6; padding: 24px; }}
  .wrap {{ max-width: 980px; margin: 0 auto; }}
  .top {{ display:flex; align-items:center; gap:12px; margin-bottom: 20px; }}
  .logo {{ font-size: 26px; font-weight: 800; letter-spacing: .5px; }}
  .logo span {{ color:#4aa3ff; }}
  .sub {{ color:#8a94a6; font-size: 13px; }}
  .card {{ background:#161b22; border:1px solid #232a33; border-radius:14px;
          padding:20px; margin-bottom:22px; }}
  .head {{ display:flex; justify-content:space-between; align-items:center;
          gap:16px; border-left:5px solid; padding-left:12px; }}
  .url {{ font-family: ui-monospace, Menlo, Consolas, monospace; font-size:14px;
         word-break: break-all; }}
  .verdict {{ font-size: 20px; font-weight: 800; white-space: nowrap; }}
  .gauge {{ display:flex; align-items:center; gap:16px; margin:18px 0; }}
  .bar {{ flex:1; height:14px; background:#0d1117; border-radius:8px; overflow:hidden;
         border:1px solid #232a33; }}
  .fill {{ height:100%; border-radius:8px; }}
  .score {{ font-size:26px; font-weight:800; }}
  .score span {{ font-size:14px; color:#8a94a6; font-weight:600; }}
  .grid {{ display:grid; grid-template-columns: 1fr 1fr; gap:22px; }}
  @media (max-width: 760px) {{ .grid {{ grid-template-columns: 1fr; }} }}
  h3 {{ font-size:13px; text-transform:uppercase; letter-spacing:.6px;
       color:#8a94a6; margin:0 0 8px; }}
  table {{ width:100%; border-collapse:collapse; font-size:13px; }}
  .ctx th {{ text-align:left; color:#8a94a6; font-weight:600; padding:5px 10px 5px 0;
            white-space:nowrap; vertical-align:top; }}
  .ctx td {{ padding:5px 0; word-break:break-all; }}
  .sig thead th {{ text-align:left; color:#8a94a6; font-weight:600;
                  border-bottom:1px solid #232a33; padding:6px 8px; }}
  .sig td {{ padding:8px; border-bottom:1px solid #1d232b; vertical-align:top; }}
  .pts {{ text-align:right; font-weight:700; font-family: ui-monospace, monospace; }}
  .muted {{ color:#8a94a6; }}
  .dot {{ display:inline-block; width:9px; height:9px; border-radius:50%;
         margin-right:6px; }}
  .note {{ background:#12212f; border:1px solid #1d3a52; color:#9ec7e6;
          padding:8px 12px; border-radius:8px; font-size:13px; margin-bottom:12px; }}
  .error {{ background:#2a1416; border:1px solid #5a2a2e; color:#f0a5a5;
           padding:8px 12px; border-radius:8px; font-size:13px; margin:10px 0; }}
  .foot {{ color:#5c6570; font-size:12px; text-align:center; margin-top:8px; }}
</style>
</head>
<body>
  <div class="wrap">
    <div class="top">
      <div class="logo">Phish<span>Vane</span></div>
      <div class="sub">Phishing URL Threat Report &middot; {count} URL(s)</div>
    </div>
    {cards}
    <div class="foot">Generated by PhishVane &middot; heuristic analysis for triage support, not a definitive verdict.</div>
  </div>
</body>
</html>
"""


def render_html(results: list[AnalysisResult]) -> str:
    cards = "\n".join(_render_card(r) for r in results)
    return _PAGE.format(count=len(results), cards=cards)


def write_html(results: list[AnalysisResult], path: str | Path) -> Path:
    path = Path(path)
    path.write_text(render_html(results), encoding="utf-8")
    return path
