#!/usr/bin/env python3
"""PhishVane command-line interface.

Examples
--------
    python cli.py https://paypal-login.tk/verify
    python cli.py --batch samples/urls.txt --html reports/scan.html
    python cli.py http://192.168.0.5/login --offline --json

Exit codes: 0 = all URLs Safe/Suspicious, 1 = at least one Likely/Dangerous,
2 = usage error.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from phishvane import Analyzer, __version__, report
from phishvane.signals import Severity

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
except ImportError:  # pragma: no cover
    sys.stderr.write("PhishVane requires the 'rich' package. Run: pip install -r requirements.txt\n")
    sys.exit(2)

console = Console()

_SEVERITY_STYLE = {
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "dark_orange",
    Severity.LOW: "yellow",
    Severity.INFO: "cyan",
}
_RISK_LEVELS = {"likely", "dangerous"}


def _score_bar(score: int, color: str, width: int = 30) -> Text:
    filled = round(score / 100 * width)
    bar = Text()
    bar.append("█" * filled, style=color)
    bar.append("░" * (width - filled), style="grey37")
    return bar


def _print_result(result) -> None:
    v = result.verdict

    header = Text()
    header.append(f"{v.emoji}  {v.label.upper()}", style=f"bold {v.color}")
    header.append(f"   score {result.score}/100  ", style=f"bold {v.color}")
    header.append_text(_score_bar(result.score, v.color))

    console.print(Panel(header, title=f"[bold]{result.input_url}[/bold]",
                        border_style=v.color, expand=False))

    if result.error:
        console.print(f"  [red]! {result.error}[/red]\n")
        return

    ctx = result.context
    meta = (f"  [grey62]host[/] {ctx.get('host')}   "
            f"[grey62]domain[/] {ctx.get('registrable_domain') or '-'}   "
            f"[grey62]tld[/] {ctx.get('suffix') or '-'}   "
            f"[grey62]mode[/] {'online' if result.online else 'offline'}")
    console.print(meta)
    if result.trust_capped:
        console.print("  [cyan]i trusted allow-list domain - score capped[/cyan]")

    scored = [s for s in result.signals if s.points > 0]
    if scored:
        table = Table(show_edge=False, pad_edge=False, box=None, padding=(0, 1))
        table.add_column("Sev", no_wrap=True)
        table.add_column("Module", style="grey62", no_wrap=True)
        table.add_column("Finding")
        table.add_column("Pts", justify="right", no_wrap=True)
        for s in result.signals:
            if s.points <= 0:
                continue
            style = _SEVERITY_STYLE.get(s.severity, "white")
            table.add_row(
                Text(s.severity.value.upper(), style=style),
                s.category,
                Text.assemble((s.title + "  ", "bold"), (s.detail, "grey62")),
                Text(f"+{s.points}", style=style),
            )
        console.print(table)
    else:
        console.print("  [green]No risk signals raised.[/green]")
    console.print()


def _print_summary(results) -> None:
    table = Table(title="Batch summary", title_style="bold", header_style="bold")
    table.add_column("URL", overflow="fold")
    table.add_column("Score", justify="right")
    table.add_column("Verdict")
    for r in results:
        table.add_row(r.input_url, str(r.score),
                      Text(f"{r.verdict.emoji} {r.verdict.label}", style=r.verdict.color))
    console.print(table)


def _collect_urls(args) -> list[str]:
    urls = list(args.urls)
    if args.batch:
        path = Path(args.batch)
        if not path.exists():
            console.print(f"[red]Batch file not found: {path}[/red]")
            sys.exit(2)
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                urls.append(line)
    return urls


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="phishvane",
        description="PhishVane - defensive phishing-URL threat analyzer.",
        epilog="Analyze suspicious links you are authorised to investigate.",
    )
    p.add_argument("urls", nargs="*", help="One or more URLs to analyze.")
    p.add_argument("-b", "--batch", metavar="FILE",
                   help="File with one URL per line (# comments allowed).")
    p.add_argument("--offline", action="store_true",
                   help="Run only offline heuristics (no WHOIS/DNS/TLS/reputation network calls).")
    p.add_argument("--json", nargs="?", const="-", metavar="PATH",
                   help="Write JSON report to PATH (or stdout if PATH omitted).")
    p.add_argument("--html", metavar="PATH", help="Write a standalone HTML report to PATH.")
    p.add_argument("-q", "--quiet", action="store_true",
                   help="Suppress the per-URL detail; show only the summary.")
    p.add_argument("-V", "--version", action="version", version=f"PhishVane {__version__}")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    urls = _collect_urls(args)
    if not urls:
        console.print("[yellow]No URLs provided.[/yellow] Try: python cli.py https://example.com")
        return 2

    if not args.quiet:
        console.rule(f"[bold]Phish[cyan]Vane[/cyan][/bold]  v{__version__}", style="grey42")

    analyzer = Analyzer(online=not args.offline)
    results = []
    for url in urls:
        result = analyzer.analyze(url)
        results.append(result)
        if not args.quiet:
            _print_result(result)

    if len(results) > 1:
        _print_summary(results)

    if args.json is not None:
        if args.json == "-":
            console.print_json(report.to_json(results))
        else:
            path = report.write_json(results, args.json)
            console.print(f"[green]JSON report written to[/green] {path}")

    if args.html:
        path = report.write_html(results, args.html)
        console.print(f"[green]HTML report written to[/green] {path}")

    return 1 if any(r.verdict.level in _RISK_LEVELS for r in results) else 0


if __name__ == "__main__":
    raise SystemExit(main())
