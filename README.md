# 🎣 PhishVane

**A defensive phishing-URL threat-analysis tool for CERT / SOC triage.**

PhishVane inspects a URL through several independent detection modules, aggregates
their weighted risk signals into a single **0–100 score**, and returns an
**explainable verdict** — so an analyst instantly sees not just *how risky* a link
is, but *why*.

```
🔴  DANGEROUS   score 88/100  ██████████████████████████░░░░
  host paypal-login.tk   domain paypal-login.tk   tld tk   mode offline
  HIGH      Typosquatting   Brand name embedded in domain ('paypal')      +24
  MEDIUM    TLD Reputation  High-abuse TLD (.tk)                           +12
  MEDIUM    Lexical         Phishing-related keywords: verify, account     +10
  LOW       Lexical         No HTTPS                                       +5
  ...
```

---

## Why PhishVane?

Phishing remains the number-one initial-access vector in real-world incidents, and
a CERT/SOC analyst's first job when a suspicious link is reported is **fast, defensible
triage**. Manually eyeballing a URL is error-prone; commercial sandboxes are slow and
opaque. PhishVane provides a **transparent, scriptable, offline-capable** first-pass
assessment that explains every point it assigns.

## Features

- **Multi-module detection engine** — seven independent analysers:
  | Module | Type | Looks for |
  |---|---|---|
  | Lexical | offline | IP-as-host, `@` tricks, deep subdomains, keywords, entropy, shorteners, embedded URLs, non-standard ports, no-HTTPS |
  | Typosquatting | offline | look-alike domains (edit distance), combosquatting, brand-in-subdomain, wrong-TLD impersonation, IDN/homoglyph attacks |
  | TLD Reputation | offline | high-abuse top-level domains |
  | WHOIS Intel | online | freshly-registered domains (age) |
  | DNS Intel | online | non-resolving hosts |
  | TLS Intel | online | invalid / expired / self-signed certificates |
  | Reputation | online + local | local threat blocklist and (optional) Google Safe Browsing |
- **Explainable 0–100 scoring** with four verdict bands (Safe / Suspicious / Likely Phishing / Dangerous).
- **Trusted allow-list safeguard** so known-good domains can't be misflagged.
- **Two interfaces** — a colour CLI **and** a Flask web dashboard.
- **Three output formats** — rich terminal, machine-readable **JSON**, and a standalone **HTML report**.
- **Online with graceful offline fallback** — `--offline` runs pure heuristics with zero network calls and zero secrets.
- **Extensible knowledge base** — brands, blocklist, suspicious TLDs and keywords are plain text files.

## Tech stack

Python 3 · [`tldextract`](https://pypi.org/project/tldextract/) · [`dnspython`](https://pypi.org/project/dnspython/) · [`python-whois`](https://pypi.org/project/python-whois/) · [`rich`](https://pypi.org/project/rich/) · [`Flask`](https://pypi.org/project/Flask/) · [`requests`](https://pypi.org/project/requests/)

## Installation

```bash
git clone <your-repo-url>
cd PhishVane
python -m venv .venv
# Windows: .venv\Scripts\activate    |    macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
```

## Usage — CLI

```bash
# Analyze a single URL
python cli.py https://paypal-login.tk/verify-account

# Analyze many URLs from a file
python cli.py --batch samples/urls.txt

# Offline heuristics only (no WHOIS/DNS/TLS/reputation network calls)
python cli.py http://192.168.0.5/login --offline

# Write machine-readable and shareable reports
python cli.py --batch samples/urls.txt --json reports/scan.json --html reports/scan.html
```

**Exit codes:** `0` = all URLs Safe/Suspicious · `1` = at least one Likely/Dangerous · `2` = usage error.

## Usage — Web dashboard

```bash
python webapp/app.py
# open http://127.0.0.1:5000
```

Paste a URL, optionally toggle **Offline mode**, and view an animated risk gauge,
verdict and full signal breakdown.

## Optional: Google Safe Browsing

The reputation module works fully offline via `phishvane/data/blocklist.txt`. To
additionally query Google Safe Browsing, set an API key — no code changes needed:

```bash
# Windows PowerShell:  $env:PHISHVANE_GSB_KEY="your-key"
export PHISHVANE_GSB_KEY="your-key"
```

## How it works

```
        ┌────────────┐
 URL ─▶ │ URLContext │  parse once: scheme, host, domain, TLD, IP/IDN flags
        └─────┬──────┘
              │  (shared context)
     ┌────────┼─────────────────────────────────────────┐
     ▼        ▼            ▼          ▼        ▼      ▼   ▼
  Lexical  Typosquat    TLD Rep   WHOIS    DNS    TLS  Reputation
     │        │            │         │       │      │     │
     └────────┴─────┬──────┴─────────┴───────┴──────┴─────┘
                    ▼
            weighted signals  ──▶  sum → clamp 0–100 → trusted cap
                    ▼
            Verdict (Safe / Suspicious / Likely / Dangerous)
                    ▼
        CLI  ·  JSON  ·  HTML report  ·  Web dashboard
```

## Project layout

```
PhishVane/
├── cli.py                 # command-line interface (rich output)
├── webapp/                # Flask web dashboard
│   ├── app.py
│   ├── templates/index.html
│   └── static/{style.css, script.js}
├── phishvane/             # core package
│   ├── analyzer.py        # orchestrates modules → score → verdict
│   ├── scoring.py         # verdict bands
│   ├── signals.py         # Signal / ModuleResult data models
│   ├── utils.py           # URLContext, entropy, levenshtein
│   ├── report.py          # JSON + HTML reports
│   ├── modules/           # the seven detection modules
│   └── data/              # brands, trusted domains, TLDs, keywords, blocklist
├── samples/urls.txt       # demo inputs
├── tests/                 # pytest suite
└── requirements.txt
```

## Testing

```bash
python -m pytest -q
```

## Responsible use

PhishVane is a **defensive** tool for analysing links you are authorised to
investigate. Its output is a heuristic decision aid to support triage, not a
definitive judgement, and it does not visit or execute page content.

## License

MIT — see [LICENSE](LICENSE).
