#!/usr/bin/env python3
"""PhishVane web dashboard (Flask).

A lightweight browser front-end over the same :class:`phishvane.Analyzer` used
by the CLI. Paste a URL, choose online/offline, and get an animated risk gauge,
verdict and full signal breakdown rendered in the browser.

Run:
    python webapp/app.py
    # then open http://127.0.0.1:5000
"""

from __future__ import annotations

import sys
from pathlib import Path

# Make the project root importable when run as `python webapp/app.py`.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from flask import Flask, jsonify, render_template, request  # noqa: E402

from phishvane import Analyzer, __version__  # noqa: E402

app = Flask(__name__)


SEVERITY_HEX = {
    "high": "#e74c3c", "medium": "#e67e22", "low": "#f1c40f", "info": "#3498db",
}


@app.route("/")
def index():
    return render_template("index.html", version=__version__)


@app.route("/scan")
def scan():
    """Server-rendered result page (shareable link, e.g. /scan?url=...&offline=1)."""
    url = (request.args.get("url") or "").strip()
    if not url:
        return render_template("index.html", version=__version__)
    offline = (request.args.get("offline") or "").lower() in ("1", "true", "on", "yes")
    result = Analyzer(online=not offline).analyze(url)
    return render_template("result.html", version=__version__,
                           r=result.to_dict(), sev_hex=SEVERITY_HEX)


@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    data = request.get_json(silent=True) or request.form
    url = (data.get("url") or "").strip()
    if not url:
        return jsonify({"error": "No URL provided."}), 400

    # Accept offline flag as bool or common truthy strings.
    offline_raw = data.get("offline", False)
    offline = str(offline_raw).lower() in ("1", "true", "on", "yes") \
        if not isinstance(offline_raw, bool) else offline_raw

    result = Analyzer(online=not offline).analyze(url)
    return jsonify(result.to_dict())


@app.route("/healthz")
def healthz():
    return jsonify({"status": "ok", "version": __version__})


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
