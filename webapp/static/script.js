"use strict";

const VERDICT_COLORS = {
  safe: "var(--safe)",
  suspicious: "var(--suspicious)",
  likely: "var(--likely)",
  dangerous: "var(--dangerous)",
};
const SEVERITY_COLORS = {
  high: "var(--dangerous)",
  medium: "var(--likely)",
  low: "var(--suspicious)",
  info: "var(--info)",
};

const form = document.getElementById("analyze-form");
const urlInput = document.getElementById("url");
const offlineInput = document.getElementById("offline");
const submitBtn = document.getElementById("submit-btn");
const loading = document.getElementById("loading");
const resultEl = document.getElementById("result");

// Example chips fill the input and immediately analyze.
document.querySelectorAll(".chip").forEach((chip) => {
  chip.addEventListener("click", () => {
    urlInput.value = chip.dataset.url;
    form.requestSubmit();
  });
});

// Support pre-filled, auto-run links: /?url=<url>&offline=1
(function autoRunFromQuery() {
  const params = new URLSearchParams(window.location.search);
  const preset = params.get("url");
  if (!preset) return;
  urlInput.value = preset;
  offlineInput.checked = ["1", "true", "on", "yes"].includes(
    (params.get("offline") || "").toLowerCase());
  form.requestSubmit();
})();

form.addEventListener("submit", async (e) => {
  e.preventDefault();
  const url = urlInput.value.trim();
  if (!url) return;

  setLoading(true);
  resultEl.classList.add("hidden");

  try {
    const resp = await fetch("/api/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url, offline: offlineInput.checked }),
    });
    const data = await resp.json();
    if (!resp.ok) throw new Error(data.error || "Analysis failed.");
    renderResult(data);
  } catch (err) {
    renderError(err.message);
  } finally {
    setLoading(false);
  }
});

function setLoading(on) {
  loading.classList.toggle("hidden", !on);
  submitBtn.disabled = on;
  submitBtn.textContent = on ? "Analyzing…" : "Analyze";
}

function esc(str) {
  const d = document.createElement("div");
  d.textContent = str == null ? "" : String(str);
  return d.innerHTML;
}

function renderError(message) {
  resultEl.innerHTML = `<div class="note-line note-error">⚠ ${esc(message)}</div>`;
  resultEl.classList.remove("hidden");
}

function renderResult(data) {
  const color = VERDICT_COLORS[data.verdict.level] || "var(--muted)";
  const ctx = data.context || {};

  const contextRows = [
    ["Input URL", data.input_url],
    ["Host", ctx.host],
    ["Registrable domain", ctx.registrable_domain || "—"],
    ["Subdomain", ctx.subdomain || "—"],
    ["TLD / suffix", ctx.suffix || "—"],
    ["Scheme", ctx.scheme],
    ["Analyzed at", data.timestamp],
    ["Mode", data.online ? "Online" : "Offline"],
  ].map(([k, v]) => `<tr><th>${esc(k)}</th><td>${esc(v)}</td></tr>`).join("");

  const scored = (data.signals || []);
  let signalsHtml;
  if (scored.length === 0) {
    signalsHtml = `<li class="no-signals">No risk signals were raised.</li>`;
  } else {
    signalsHtml = scored.map((s) => {
      const sc = SEVERITY_COLORS[s.severity] || "var(--muted)";
      const pts = s.points > 0 ? `+${s.points}` : `${s.points}`;
      return `
        <li class="sig-item">
          <span class="sig-dot" style="background:${sc}"></span>
          <div class="sig-body">
            <div class="sig-meta">
              <span class="sig-title">${esc(s.title)}</span>
              <span class="sig-pts" style="color:${sc}">${pts}</span>
            </div>
            <div class="sig-cat">${esc(s.category)} · ${esc(s.severity)}</div>
            <div class="sig-detail">${esc(s.detail)}</div>
          </div>
        </li>`;
    }).join("");
  }

  const errorNote = data.error
    ? `<div class="note-line note-error">⚠ ${esc(data.error)}</div>` : "";
  const trustNote = data.trust_capped
    ? `<div class="note-line note-trust">ℹ Score capped: registrable domain is on the trusted allow-list.</div>` : "";

  resultEl.innerHTML = `
    <div class="result-head" style="border-color:${color}">
      <div class="result-url">${esc(data.input_url)}</div>
      <div class="result-verdict" style="color:${color}">${data.verdict.emoji} ${esc(data.verdict.label)}</div>
    </div>
    ${errorNote}
    <div class="gauge">
      <div class="gauge-bar"><div class="gauge-fill" style="background:${color}"></div></div>
      <div class="gauge-score" style="color:${color}">${data.score}<small>/100</small></div>
    </div>
    ${trustNote}
    <div class="cols">
      <div>
        <h3>URL details</h3>
        <table class="ctx-table">${contextRows}</table>
      </div>
      <div>
        <h3>Risk signals (${scored.length})</h3>
        <ul class="signals">${signalsHtml}</ul>
      </div>
    </div>
  `;

  resultEl.classList.remove("hidden");
  // Animate the gauge fill after paint.
  requestAnimationFrame(() => {
    const fill = resultEl.querySelector(".gauge-fill");
    if (fill) fill.style.width = `${data.score}%`;
  });
}
