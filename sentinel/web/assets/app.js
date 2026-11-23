// Sentinel-BD dashboard.
//
// Safety rule for this file: indicator values are attacker-controlled. They
// are only ever inserted as text (textContent / text nodes), shown defanged,
// and never turned into links. There is no innerHTML anywhere.

const $ = (sel, root = document) => root.querySelector(sel);
const SVG_NS = "http://www.w3.org/2000/svg";
const reduceMotion = matchMedia("(prefers-reduced-motion: reduce)").matches;

/* ------------------------------------------------------------------ DOM */

function h(tag, props = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(props || {})) {
    if (value === null || value === undefined || value === false) continue;
    if (key === "class") node.className = value;
    else if (key === "dataset") Object.assign(node.dataset, value);
    else if (key.startsWith("on")) node.addEventListener(key.slice(2), value);
    else if (key === "style") Object.assign(node.style, value);
    else node.setAttribute(key, value === true ? "" : value);
  }
  append(node, children);
  return node;
}

function s(tag, attrs = {}, ...children) {
  const node = document.createElementNS(SVG_NS, tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (key.startsWith("on")) node.addEventListener(key.slice(2), value);
    else node.setAttribute(key, value);
  }
  append(node, children);
  return node;
}

function append(node, children) {
  for (const child of children.flat()) {
    if (child === null || child === undefined || child === false) continue;
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
}

function clear(node) {
  while (node.firstChild) node.firstChild.remove();
  return node;
}

/* --------------------------------------------------------------- format */

const nf = new Intl.NumberFormat("en");
const fmt = (n) => nf.format(n ?? 0);
const rtf = new Intl.RelativeTimeFormat("en", { numeric: "auto" });

function ago(iso) {
  if (!iso) return "never";
  const seconds = (new Date(iso).getTime() - Date.now()) / 1000;
  const units = [["year", 31536000], ["month", 2592000], ["day", 86400], ["hour", 3600], ["minute", 60]];
  for (const [unit, size] of units) {
    if (Math.abs(seconds) >= size) return rtf.format(Math.round(seconds / size), unit);
  }
  return "just now";
}

function shortDate(isoDay) {
  return new Date(isoDay + "T00:00:00Z").toLocaleDateString("en-GB", { day: "numeric", month: "short", timeZone: "UTC" });
}

/** hxxp://evil[.]com/path - readable, but not clickable or resolvable by accident. */
function defang(type, value) {
  const lastDot = (text) => text.replace(/\.(?=[^.]*$)/, "[.]");
  if (type === "ipv4" || type === "domain") return lastDot(value);
  if (type === "url") {
    const m = value.match(/^([a-z]+):\/\/([^/?#]+)(.*)$/i);
    if (!m) return value;
    const scheme = m[1].toLowerCase().replace(/^http/, "hxxp").replace(/^ftp/, "fxp");
    return `${scheme}://${lastDot(m[2])}${m[3]}`;
  }
  return value;
}

const TYPE_LABEL = { ipv4: "IP", domain: "Domain", url: "URL", sha256: "SHA-256", sha1: "SHA-1", md5: "MD5" };
const SOURCES = {
  feodotracker: ["FT", "Feodo Tracker"],
  urlhaus: ["UH", "URLhaus"],
  threatfox: ["TF", "ThreatFox"],
  openphish: ["OP", "OpenPhish"],
  phishhunter: ["PH", "Phishing hunter"],
  honeypot: ["HP", "Sentinel-BD honeypot"],
};
const sourceName = (key) => (SOURCES[key] || [key.slice(0, 2).toUpperCase(), key])[1];
const sourceAbbr = (key) => (SOURCES[key] || [key.slice(0, 2).toUpperCase(), key])[0];
const SEV_COLOR = { high: "var(--critical)", medium: "var(--serious)", low: "var(--muted)" };
const REASON_TEXT = {
  "tld": (v) => ["Bangladeshi domain", `Uses the ${v} country domain`],
  "impersonates": (v) => [`Imitates ${v}`, `The name looks like a copy of ${v}`],
  "ip": () => ["Bangladeshi IP space", "Address allocated to Bangladesh by APNIC"],
  "geo": () => ["Located in Bangladesh", "The reporting feed places it in Bangladesh"],
};
function reasonInfo(reason) {
  const [kind, value] = reason.split(":");
  return (REASON_TEXT[kind] || (() => [reason, ""]))(value);
}

function animateNumber(node, to) {
  const from = Number(node.dataset.value || 0);
  node.dataset.value = to;
  if (reduceMotion || from === to) { node.textContent = fmt(to); return; }
  const start = performance.now();
  const duration = 700;
  const step = (now) => {
    const t = Math.min(1, (now - start) / duration);
    const eased = 1 - Math.pow(1 - t, 3);
    node.textContent = fmt(Math.round(from + (to - from) * eased));
    if (t < 1) requestAnimationFrame(step);
  };
  requestAnimationFrame(step);
}

function toast(message) {
  const node = $("#toast");
  node.textContent = message;
  node.classList.add("show");
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => node.classList.remove("show"), 1800);
}

async function copy(text, message = "Copied") {
  try {
    await navigator.clipboard.writeText(text);
    toast(message);
  } catch {
    toast("Copy failed: select the text and copy it manually");
  }
}

/* ------------------------------------------------------------------ API */

async function api(path, params = {}, signal) {
  const url = new URL(path, location.origin);
  for (const [key, value] of Object.entries(params)) {
    if (value !== "" && value !== null && value !== undefined && value !== false) url.searchParams.set(key, value);
  }
  const response = await fetch(url, { signal, headers: { Accept: "application/json" } });
  if (!response.ok) throw new Error(`${response.status} ${response.statusText}`);
  return response.json();
}

/* ---------------------------------------------------------------- state */

const DEFAULTS = { scope: "all", sort: "score", type: "", severity: "", source: "", malware: "", reason: "", day: "", q: "", offset: 0 };
const FILTER_KEYS = ["type", "severity", "source", "malware", "reason", "day", "q"];
const state = { ...DEFAULTS };
let stats = null;
let rows = [];
let cursor = -1;
let tableAbort = null;

function readHash() {
  const params = new URLSearchParams(location.hash.slice(1));
  for (const key of Object.keys(DEFAULTS)) {
    const value = params.get(key);
    state[key] = value === null ? DEFAULTS[key] : key === "offset" ? Math.max(0, parseInt(value, 10) || 0) : value;
  }
}

function writeHash() {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(state)) {
    if (value !== DEFAULTS[key] && value !== "") params.set(key, value);
  }
  const hash = params.toString();
  history.replaceState(null, "", hash ? `#${hash}` : location.pathname);
}

function setFilter(changes) {
  Object.assign(state, changes, { offset: "offset" in changes ? changes.offset : 0 });
  writeHash();
  syncControls();
  loadTable();
}

const activeFilterCount = () => FILTER_KEYS.filter((key) => state[key]).length;

/* --------------------------------------------------------------- status */

function renderStatus() {
  const dot = $("#status .status-dot");
  const text = $("#status .status-text");
  const runs = stats.last_runs || [];
  const ok = runs.filter((run) => run.ok).length;
  dot.dataset.state = !runs.length ? "warn" : ok === runs.length ? "ok" : ok ? "warn" : "error";
  text.textContent = runs.length ? `${ok}/${runs.length} feeds healthy` : "No collection runs yet";
  $("#status .status-detail").textContent = runs.length ? ` · updated ${ago(stats.last_updated)}` : "";
}

/* -------------------------------------------------------------- readout */

const READOUT = [
  {
    key: "total", label: "indicators tracked", hint: "Show everything",
    value: () => stats.total,
    active: () => state.scope === "all" && !activeFilterCount() && state.sort === "score",
    apply: () => setFilter({ ...DEFAULTS }),
  },
  {
    key: "bd", label: "aimed at Bangladesh", hint: "Filter to Bangladesh",
    value: () => stats.bd_relevant,
    active: () => state.scope === "bd" && !activeFilterCount(),
    apply: () => setFilter({ ...DEFAULTS, scope: "bd" }),
  },
  {
    key: "new", label: "new in the last 24 h", hint: "Newest first",
    value: () => stats.new_24h,
    active: () => state.sort === "newest" && !activeFilterCount(),
    apply: () => setFilter({ ...DEFAULTS, scope: state.scope, sort: "newest" }),
  },
  {
    key: "high", label: "high severity", hint: "Score 80 or more",
    value: () => stats.by_severity.high || 0,
    active: () => state.severity === "high",
    apply: () => setFilter({ severity: state.severity === "high" ? "" : "high" }),
  },
];

function renderReadout() {
  const root = $("#readout");
  if (!root.children.length) {
    for (const item of READOUT) {
      root.append(
        h("button", { type: "button", class: "readout-item", dataset: { key: item.key }, onclick: item.apply },
          h("span", { class: "readout-num" }, "0"),
          h("span", { class: "readout-label" }, item.label),
          h("span", { class: "readout-hint" }, item.hint)),
      );
    }
  }
  for (const item of READOUT) {
    animateNumber($(`[data-key="${item.key}"] .readout-num`, root), item.value());
  }
  syncReadout();
}

function syncReadout() {
  for (const item of READOUT) {
    const node = $(`#readout [data-key="${item.key}"]`);
    if (node) node.setAttribute("aria-pressed", item.active() ? "true" : "false");
  }
}

/* ---------------------------------------------------------------- pulse */

function niceMax(value) {
  if (value <= 5) return 5;
  const power = 10 ** Math.floor(Math.log10(value));
  for (const step of [1, 2, 2.5, 5, 10]) if (step * power >= value) return step * power;
  return value;
}

function renderPulse() {
  const root = $("#pulse");
  const points = stats.timeline;
  const width = Math.max(280, root.clientWidth);
  const height = root.clientHeight || 220;
  const pad = { top: 8, right: 4, bottom: 24, left: 44 };
  const innerW = width - pad.left - pad.right;
  const innerH = height - pad.top - pad.bottom;
  const max = niceMax(Math.max(1, ...points.map((p) => p.count)));
  const slot = innerW / points.length;
  const barW = Math.max(2, slot - Math.min(6, slot * 0.28));
  const y = (v) => pad.top + innerH - (v / max) * innerH;

  const svg = s("svg", { viewBox: `0 0 ${width} ${height}`, role: "img", "aria-label": "New indicators per day over the last 30 days" });
  const plot = s("g", { class: state.day ? "has-selection" : "" });

  for (const tick of [0, max / 2, max]) {
    svg.append(
      s("line", { class: tick === 0 ? "baseline" : "gridline", x1: pad.left, x2: width - pad.right, y1: y(tick), y2: y(tick) }),
      s("text", { class: "tick", x: pad.left - 8, y: y(tick) + 4, "text-anchor": "end" }, compact(tick)),
    );
  }

  points.forEach((point, i) => {
    const x = pad.left + i * slot + (slot - barW) / 2;
    const barH = Math.max(point.count ? 2 : 0, (point.count / max) * innerH);
    const radius = Math.min(4, barW / 2, barH);
    const bar = s("path", {
      class: `bar${state.day === point.day ? " selected" : ""}`,
      d: roundedTop(x, y(0) - barH, barW, barH, radius),
    });
    const hit = s("rect", {
      class: "hit", x: pad.left + i * slot, y: pad.top, width: slot, height: innerH,
      tabindex: 0, role: "button",
      "aria-label": `${shortDate(point.day)}: ${fmt(point.count)} new indicators`,
      "aria-pressed": state.day === point.day ? "true" : "false",
      onmouseenter: (event) => { bar.classList.add("hover"); showTip(event, point); },
      onmousemove: (event) => showTip(event, point),
      onmouseleave: () => { bar.classList.remove("hover"); hideTip(); },
      onfocus: (event) => showTip(event, point),
      onblur: hideTip,
      onclick: () => setFilter({ day: state.day === point.day ? "" : point.day }),
      onkeydown: (event) => {
        if (event.key === "Enter" || event.key === " ") { event.preventDefault(); event.currentTarget.dispatchEvent(new Event("click")); }
      },
    });
    plot.append(hit, bar);

    const isEdge = i === 0 || i === points.length - 1 || i === Math.floor(points.length / 2);
    if (isEdge) {
      svg.append(s("text", {
        class: "tick", x: x + barW / 2, y: height - 6,
        "text-anchor": i === 0 ? "start" : i === points.length - 1 ? "end" : "middle",
      }, i === points.length - 1 ? "Today" : shortDate(point.day)));
    }
  });
  svg.append(plot);
  clear(root).append(svg);

  const total = points.reduce((sum, p) => sum + p.count, 0);
  const peak = points.reduce((best, p) => (p.count > best.count ? p : best), points[0]);
  append(clear($("#pulse-summary")), [
    h("div", {}, h("span", { class: "num" }, fmt(total)), " in 30 days"),
    peak.count ? h("div", { class: "muted" }, `peak ${fmt(peak.count)} on ${shortDate(peak.day)}`) : null,
  ]);
}

function roundedTop(x, y, w, hgt, r) {
  if (hgt <= 0) return "";
  return `M${x},${y + hgt}V${y + r}Q${x},${y} ${x + r},${y}H${x + w - r}Q${x + w},${y} ${x + w},${y + r}V${y + hgt}Z`;
}

function compact(n) {
  return n >= 1000 ? `${+(n / 1000).toFixed(n >= 10000 ? 0 : 1)}k` : String(n);
}

function showTip(event, point) {
  const tip = $("#tooltip");
  clear(tip).append(h("strong", {}, fmt(point.count)), " new · ", shortDate(point.day));
  const rect = event.currentTarget.getBoundingClientRect();
  const x = event.clientX ?? rect.left + rect.width / 2;
  tip.style.left = `${Math.min(innerWidth - 80, Math.max(80, x))}px`;
  tip.style.top = `${rect.top + 8}px`;
  tip.hidden = false;
}
function hideTip() { $("#tooltip").hidden = true; }

/* --------------------------------------------------------------- brands */

function renderBrands() {
  const root = clear($("#brands"));
  const brands = Object.entries(stats.brands || {});
  const signals = [
    ["tld:.bd", "tld", ".bd domains"],
    ["ip:bd-space", "ip", "BD IP space"],
    ["geo:BD", "geo", "Geolocated to BD"],
  ].map(([reason, kind, label]) => [reason, label, (stats.bd_reason_kinds || {})[kind] || 0]).filter((x) => x[2]);

  if (!brands.length) {
    root.append(h("p", { class: "empty" },
      h("strong", {}, "No lookalike bKash, Nagad or bank domains in today's feeds. "),
      "Global feeds rarely catch them. The phishing hunter (phase 2) will watch new certificates for exactly these names."));
  }
  const max = Math.max(1, ...brands.map(([, n]) => n), ...signals.map((x) => x[2]));
  const row = (label, count, reason) =>
    h("button", {
      type: "button", class: "brand-row", "aria-pressed": state.reason === reason ? "true" : "false",
      dataset: { reason },
      onclick: () => setFilter({ reason: state.reason === reason ? "" : reason, scope: "all" }),
    },
      h("span", { class: "brand-row-name", title: label }, label),
      h("span", { class: "brand-row-bar" }, h("span", { style: { width: `${(count / max) * 100}%` } })),
      h("span", { class: "brand-row-count" }, fmt(count)));

  for (const [brand, count] of brands) root.append(row(brand, count, `impersonates:${brand}`));
  if (signals.length) {
    root.append(h("p", { class: "sub", style: { margin: "14px 8px 6px" } }, "Other Bangladesh signals"));
    for (const [reason, label, count] of signals) root.append(row(label, count, reason));
  }
}

/* --------------------------------------------------------------- facets */

function renderFacets() {
  const root = clear($("#facets"));
  const groups = [
    ["Type", "type", Object.entries(stats.by_type).sort((a, b) => b[1] - a[1]), (k) => TYPE_LABEL[k] || k],
    ["Severity", "severity", ["high", "medium", "low"].map((k) => [k, stats.by_severity[k] || 0]).filter((x) => x[1]),
      (k) => h("span", { class: `sev sev-${k}` }, k)],
    ["Source", "source", Object.entries(stats.by_source).sort((a, b) => b[1] - a[1]), sourceName],
    ["Malware", "malware", Object.entries(stats.top_malware).slice(0, 8), (k) => k],
  ];
  for (const [title, key, entries, label] of groups) {
    if (!entries.length) continue;
    root.append(h("div", { class: "facet" },
      h("span", { class: "facet-name" }, title),
      entries.map(([value, count]) => h("button", {
        type: "button", class: "chip", dataset: { facet: key, value },
        "aria-pressed": state[key] === value ? "true" : "false",
        onclick: () => setFilter({ [key]: state[key] === value ? "" : value }),
      }, label(value), h("span", { class: "chip-count" }, compact(count))))));
  }
}

function syncControls() {
  for (const button of document.querySelectorAll("[data-scope]")) button.setAttribute("aria-pressed", state.scope === button.dataset.scope);
  for (const button of document.querySelectorAll("[data-sort]")) button.setAttribute("aria-pressed", state.sort === button.dataset.sort);
  for (const chip of document.querySelectorAll(".chip[data-facet]")) chip.setAttribute("aria-pressed", state[chip.dataset.facet] === chip.dataset.value);
  for (const row of document.querySelectorAll(".brand-row")) row.setAttribute("aria-pressed", state.reason === row.dataset.reason);
  if ($("#search").value !== state.q) $("#search").value = state.q;
  if (stats) { syncReadout(); renderPulse(); }
  renderActiveFilters();
}

function renderActiveFilters() {
  const root = clear($("#active-filters"));
  const label = {
    type: (v) => `Type: ${TYPE_LABEL[v] || v}`,
    severity: (v) => `Severity: ${v}`,
    source: (v) => `Source: ${sourceName(v)}`,
    malware: (v) => `Malware: ${v}`,
    reason: (v) => reasonInfo(v)[0],
    day: (v) => `First seen ${shortDate(v)}`,
    q: (v) => `“${v}”`,
  };
  for (const key of FILTER_KEYS) {
    if (!state[key]) continue;
    root.append(h("button", { type: "button", class: "pill", title: "Remove filter", onclick: () => setFilter({ [key]: "" }) },
      label[key](state[key]), h("span", { class: "pill-x", "aria-hidden": "true" }, "×")));
  }
  if (activeFilterCount() > 1) {
    root.append(h("button", { type: "button", class: "pill pill-clear", onclick: () => setFilter(Object.fromEntries(FILTER_KEYS.map((k) => [k, ""]))) }, "Clear all"));
  }
}

/* ---------------------------------------------------------------- table */

const PAGE = 25;

async function loadTable() {
  tableAbort?.abort();
  tableAbort = new AbortController();
  const table = $("#threats");
  table.classList.add("loading");
  try {
    const page = await api("/api/v1/indicators", {
      bd_only: state.scope === "bd", sort: state.sort, type: state.type, severity: state.severity,
      source: state.source, malware: state.malware, reason: state.reason, day: state.day, q: state.q,
      limit: PAGE, offset: state.offset,
    }, tableAbort.signal);
    rows = page.items;
    cursor = -1;
    renderRows(page);
  } catch (error) {
    if (error.name !== "AbortError") renderTableError(error);
  } finally {
    table.classList.remove("loading");
  }
}

function renderRows(page) {
  const body = clear($("#threats-body"));
  if (!page.items.length) {
    body.append(h("tr", { class: "table-empty" }, h("td", { colspan: 6 }, "Nothing matches these filters.")));
  }
  page.items.forEach((item, index) => {
    const context = item.malware || (item.threat_type || "").replaceAll("_", " ");
    body.append(h("tr", {
      tabindex: 0, dataset: { index },
      onclick: () => openDrawer(item),
      onkeydown: (event) => { if (event.key === "Enter") openDrawer(item); },
    },
      h("td", { class: "c-score" }, scoreCell(item)),
      h("td", { class: "c-type" }, h("span", { class: "type-tag" }, TYPE_LABEL[item.type] || item.type)),
      h("td", { class: "c-value" }, h("div", { class: "value", title: defang(item.type, item.value) }, defang(item.type, item.value))),
      h("td", { class: "c-ctx" }, h("div", { class: "ctx" },
        context ? h("span", { class: "ctx-text" }, context) : null,
        item.bd_relevant ? h("span", { class: "badge-bd", title: item.bd_reasons.map((r) => reasonInfo(r)[0]).join(" · ") }, "BD") : null)),
      h("td", { class: "c-src" }, h("div", { class: "srcs" },
        item.sightings.map((sg) => h("span", { class: "src", title: sourceName(sg.source) }, sourceAbbr(sg.source))))),
      h("td", { class: "c-time" }, h("span", { class: "time", title: new Date(item.last_seen).toLocaleString() }, ago(item.last_seen))),
    ));
  });

  const from = page.total ? page.offset + 1 : 0;
  const to = page.offset + page.items.length;
  $("#page-info").textContent = `${fmt(from)}–${fmt(to)} of ${fmt(page.total)}`;
  $("#prev").disabled = page.offset === 0;
  $("#next").disabled = to >= page.total;
}

function scoreCell(item) {
  return h("span", { class: "score", title: `Score ${item.score} · ${item.severity}` },
    h("span", { class: "score-bar", style: { width: "44px" } },
      h("span", { class: `tone-${item.severity}`, style: { width: `${item.score}%` } })),
    String(item.score));
}

function renderTableError(error) {
  clear($("#threats-body")).append(h("tr", { class: "table-empty" },
    h("td", { colspan: 6 }, `Could not load threats (${error.message}). Retrying shortly.`)));
  setTimeout(loadTable, 8000);
}

function moveCursor(delta) {
  const trs = [...document.querySelectorAll("#threats-body tr[data-index]")];
  if (!trs.length) return;
  cursor = Math.max(0, Math.min(trs.length - 1, cursor + delta));
  trs.forEach((tr, i) => tr.classList.toggle("cursor", i === cursor));
  trs[cursor].focus({ preventScroll: true });
  trs[cursor].scrollIntoView({ block: "nearest" });
}

/* --------------------------------------------------------------- stream */

async function loadStream() {
  try {
    const page = await api("/api/v1/indicators", { sort: "newest", limit: 14 });
    const root = clear($("#stream"));
    page.items.forEach((item, i) => {
      root.append(h("li", {
        class: "stream-item", tabindex: 0, style: { animationDelay: `${i * 25}ms` },
        onclick: () => openDrawer(item),
        onkeydown: (event) => { if (event.key === "Enter") openDrawer(item); },
      },
        h("span", { class: "stream-dot", style: { background: SEV_COLOR[item.severity] } }),
        h("div", { style: { minWidth: 0 } },
          h("div", { class: "stream-value", title: defang(item.type, item.value) }, defang(item.type, item.value)),
          h("div", { class: "stream-meta" },
            h("span", {}, TYPE_LABEL[item.type] || item.type),
            h("span", {}, item.malware || sourceName(item.sightings[0]?.source || "")),
            h("span", {}, ago(item.first_seen))))));
    });
    if (stats) $("#stream-sub").textContent = `Newest first · collection ran ${ago(stats.last_updated)}`;
  } catch {
    /* the status bar already reports API trouble */
  }
}

/* --------------------------------------------------------------- ring */

function ring(score, severity, large = false) {
  const r = 30;
  const circumference = 2 * Math.PI * r;
  const fill = s("circle", {
    class: "ring-fill", cx: 36, cy: 36, r, stroke: SEV_COLOR[severity] || "var(--muted)",
    "stroke-dasharray": circumference, "stroke-dashoffset": circumference,
  });
  requestAnimationFrame(() => requestAnimationFrame(() => {
    fill.setAttribute("stroke-dashoffset", circumference * (1 - score / 100));
  }));
  return h("div", { class: `ring${large ? " ring-lg" : ""}`, role: "img", "aria-label": `Score ${score} of 100, ${severity}` },
    s("svg", { viewBox: "0 0 72 72" }, s("circle", { class: "ring-track", cx: 36, cy: 36, r }), fill),
    h("span", { class: "ring-label" }, String(score)));
}

/* --------------------------------------------------------------- lookup */

async function runLookup(value) {
  value = value.trim();
  if (!value) return;
  const root = $("#verdict");
  root.hidden = false;
  root.dataset.tone = "";
  clear(root).append(h("p", { class: "muted" }, "Checking…"));
  try {
    const result = await api("/api/v1/lookup", { value });
    clear(root);
    if (!result.type || !result.normalized) {
      root.dataset.tone = "";
      root.append(checkIcon("?"), h("div", {},
        h("h3", {}, "That doesn't look like an indicator"),
        h("p", {}, "Try an IPv4 address, a domain, a URL, or an MD5, SHA-1 or SHA-256 hash.")));
      return;
    }
    if (!result.found) {
      root.dataset.tone = "clean";
      root.append(checkIcon("✓"), h("div", {},
        h("h3", {}, "Not in Sentinel-BD's data"),
        h("p", {}, "No feed has reported it. That isn't proof it's safe, only that it isn't known to be bad here."),
        h("div", { class: "value" }, `${TYPE_LABEL[result.type]} · ${defang(result.type, result.normalized)}`)));
      return;
    }
    const item = result.indicator;
    root.dataset.tone = item.severity === "high" ? "bad" : item.severity === "medium" ? "warn" : "";
    const headline = { high: "Known malicious", medium: "Likely malicious", low: "Reported, low confidence" }[item.severity];
    root.append(
      ring(item.score, item.severity),
      h("div", { style: { minWidth: 0 } },
        h("h3", {}, headline),
        h("p", {}, [
          `${TYPE_LABEL[item.type]} seen by ${item.sightings.map((sg) => sourceName(sg.source)).join(" and ")}`,
          item.malware ? ` · ${item.malware}` : "",
          ` · last seen ${ago(item.last_seen)}`,
        ].join("")),
        item.bd_relevant ? h("p", {}, h("span", { class: "badge-bd" }, "BD"), " ", item.bd_reasons.map((r) => reasonInfo(r)[0]).join(" · ")) : null,
        h("div", { class: "value" }, defang(item.type, item.value))),
      h("button", { type: "button", class: "btn", onclick: () => openDrawer(item, result.explanation) }, "Why this score?"),
    );
  } catch (error) {
    clear(root).append(h("p", { class: "muted" }, `Lookup failed (${error.message}).`));
  }
}

function checkIcon(symbol) {
  return h("div", { class: "ring", "aria-hidden": "true" },
    s("svg", { viewBox: "0 0 72 72" }, s("circle", { class: "ring-track", cx: 36, cy: 36, r: 30 })),
    h("span", { class: "ring-label" }, symbol));
}

async function renderExamples() {
  try {
    const [bd, top] = await Promise.all([
      api("/api/v1/indicators", { bd_only: true, limit: 2 }),
      api("/api/v1/indicators", { type: "ipv4", limit: 1 }),
    ]);
    const seen = new Set();
    const picks = [...bd.items, ...top.items].filter((i) => !seen.has(i.value) && seen.add(i.value)).slice(0, 3);
    const root = clear($("#lookup-examples"));
    if (!picks.length) return;
    root.append("Try:");
    for (const item of picks) {
      const text = defang(item.type, item.value);
      root.append(h("button", {
        type: "button", class: "example", title: text,
        onclick: () => { $("#lookup-input").value = text; runLookup(text); },
      }, text));
    }
    root.append(h("button", {
      type: "button", class: "example",
      onclick: () => { $("#lookup-input").value = "google.com"; runLookup("google.com"); },
    }, "google.com"));
  } catch { /* examples are optional */ }
}

/* --------------------------------------------------------------- drawer */

let lastFocus = null;

async function openDrawer(item, explanation = null) {
  lastFocus = document.activeElement;
  const drawer = $("#drawer");
  const body = clear($("#drawer-body"));
  const shown = defang(item.type, item.value);

  body.append(
    h("div", { class: "drawer-top" },
      h("h2", { id: "drawer-title" }, `${TYPE_LABEL[item.type] || item.type} indicator`),
      h("button", { type: "button", class: "btn btn-ghost drawer-close", "aria-label": "Close", onclick: closeDrawer }, "×")),
    h("div", { class: "drawer-value" }, shown),
    h("div", { class: "drawer-actions" },
      h("button", { type: "button", class: "btn", onclick: () => copy(shown, "Copied (defanged)") }, "Copy defanged"),
      h("button", { type: "button", class: "btn btn-ghost", onclick: () => copy(item.value, "Copied live value: handle with care") }, "Copy live value"),
      h("button", { type: "button", class: "btn btn-ghost", onclick: () => { closeDrawer(); setFilter({ q: item.value }); } }, "Filter to this")),
    h("div", { class: "drawer-hero" },
      ring(item.score, item.severity, true),
      h("div", {},
        h("span", { class: `sev sev-${item.severity}` }, `${item.severity} severity`),
        h("p", {}, item.malware ? `${item.malware} · ${(item.threat_type || "").replaceAll("_", " ")}` : (item.threat_type || "").replaceAll("_", " ")),
        h("p", { class: "muted" }, `First seen ${ago(item.first_seen)} · last seen ${ago(item.last_seen)}`))),
  );

  const mathSection = h("section", {}, h("h3", {}, "Why this score"), h("p", { class: "muted" }, "Working it out…"));
  body.append(mathSection);
  const connSection = h("section", {}, h("h3", {}, "Connections"), h("p", { class: "muted" }, "Looking for shared infrastructure…"));
  body.append(connSection);

  if (item.bd_reasons.length) {
    body.append(h("section", {}, h("h3", {}, "Why it concerns Bangladesh"),
      h("div", { class: "reasons" }, item.bd_reasons.map((reason) => {
        const [title, why] = reasonInfo(reason);
        return h("div", { class: "reason" }, h("span", { class: "badge-bd" }, "BD"), h("span", {}, title), h("span", { class: "reason-why" }, why));
      }))));
  }
  if (item.tags.length) {
    body.append(h("section", {}, h("h3", {}, "Tags"), h("div", { class: "tags" }, item.tags.map((t) => h("span", { class: "tag" }, t)))));
  }
  body.append(h("section", {}, h("h3", {}, "Sightings"),
    h("table", { class: "sightings" },
      h("thead", {}, h("tr", {}, h("th", {}, "Source"), h("th", {}, "First"), h("th", {}, "Last"), h("th", {}, "Reference"))),
      h("tbody", {}, item.sightings.map((sg) => h("tr", {},
        h("td", {}, sourceName(sg.source),
          sg.confidence != null ? h("div", { class: "muted" }, `confidence ${sg.confidence}%`) : null,
          sg.note ? h("div", { class: "sighting-note" }, sg.note) : null),
        h("td", {}, ago(sg.first_seen)),
        h("td", {}, ago(sg.last_seen)),
        h("td", {}, referenceLink(sg.reference))))))));

  $("#scrim").hidden = false;
  drawer.hidden = false;
  document.body.style.overflow = "hidden";
  $(".drawer-close", drawer).focus();

  loadConnections(item, connSection);

  try {
    explanation ||= await api("/api/v1/explain", { type: item.type, value: item.value });
    clear(mathSection).append(h("h3", {}, "Why this score"), scoreMath(explanation));
  } catch (error) {
    clear(mathSection).append(h("h3", {}, "Why this score"), h("p", { class: "muted" }, `Unavailable (${error.message}).`));
  }
}

function scoreMath(ex) {
  const pct = (x) => `${Math.round(x * 100)}%`;
  return h("div", { class: "math" },
    ex.sources.map((src) => h("div", {},
      h("div", { class: "math-row" },
        h("span", {}, sourceName(src.source)),
        h("span", { class: "bar-track" }, h("span", { style: { width: pct(src.weight) } })),
        h("span", { class: "v" }, pct(src.weight))),
      h("div", { class: "math-note" },
        `reliability ${pct(src.reliability)}${src.confidence != null ? ` × the feed's own confidence ${src.confidence}%` : ""}`))),
    h("div", { class: "math-step" },
      h("span", {}, ex.sources.length > 1 ? "Sources agree: 1 − (each source wrong)" : "Source confidence"),
      h("span", { class: "v" }, pct(ex.combined))),
    h("div", { class: "math-step" },
      h("span", {}, ex.half_life_days
        ? `Freshness: last seen ${ex.age_days < 1 ? `${Math.round(ex.age_days * 24)} hours` : `${ex.age_days.toFixed(1)} days`} ago, half-life ${ex.half_life_days} days`
        : "Freshness: file hashes never go stale"),
      h("span", { class: "v" }, `× ${ex.decay.toFixed(2)}`)),
    ex.bd_boost ? h("div", { class: "math-step" }, h("span", {}, "Concerns Bangladesh"), h("span", { class: "v" }, `+ ${ex.bd_boost}`)) : null,
    h("div", { class: "math-step math-total" }, h("span", {}, "Score (capped at 100)"), h("span", { class: "v" }, String(ex.score))),
  );
}

/* ---------------------------------------------------------- connections */

const TYPE_CLASS = (type) => (["md5", "sha1", "sha256"].includes(type) ? "hash" : type);
const EDGE_TEXT = {
  "hosted-on": ["Hosted on", "URLs on this host"],
  "resolves-to": ["Resolves to", "Domains pointing here"],
  "downloaded": ["Downloaded", "Downloaded by (honeypot)"],
  "delivers": ["Delivered", "Delivered by"],
};

async function openByValue(type, value) {
  try {
    const result = await api("/api/v1/lookup", { type, value });
    if (result.found) openDrawer(result.indicator, result.explanation);
  } catch { /* leave the current drawer */ }
}

async function loadConnections(item, section) {
  let graph;
  try {
    graph = await api("/api/v1/graph", { type: item.type, value: item.value, depth: 2 });
  } catch {
    clear(section).append(h("h3", {}, "Connections"), h("p", { class: "muted" }, "Unavailable right now."));
    return;
  }
  clear(section).append(h("h3", {}, "Connections"));
  const byId = new Map(graph.nodes.map((n) => [n.id, n]));
  const direct = graph.edges.filter((e) => e.src === graph.center || e.dst === graph.center);

  if (!direct.length) {
    section.append(h("p", { class: "muted" }, "No shared infrastructure with other known indicators yet."));
  } else {
    section.append(connGraph(graph, byId));
    section.append(h("div", { class: "conn-legend" },
      [["url", "URL"], ["domain", "Domain"], ["ipv4", "IP"], ["hash", "File hash"]].map(([c, label]) =>
        h("span", {}, h("i", { class: `t-${c}`, style: { background: `var(--t-${c})`, borderRadius: c === "hash" ? "2px" : "50%" } }), label))));
    const groups = new Map();
    for (const e of direct) {
      const outgoing = e.src === graph.center;
      const other = byId.get(outgoing ? e.dst : e.src);
      if (!other) continue;
      const title = (EDGE_TEXT[e.kind] || [e.kind, e.kind])[outgoing ? 0 : 1];
      if (!groups.has(title)) groups.set(title, []);
      groups.get(title).push(other);
    }
    for (const [title, nodes] of groups) {
      section.append(h("div", { class: "conn-group" }, h("h4", {}, `${title} (${nodes.length})`),
        nodes.slice(0, 12).map((n) => h("button", { type: "button", class: "conn-item", onclick: () => openByValue(n.type, n.value) },
          h("span", { class: `sev sev-${n.severity}`, title: `score ${n.score}` }, String(n.score)),
          h("code", { title: defang(n.type, n.value) }, defang(n.type, n.value)),
          h("span", { class: "muted" }, n.sources.map(sourceName).join(", ")))),
        nodes.length > 12 ? h("p", { class: "muted" }, `and ${nodes.length - 12} more`) : null));
    }
    if (graph.truncated) section.append(h("p", { class: "muted" }, "Showing the nearest 60 connections."));
  }
  if (graph.resolutions.length) {
    const known = new Set(graph.nodes.filter((n) => n.type === "ipv4").map((n) => n.value));
    section.append(h("div", { class: "conn-group" }, h("h4", {}, "DNS answers"),
      h("p", { class: "muted", style: { margin: 0 } },
        graph.resolutions.map((ip) => `${defang("ipv4", ip)}${known.has(ip) ? " (known malicious)" : ""}`).join(" · "))));
  }
}

/** Center node, its neighbours on a ring, second-hop nodes beyond them. */
function connGraph(graph, byId) {
  const W = 480, H = 300, cx = W / 2, cy = H / 2;
  const depth = new Map([[graph.center, 0]]);
  const parent = new Map();
  let frontier = [graph.center];
  for (let d = 1; d <= 2 && frontier.length; d++) {
    const next = [];
    for (const id of frontier) {
      for (const e of graph.edges) {
        const other = e.src === id ? e.dst : e.dst === id ? e.src : null;
        if (other !== null && !depth.has(other)) { depth.set(other, d); parent.set(other, id); next.push(other); }
      }
    }
    frontier = next;
  }
  const ring1 = [...depth].filter(([, d]) => d === 1).map(([id]) => id).slice(0, 14);
  const pos = new Map([[graph.center, [cx, cy, 0]]]);
  ring1.forEach((id, i) => {
    const a = (i / ring1.length) * Math.PI * 2 - Math.PI / 2;
    pos.set(id, [cx + Math.cos(a) * 95, cy + Math.sin(a) * 95, a]);
  });
  const ring2 = [...depth].filter(([id, d]) => d === 2 && pos.has(parent.get(id))).map(([id]) => id).slice(0, 24);
  const kids = new Map();
  for (const id of ring2) {
    const p = parent.get(id);
    kids.set(p, [...(kids.get(p) || []), id]);
  }
  for (const [p, list] of kids) {
    const base = pos.get(p)[2];
    list.forEach((id, i) => {
      const a = base + (i - (list.length - 1) / 2) * 0.28;
      pos.set(id, [cx + Math.cos(a) * 140, cy + Math.sin(a) * 128, a]);
    });
  }

  const svg = s("svg", { class: "conn-graph", viewBox: `0 0 ${W} ${H}`, role: "img", "aria-label": "Connection graph" });
  for (const e of graph.edges) {
    const a = pos.get(e.src), b = pos.get(e.dst);
    if (a && b) svg.append(s("line", { class: "edge", x1: a[0], y1: a[1], x2: b[0], y2: b[1] }));
  }
  for (const [id, [x, y]] of pos) {
    const n = byId.get(id);
    if (!n) continue;
    const isCenter = id === graph.center;
    const r = isCenter ? 13 : depth.get(id) === 1 ? 8 + n.score / 25 : 6;
    // Hashes are squares: shape, not only colour, tells them apart.
    const isHash = TYPE_CLASS(n.type) === "hash";
    const circle = s(isHash ? "rect" : "circle", {
      class: `node t-${TYPE_CLASS(n.type)}${isCenter ? " center" : ""}`,
      ...(isHash ? { x: x - r, y: y - r, width: 2 * r, height: 2 * r, rx: 2 } : { cx: x, cy: y, r }),
      tabindex: isCenter ? -1 : 0, role: isCenter ? "img" : "button",
      "aria-label": `${TYPE_LABEL[n.type] || n.type} ${defang(n.type, n.value)}, score ${n.score}`,
      onclick: () => !isCenter && openByValue(n.type, n.value),
      onkeydown: (ev) => { if (ev.key === "Enter" && !isCenter) openByValue(n.type, n.value); },
      onmouseenter: (ev) => showNodeTip(ev, n), onmouseleave: hideTip,
    });
    svg.append(circle);
    if (depth.get(id) <= 1 && !isCenter) {
      const text = defang(n.type, n.value);
      svg.append(s("text", { class: "label", x, y: y + r + 12, "text-anchor": "middle" },
        text.length > 22 ? `${text.slice(0, 21)}…` : text));
    }
  }
  return svg;
}

function showNodeTip(event, n) {
  const tip = $("#tooltip");
  clear(tip).append(h("strong", {}, String(n.score)), ` ${TYPE_LABEL[n.type] || n.type} · ${n.sources.map(sourceName).join(", ")}`);
  const rect = event.currentTarget.getBoundingClientRect();
  tip.style.left = `${rect.left + rect.width / 2}px`;
  tip.style.top = `${rect.top}px`;
  tip.hidden = false;
}

const LINK_TEXT = { "hosted-on": "hosted on", "resolves-to": "resolves to", downloaded: "downloaded", delivers: "delivered" };

async function loadLinks() {
  let items;
  try {
    items = await api("/api/v1/correlations", { limit: 12 });
  } catch {
    return;
  }
  const root = clear($("#links"));
  if (stats?.relations) {
    clear($("#links-counts")).append(...Object.entries(stats.relations).map(([k, n]) =>
      h("span", {}, h("b", {}, fmt(n)), ` ${LINK_TEXT[k] || k}`)));
  }
  if (!items.length) {
    root.append(h("li", { class: "empty" },
      "No cross-source links yet. They appear as the honeypot, the phishing hunter and the feeds start to overlap."));
    return;
  }
  const end = (n) => h("button", { type: "button", class: "link-end", onclick: () => openByValue(n.type, n.value) },
    h("span", { class: "link-value", title: defang(n.type, n.value) }, defang(n.type, n.value)),
    h("span", { class: "link-meta" }, `${TYPE_LABEL[n.type] || n.type} · ${n.score} · ${n.sources.map(sourceName).join(", ")}`));
  for (const c of items) {
    root.append(h("li", { class: "link-row" },
      end(c.src), h("span", { class: "link-kind" }, LINK_TEXT[c.kind] || c.kind), end(c.dst),
      c.own_sensor ? h("span", { class: "badge-own", title: "Found by Sentinel-BD's own sensors" }, "own sensor")
        : h("span", { class: "muted", style: { fontSize: "12px" } }, ago(c.last_seen))));
  }
}

/** Only well-known reference sites become links; anything else stays text. */
function referenceLink(ref) {
  if (!ref) return "–";
  try {
    const url = new URL(ref);
    const trusted = ["abuse.ch", "openphish.com", "crt.sh"].some((d) => url.hostname === d || url.hostname.endsWith(`.${d}`));
    if (url.protocol === "https:" && trusted) {
      return h("a", { href: url.href, target: "_blank", rel: "noopener noreferrer" }, url.hostname);
    }
    return h("span", { class: "muted", title: "Unverified reference, not linked" }, url.hostname);
  } catch {
    return "–";
  }
}

function closeDrawer() {
  const drawer = $("#drawer");
  if (drawer.hidden) return;
  drawer.hidden = true;
  $("#scrim").hidden = true;
  document.body.style.overflow = "";
  lastFocus?.focus?.();
}

/* -------------------------------------------------------------- builder */

const builder = { kind: "ip", min: 50, bd: false, vendor: "pfsense" };
const VENDORS = [
  ["pfsense", "pfSense / OPNsense"],
  ["fortigate", "FortiGate"],
  ["paloalto", "Palo Alto"],
  ["mikrotik", "MikroTik"],
  ["bind", "BIND (RPZ)"],
  ["pihole", "Pi-hole"],
  ["stix", "SIEM (TAXII)"],
];

function feedUrl(kind = builder.kind, extra = {}) {
  const special = { rpz: "/feeds/rpz.zone", stix: "/feeds/stix.json", mikrotik: "/feeds/mikrotik.rsc" };
  const path = special[kind] || `/feeds/${kind}.txt`;
  const url = new URL(path, location.origin);
  url.searchParams.set("min_score", builder.min);
  if (builder.bd) url.searchParams.set("bd_only", "true");
  for (const [key, value] of Object.entries(extra)) url.searchParams.set(key, value);
  return url.href;
}

function vendorSnippet() {
  const k = builder.kind;
  const name = `sentinel-bd-${k}`;
  const unsupported = (what) => `${VENDORS.find((v) => v[0] === builder.vendor)[1]} has no ${what} list type.\nPick another indicator type above.`;
  switch (builder.vendor) {
    case "pfsense":
      if (k === "ip") return `Firewall → pfBlockerNG → IP → IPv4 → Add\n  Name       ${name}\n  Source     ${feedUrl()}\n  Action     Deny Both\n  Frequency  Every 4 hours\nThen: Update → Run.`;
      if (k === "domain") return `Firewall → pfBlockerNG → DNSBL → DNSBL Groups → Add\n  Name       ${name}\n  Source     ${feedUrl()}\n  Action     Unbound\n  Frequency  Every 4 hours\nThen: Update → Run.`;
      return unsupported(k === "url" ? "full-URL" : "hash");
    case "fortigate": {
      const type = { ip: "address", domain: "domain", url: "category", hash: "malware" }[k];
      return `config system external-resource\n    edit "${name}"\n        set type ${type}\n        set resource "${feedUrl()}"\n        set refresh-rate 60\n    next\nend\n\n# Then use "${name}" in a firewall policy (address),\n# DNS filter (domain), web filter (category) or AV profile (malware).`;
    }
    case "paloalto": {
      if (k === "hash") return unsupported("hash");
      const type = { ip: "IP List", domain: "Domain List", url: "URL List" }[k];
      const url = k === "url" ? feedUrl("url", { strip_scheme: "true" }) : feedUrl();
      return `Objects → External Dynamic Lists → Add\n  Name    ${name}\n  Type    ${type}\n  Source  ${url}\n  Repeat  Hourly\n\nThen reference it in a Security policy (IP)\nor a URL Filtering / Anti-Spyware profile (Domain, URL).`;
    }
    case "mikrotik":
      if (k !== "ip") return unsupported(k === "domain" ? "domain" : k === "url" ? "URL" : "hash");
      return `/system script add name=${name} source={\n  /tool fetch url="${feedUrl("mikrotik")}" dst-path=${name}.rsc\n  /import file-name=${name}.rsc\n}\n/system scheduler add name=${name} interval=6h on-event=${name}\n/ip firewall raw add chain=prerouting src-address-list=sentinel-bd action=drop`;
    case "bind":
      if (k !== "domain") return "RPZ blocks domains. Choose Domains above.";
      return `# Refresh every 6 hours (cron)\ncurl -fsS "${feedUrl("rpz")}" -o /etc/bind/db.${name}.rpz && rndc reload ${name}.rpz\n\n// named.conf\noptions { response-policy { zone "${name}.rpz"; }; };\nzone "${name}.rpz" {\n    type primary;\n    file "/etc/bind/db.${name}.rpz";\n    allow-query { none; };\n};`;
    case "pihole":
      if (k !== "domain") return "Pi-hole blocks domains. Choose Domains above.";
      return `Pi-hole admin → Lists (Adlists) → Address:\n  ${feedUrl()}\nAdd, then update gravity:\n  pihole -g`;
    case "stix":
      return `TAXII 2.1 server (subscribe; your tool polls for new objects):\n  ${location.origin}/taxii2/\n  collections: "all indicators" and "aimed at Bangladesh"\n\nOr a one-off STIX 2.1 bundle:\n  ${feedUrl("stix")}\n\nOpenCTI: TAXII2 connector.  MISP: Sync Actions → Feeds (TAXII).\nSplunk / Elastic / Microsoft Sentinel: Threat Intelligence – TAXII data connector.`;
    default:
      return "";
  }
}

let previewTimer = null;
function updateBuilder() {
  for (const b of document.querySelectorAll("#builder-kind button")) b.setAttribute("aria-pressed", b.dataset.kind === builder.kind);
  for (const b of document.querySelectorAll("#vendor-tabs button")) b.setAttribute("aria-selected", b.dataset.vendor === builder.vendor);
  $("#builder-score-out").textContent = builder.min;
  let url = feedUrl();
  if (builder.vendor === "paloalto" && builder.kind === "url") url = feedUrl("url", { strip_scheme: "true" });
  if (builder.vendor === "mikrotik" && builder.kind === "ip") url = feedUrl("mikrotik");
  if (builder.vendor === "bind" && builder.kind === "domain") url = feedUrl("rpz");
  if (builder.vendor === "stix") url = feedUrl("stix");
  $("#builder-url").value = url;
  $("#vendor-snippet").textContent = vendorSnippet();
  $("#builder-count-label").textContent = { ip: "IPs", domain: "domains", url: "URLs", hash: "hashes" }[builder.kind] + " would be blocked";

  clearTimeout(previewTimer);
  previewTimer = setTimeout(async () => {
    try {
      const preview = await api("/api/v1/feed-preview", { kind: builder.kind, min_score: builder.min, bd_only: builder.bd });
      animateNumber($("#builder-count"), preview.count);
      const typeOf = { ip: "ipv4", domain: "domain", url: "url", hash: "sha256" }[builder.kind];
      clear($("#builder-sample")).append(...preview.sample.map((v) => h("li", { title: defang(typeOf, v) }, defang(typeOf, v))));
      if (!preview.sample.length) $("#builder-sample").append(h("li", { class: "muted" }, "Nothing at this threshold."));
    } catch { /* leave the last preview in place */ }
  }, 180);
}

function initBuilder() {
  const tabs = $("#vendor-tabs");
  for (const [key, label] of VENDORS) {
    tabs.append(h("button", { type: "button", role: "tab", dataset: { vendor: key }, onclick: () => { builder.vendor = key; updateBuilder(); } }, label));
  }
  for (const b of document.querySelectorAll("#builder-kind button")) {
    b.addEventListener("click", () => { builder.kind = b.dataset.kind; updateBuilder(); });
  }
  $("#builder-score").addEventListener("input", (e) => { builder.min = Number(e.target.value); updateBuilder(); });
  $("#builder-bd").addEventListener("change", (e) => { builder.bd = e.target.checked; updateBuilder(); });
  $("#builder-copy").addEventListener("click", () => copy($("#builder-url").value, "Feed URL copied"));
  updateBuilder();
}

/* ------------------------------------------------------------- honeypot */

async function loadHoneypot() {
  const root = $("#honeypot-body");
  let hp;
  try {
    hp = await api("/api/v1/honeypot", { days: 30 });
  } catch {
    return;
  }
  clear(root);
  const live = $("#hp-live");
  const fresh = hp.last_report && Date.now() - new Date(hp.last_report).getTime() < 30 * 60 * 1000;
  live.className = `hp-live ${fresh ? "on" : "off"}`;
  live.textContent = hp.last_report ? (fresh ? "● live" : `last report ${ago(hp.last_report)}`) : "";

  if (!hp.sessions) {
    root.append(h("p", { class: "empty hp-wide", style: { gridColumn: "1 / -1" } },
      h("strong", {}, "The sensor hasn't reported yet. "),
      "Once the honeypot server is running, attackers usually find it within minutes, and their passwords, commands and downloads will appear here."));
    return;
  }

  root.append(h("div", { class: "hp-figures" },
    figure(hp.sessions, "connections"),
    figure(hp.login_attempts, "passwords tried"),
    figure(hp.attackers, "attacking IPs")));

  const list = (title, items, render) => h("div", { class: "hp-list" }, h("h3", {}, title),
    items.length ? h("ol", {}, items.map((item) => h("li", {}, render(item), h("span", { class: "n" }, fmt(item.count)))))
      : h("p", { class: "muted" }, "None yet"));
  const code = (text) => h("code", { title: text }, text);

  root.append(
    list("Passwords tried", hp.passwords.slice(0, 8), (i) => code(i.value)),
    list("Usernames tried", hp.usernames.slice(0, 8), (i) => code(i.value)),
    list("Top attackers", hp.top_attackers.slice(0, 8), (i) => h("button", {
      type: "button", class: "code-btn", title: "Check this IP",
      onclick: () => { $("#lookup-input").value = i.value; runLookup(i.value); scrollTo({ top: 0, behavior: reduceMotion ? "auto" : "smooth" }); },
    }, code(defang("ipv4", i.value)))),
  );
  root.append(h("div", { class: "hp-list hp-wide" }, h("h3", {}, "Commands run after a fake login"),
    hp.commands.length ? h("ol", {}, hp.commands.map((i) => h("li", {}, code(defangText(i.value)), h("span", { class: "n" }, fmt(i.count)))))
      : h("p", { class: "muted" }, "No attacker has got past the login yet.")));
}

/** Defang every URL inside free text, e.g. an attacker's wget command. */
function defangText(text) {
  return text.replace(/\b(https?|ftp):\/\/([^\s/'"]+)/gi, (_, scheme, host) =>
    `${scheme.toLowerCase().replace(/^http/, "hxxp").replace(/^ftp/, "fxp")}://${host.replace(/\.(?=[^.]*$)/, "[.]")}`);
}

function figure(value, label) {
  const num = h("span", { class: "num" }, "0");
  animateNumber(num, value);
  return h("div", { class: "hp-figure" }, num, h("span", {}, label));
}

/* --------------------------------------------------------------- health */

function renderHealth() {
  const root = clear($("#health"));
  const runs = [...(stats.last_runs || [])].sort((a, b) => a.source.localeCompare(b.source));
  if (!runs.length) root.append(h("li", { class: "empty" }, "No collection has run yet."));
  for (const run of runs) {
    root.append(h("li", { class: "health-item" },
      h("span", { class: "health-name" }, sourceName(run.source)),
      h("span", { class: `health-state ${run.ok ? "ok" : "fail"}` }, run.ok ? "● Healthy" : "▲ Failed"),
      h("span", { class: "health-meta" },
        `${ago(run.finished_at || run.started_at)} · ${fmt(run.fetched)} fetched · ${fmt(run.created)} new · ${fmt(run.updated)} refreshed`),
      run.error ? h("span", { class: "health-error" }, run.error) : null));
  }

  const mix = clear($("#mix"));
  const entries = Object.entries(stats.by_type).sort((a, b) => b[1] - a[1]);
  const max = Math.max(1, ...entries.map((e) => e[1]));
  for (const [type, count] of entries) {
    mix.append(
      h("dt", {}, TYPE_LABEL[type] || type),
      h("dd", {}, h("div", { class: "bar", style: { width: `${(count / max) * 100}%` } })),
      h("dd", { class: "n" }, fmt(count)));
  }
}

/* ----------------------------------------------------------------- load */

async function loadStats() {
  try {
    stats = await api("/api/v1/stats");
    renderStatus();
    renderReadout();
    renderPulse();
    renderBrands();
    renderFacets();
    renderHealth();
    syncControls();
    loadLinks();
  } catch (error) {
    $("#status .status-dot").dataset.state = "error";
    $("#status .status-text").textContent = `API unreachable (${error.message})`;
    $("#status .status-detail").textContent = "";
  }
}

function bindEvents() {
  $("#lookup-form").addEventListener("submit", (event) => {
    event.preventDefault();
    runLookup($("#lookup-input").value);
  });
  for (const button of document.querySelectorAll("[data-scope]")) {
    button.addEventListener("click", () => setFilter({ scope: button.dataset.scope }));
  }
  for (const button of document.querySelectorAll("[data-sort]")) {
    button.addEventListener("click", () => setFilter({ sort: button.dataset.sort }));
  }
  let searchTimer = null;
  $("#search").addEventListener("input", (event) => {
    clearTimeout(searchTimer);
    searchTimer = setTimeout(() => setFilter({ q: event.target.value.trim() }), 300);
  });
  $("#prev").addEventListener("click", () => setFilter({ offset: Math.max(0, state.offset - PAGE) }));
  $("#next").addEventListener("click", () => setFilter({ offset: state.offset + PAGE }));
  $("#scrim").addEventListener("click", closeDrawer);
  addEventListener("hashchange", () => { readHash(); syncControls(); loadTable(); });

  let resizeTimer = null;
  new ResizeObserver(() => {
    clearTimeout(resizeTimer);
    resizeTimer = setTimeout(() => stats && renderPulse(), 80);
  }).observe($("#pulse"));

  document.addEventListener("keydown", (event) => {
    const typing = /^(INPUT|TEXTAREA|SELECT)$/.test(event.target.tagName);
    if (event.key === "Escape") {
      if (!$("#drawer").hidden) closeDrawer();
      else if (typing) event.target.blur();
      return;
    }
    if (typing || event.metaKey || event.ctrlKey || event.altKey) return;
    if (!$("#drawer").hidden) return;
    if (event.key === "/") { event.preventDefault(); $("#lookup-input").focus(); }
    else if (event.key === "j") { event.preventDefault(); moveCursor(1); }
    else if (event.key === "k") { event.preventDefault(); moveCursor(-1); }
  });
}

function init() {
  readHash();
  bindEvents();
  initBuilder();
  syncControls();
  loadStats();
  loadTable();
  loadStream();
  loadHoneypot();
  renderExamples();
  // Collection runs every 6 hours; refreshing every 5 minutes is plenty.
  setInterval(() => { loadStats(); loadStream(); loadHoneypot(); }, 5 * 60 * 1000);
}

init();
