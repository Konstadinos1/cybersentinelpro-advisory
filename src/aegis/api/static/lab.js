// Attack lab front end.
// Payloads are attacker-controlled text by design, so everything is written
// with textContent / createElement. innerHTML is never used.
"use strict";

const state = { cases: [], results: new Map(), filter: "all", running: false };

const $ = (id) => document.getElementById(id);

function element(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

// Invisible characters are the whole point of some cases; make them visible.
function revealHidden(text) {
  return text.replace(/[\u200b-\u200f\u202a-\u202e\u2060-\u2064\ufeff]|[\u{e0000}-\u{e007f}]/gu,
    (ch) => `\u27e8U+${ch.codePointAt(0).toString(16).toUpperCase()}\u27e9`);
}

function showBanner(message) {
  const banner = $("banner");
  banner.textContent = message;
  banner.hidden = !message;
}

function badgeFor(result) {
  if (!result) return { text: "not run", cls: "" };
  if (result.error) return { text: "error", cls: "bad" };
  if (!result.passed) return { text: "GUARD FAILED", cls: "bad" };
  return { text: result.outcome.blocked ? "blocked" : "allowed", cls: "ok" };
}

function percent(passed, total) {
  return total ? `${Math.round((passed / total) * 100)}%` : "-";
}

function updateStats() {
  const done = [...state.results.values()].filter((r) => !r.error);
  const by = (expect) => done.filter((r) => r.case.expect === expect);
  const attacks = by("blocked");
  const benign = by("allowed");
  $("stat-run").textContent = `${state.results.size} / ${state.cases.length}`;
  $("stat-attacks").textContent = percent(attacks.filter((r) => r.passed).length, attacks.length);
  $("stat-benign").textContent = percent(benign.filter((r) => r.passed).length, benign.length);
  const failed = [...state.results.values()].filter((r) => r.error || !r.passed).length;
  $("stat-failed").textContent = String(failed);
}

function section(title, child) {
  const fragment = document.createDocumentFragment();
  fragment.append(element("h2", "", title), child);
  return fragment;
}

function outcomeNode(result) {
  if (!result) return element("p", "empty", "Not run yet.");
  if (result.error) return element("p", "", `Request failed: ${result.error}`);
  const rules = result.outcome.rule_ids.length ? `\nrules: ${result.outcome.rule_ids.join(", ")}` : "";
  return element("pre", "", revealHidden(result.outcome.detail + rules));
}

function caseNode(item) {
  const result = state.results.get(item.id);
  const details = element("details", "case");
  details.dataset.id = item.id;
  const summary = element("summary");
  const badge = badgeFor(result);
  const run = element("button", "", "Run");
  run.type = "button";
  run.disabled = state.running;
  run.setAttribute("aria-label", `Run ${item.id}`);
  run.addEventListener("click", (event) => { event.preventDefault(); runCases([item]); });
  summary.append(
    element("span", "case-id", item.id),
    element("span", "case-title", item.title),
    element("span", `badge ${badge.cls}`, badge.text),
    run,
  );
  const body = element("div", "case-body");
  const expectation = item.expect === "blocked"
    ? "Attack: the guard must block this." : "Benign control: the guard must allow this.";
  body.append(section("Expectation", element("p", "", `${expectation} ${item.description}`)));
  body.append(section("Payload", element("pre", "", revealHidden(JSON.stringify(item.input, null, 2)))));
  body.append(section("Outcome", outcomeNode(result)));
  if (item.references.length) {
    const refs = element("div", "refs");
    item.references.forEach((ref) => refs.append(element("span", "ref", ref)));
    body.append(section("Maps to", refs));
  }
  details.append(summary, body);
  return details;
}

// Re-rendering replaces the nodes, so keyboard focus is carried over by hand.
function focusedControl() {
  const active = document.activeElement;
  const owner = active && active.closest ? active.closest("details.case") : null;
  return owner ? { id: owner.dataset.id, tag: active.tagName } : null;
}

function restoreFocus(container, focused) {
  if (!focused) return;
  const owner = [...container.querySelectorAll("details.case")].find((d) => d.dataset.id === focused.id);
  const target = owner && owner.querySelector(focused.tag === "BUTTON" ? "summary button" : "summary");
  if (target) target.focus({ preventScroll: true });
}

function render() {
  const open = new Set([...document.querySelectorAll("details.case[open]")].map((d) => d.dataset.id));
  const focused = focusedControl();
  const visible = state.cases.filter((c) => state.filter === "all" || c.module === state.filter);
  const container = $("cases");
  container.replaceChildren(...visible.map(caseNode));
  if (!visible.length) container.append(element("p", "empty", "No cases in this module."));
  container.querySelectorAll("details.case").forEach((d) => { d.open = open.has(d.dataset.id); });
  restoreFocus(container, focused);
  $("run-all").disabled = state.running;
  $("run-all").textContent = state.running ? "Running..." : "Run all cases";
  updateStats();
}

function renderFilters() {
  const modules = ["all", ...new Set(state.cases.map((c) => c.module))];
  const buttons = modules.map((name) => {
    const button = element("button", "", name === "all" ? "All modules" : name);
    button.type = "button";
    button.setAttribute("aria-pressed", String(state.filter === name));
    button.addEventListener("click", () => { state.filter = name; renderFilters(); render(); });
    return button;
  });
  $("filters").replaceChildren(...buttons);
}

async function runOne(item) {
  try {
    const response = await fetch(`/lab/api/cases/${encodeURIComponent(item.id)}/run`, { method: "POST" });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    state.results.set(item.id, await response.json());
  } catch (error) {
    state.results.set(item.id, { case: item, error: error.message, passed: false });
    showBanner("Some cases could not be run. Is the server still up?");
  }
}

async function runCases(items) {
  if (state.running) return;
  // Buttons are disabled while running and so lose focus; remember where it was.
  const focused = focusedControl();
  state.running = true;
  showBanner("");
  render();
  for (const item of items) {
    await runOne(item);
    render();
  }
  state.running = false;
  render();
  restoreFocus($("cases"), focused);
}

async function start() {
  try {
    const response = await fetch("/lab/api/cases");
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    state.cases = await response.json();
  } catch (error) {
    $("loading").textContent = "";
    showBanner(`Could not load cases: ${error.message}`);
    return;
  }
  renderFilters();
  render();
  $("run-all").addEventListener("click", () => {
    runCases(state.cases.filter((c) => state.filter === "all" || c.module === state.filter));
  });
}

start();
