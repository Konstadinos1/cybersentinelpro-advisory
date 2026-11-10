// Landing page: live corpus counts and one runnable attack.
// Case text is attacker-shaped by design, so it is only ever written with
// textContent. innerHTML is never used.
"use strict";

const FEATURED_CASE = "RT-MCP-001";
const RATE_LIMITED = 429;

const $ = (id) => document.getElementById(id);

function element(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function showStats(cases) {
  const attacks = cases.filter((c) => c.expect === "blocked").length;
  $("stat-cases").textContent = String(cases.length);
  $("stat-attacks").textContent = String(attacks);
  $("stat-benign").textContent = String(cases.length - attacks);
  $("corpus-stats").hidden = false;
}

function showPayload(cases) {
  const featured = cases.find((c) => c.id === FEATURED_CASE);
  if (!featured) {
    disableTry("The featured case is not in this build. The full lab still works.");
    return;
  }
  $("try-payload").textContent = JSON.stringify(featured.input.advertised, null, 2);
}

function disableTry(message) {
  $("try-payload").textContent = "Unavailable.";
  $("try-run").disabled = true;
  $("try-status").textContent = message;
}

// "RULE-ID message; RULE-ID message" becomes one list item per finding.
function reasonItems(detail) {
  return detail.split("; ").filter(Boolean).map((part) => {
    const space = part.indexOf(" ");
    const item = element("li");
    if (space > 0 && /^AEGIS-/.test(part)) {
      item.append(element("code", "", part.slice(0, space)), ` ${part.slice(space + 1)}`);
    } else {
      item.textContent = part;
    }
    return item;
  });
}

function showResult(result, elapsedMs) {
  const blocked = result.outcome.blocked;
  const badge = $("try-badge");
  badge.textContent = blocked ? "blocked" : "NOT BLOCKED";
  badge.className = `badge ${result.passed ? "ok" : "bad"}`;
  $("try-reasons").replaceChildren(...reasonItems(result.outcome.detail));
  $("try-result").hidden = false;
  $("try-status").textContent = `Ran on the server just now in ${elapsedMs} ms.`;
}

function failureMessage(status) {
  if (status === RATE_LIMITED) return "Too many runs from this address. Wait a minute and try again.";
  return "The server could not run the case. Try again, or open the full lab.";
}

async function runFeatured() {
  const button = $("try-run");
  button.disabled = true;
  button.textContent = "Running...";
  $("try-status").textContent = "";
  const started = performance.now();
  try {
    const response = await fetch(`/lab/api/cases/${FEATURED_CASE}/run`, { method: "POST" });
    if (!response.ok) {
      $("try-status").textContent = failureMessage(response.status);
    } else {
      showResult(await response.json(), Math.round(performance.now() - started));
    }
  } catch (error) {
    $("try-status").textContent = failureMessage(0);
  }
  button.disabled = false;
  button.textContent = "Run it again";
}

async function start() {
  try {
    const response = await fetch("/lab/api/cases");
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const cases = await response.json();
    showStats(cases);
    showPayload(cases);
  } catch (error) {
    disableTry("Could not reach the lab API. Reload the page to try again.");
    return;
  }
  $("try-run").addEventListener("click", runFeatured);
}

start();
