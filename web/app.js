"use strict";

const find = (selector) => document.querySelector(selector);
const artifacts = {};
const tiles = [...document.querySelectorAll(".upload")];
const defaults = Object.fromEntries(tiles.map((tile) => [tile.dataset.artifact, tile.querySelector("small").textContent]));
const result = find("#result");
const error = find("#form-error");
const run = find("#run");
const clear = find("#clear");
const demo = find("#load-demo");
const exportButton = find("#export");
const initial = [...result.children].map((child) => child.cloneNode(true));
let report;
let generation = 0;

function element(tag, text, className) {
  const node = document.createElement(tag);
  if (text !== undefined) node.textContent = text;
  if (className) node.className = className;
  return node;
}

function showError(message) {
  error.hidden = !message;
  error.textContent = message || "";
}

function updateInputs() {
  for (const tile of tiles) {
    const key = tile.dataset.artifact;
    tile.classList.toggle("ready", Boolean(artifacts[key]));
    tile.querySelector("small").textContent = artifacts[key]?.name || defaults[key];
    tile.querySelector(".add").textContent = artifacts[key] ? "✓" : "+";
  }
  find("#evidence-count").textContent = Object.keys(artifacts).length + " / 3";
  clear.hidden = !Object.keys(artifacts).length;
}

function invalidate() {
  generation += 1;
  report = undefined;
  exportButton.hidden = true;
  result.replaceChildren(...initial.map((child) => child.cloneNode(true)));
}

async function saveFile(key, file) {
  if (!file) return;
  if (file.size > 750000) {
    showError("Each artifact must be 750 KB or smaller.");
    return;
  }
  try {
    artifacts[key] = { name: file.name, text: (await file.text()).replace(/^\uFEFF/, "") };
    showError();
    invalidate();
    updateInputs();
  } catch {
    showError("This file could not be read.");
  }
}

for (const tile of tiles) {
  const input = tile.querySelector("input");
  input.addEventListener("change", () => {
    saveFile(tile.dataset.artifact, input.files[0]);
    input.value = "";
  });
  for (const type of ["dragover", "dragleave", "drop"]) {
    tile.addEventListener(type, (event) => {
      event.preventDefault();
      tile.classList.toggle("drag", type === "dragover");
      if (type === "drop") saveFile(tile.dataset.artifact, event.dataTransfer.files[0]);
    });
  }
}

clear.addEventListener("click", () => {
  for (const key of Object.keys(artifacts)) delete artifacts[key];
  invalidate();
  showError();
  updateInputs();
});

demo.addEventListener("click", async () => {
  demo.disabled = true;
  try {
    const response = await fetch("/demo.json");
    if (!response.ok) throw new Error("The demo files could not be loaded.");
    Object.assign(artifacts, await response.json());
    invalidate();
    showError();
    updateInputs();
    run.focus();
  } catch (err) {
    showError(err.message);
  } finally {
    demo.disabled = false;
  }
});

find("#review-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!artifacts.patch?.text.trim()) {
    showError("Upload a code diff or load the checkout demo, then run the assessment.");
    return;
  }
  showError();
  invalidate();
  const revision = generation;
  run.disabled = true;
  run.firstChild.textContent = "Reviewing evidence ";
  try {
    const response = await fetch("/api/assess", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(Object.fromEntries(Object.entries(artifacts).map(([key, input]) => [key, input.text]))),
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || "The assessment failed.");
    if (revision === generation) {
      report = data;
      renderReport(data);
    }
  } catch (err) {
    if (revision === generation) showError(err.message || "Could not reach the assessment server.");
  } finally {
    run.disabled = false;
    run.firstChild.textContent = "Run assessment ";
  }
});

function metric(value, label) {
  const node = element("div", undefined, "metric");
  node.append(element("strong", value), element("small", label));
  return node;
}

function evidenceRow(title, meta, action, tag) {
  const row = element("div", undefined, "row");
  if (tag) row.append(element("div", tag, "severity " + tag.toLowerCase()));
  row.append(element("strong", title), element("small", meta));
  if (action) row.append(element("p", action));
  return row;
}

function renderReport(data) {
  const verdict = element("div", undefined, "verdict " + data.decision.toLowerCase());
  const lead = element("div");
  lead.append(element("div", "DEPLOYMENT RECOMMENDATION", "mono"), element("div", data.decision, "decision"), element("p", data.advisory));
  const score = element("div", undefined, "score");
  score.append(element("strong", data.score), document.createTextNode(" / 100"), element("small", "RISK SCORE"));
  verdict.append(lead, score);

  const summary = element("div", undefined, "summary");
  summary.append(metric(data.files.length, "Changed files"),
    metric(data.coverage.percent === null ? "—" : data.coverage.percent + "%", "Coverage of observed added lines"),
    metric(data.incidents_supplied ? data.incidents.length : "—", "Related incidents"));

  const tabs = element("div", undefined, "tabs");
  tabs.setAttribute("role", "tablist");
  tabs.setAttribute("aria-label", "Advisory evidence");
  const body = element("div", undefined, "tab-body");
  body.id = "evidence-panel";
  body.setAttribute("role", "tabpanel");
  body.tabIndex = 0;
  const views = [
    ["Risk summary", () => renderOverview(data, body)],
    ["Changed files", () => renderFiles(data, body)],
    ["Findings (" + data.findings.length + ")", () => renderFindings(data, body)],
    ["Rollback", () => renderRollback(data, body)],
  ];
  const buttons = views.map(([label], index) => {
    const button = element("button", label);
    button.type = "button";
    button.id = "review-tab-" + index;
    button.setAttribute("role", "tab");
    button.setAttribute("aria-controls", body.id);
    button.addEventListener("click", () => activate(index));
    return button;
  });
  function activate(index) {
    buttons.forEach((button, position) => {
      button.setAttribute("aria-selected", String(position === index));
      button.tabIndex = position === index ? 0 : -1;
    });
    body.setAttribute("aria-labelledby", buttons[index].id);
    body.replaceChildren();
    views[index][1]();
  }
  tabs.addEventListener("keydown", (event) => {
    const index = buttons.indexOf(event.target);
    const next = { ArrowLeft: (index + buttons.length - 1) % buttons.length, ArrowRight: (index + 1) % buttons.length, Home: 0, End: buttons.length - 1 }[event.key];
    if (index < 0 || next === undefined) return;
    event.preventDefault();
    activate(next);
    buttons[next].focus();
  });
  tabs.append(...buttons);
  activate(0);
  result.replaceChildren(verdict, summary, tabs, body);
  exportButton.hidden = false;
}

function renderOverview(data, body) {
  body.append(element("h3", "What drives the score"));
  const dimensions = element("div", undefined, "dimensions");
  for (const row of data.dimensions) {
    const item = element("div", undefined, "dimension");
    const meter = element("meter");
    meter.min = 0;
    meter.max = row.max;
    meter.value = row.points;
    meter.setAttribute("aria-label", row.label);
    item.append(element("span", row.label), meter, element("output", row.points + " / " + row.max));
    dimensions.append(item);
  }
  body.append(dimensions);
  if (data.blockers.length) {
    const blockers = element("div", undefined, "blockers");
    blockers.append(element("strong", "Release gates"));
    for (const gate of data.blockers) blockers.append(element("p", gate));
    body.append(blockers);
  }
}

function renderFiles(data, body) {
  const coverage = data.coverage;
  body.append(element("h3", "Changed files and coverage"));
  body.append(element("p", "Added source lines · " + coverage.covered + " covered, " + coverage.missed + " missed, " + coverage.unknown + " without line evidence."));
  for (const file of data.files) {
    body.append(evidenceRow(file.path, "+" + file.added + " / −" + file.removed + " lines · " + file.covered + " covered · " + file.missed + " missed · " + file.unknown + " unknown", undefined, file.tags.join(" / ")));
  }
  body.append(element("h3", "Related incidents"));
  if (!data.incidents.length) body.append(element("p", data.incidents_supplied ? "No matching incident modules." : "No incident history supplied."));
  for (const incident of data.incidents) body.append(evidenceRow(incident.id, incident.module, undefined, incident.severity));
}

function renderFindings(data, body) {
  body.append(element("h3", "Findings and remediation"));
  if (!data.findings.length) body.append(element("p", "No findings matched the configured change, privacy and security rules."));
  for (const finding of data.findings) {
    body.append(evidenceRow(finding.title, finding.area + " · " + finding.file + (finding.line ? ":" + finding.line : ""), finding.action, finding.severity));
  }
}

function renderRollback(data, body) {
  body.append(element("h3", "Rollback checklist"));
  const list = element("ol", undefined, "rollback");
  for (const action of data.checklist) list.append(element("li", action));
  body.append(list);
}

exportButton.addEventListener("click", () => {
  if (!report) return;
  const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
  const download = element("a");
  download.href = URL.createObjectURL(blob);
  download.download = "releaseguard-advisory.json";
  download.click();
  setTimeout(() => URL.revokeObjectURL(download.href), 1000);
});
