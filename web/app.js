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
let pendingUploads = 0;
let reviewing = false;

function syncRunState() {
  run.disabled = reviewing || pendingUploads > 0;
}

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
  find("#evidence-count").textContent = Object.keys(artifacts).length + " / " + tiles.length;
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
  delete artifacts[key];
  invalidate();
  updateInputs();
  const tile = tiles.find((item) => item.dataset.artifact === key);
  tile?.setAttribute("aria-busy", "true");
  if (tile) tile.querySelector("small").textContent = "Reading " + file.name + "…";
  pendingUploads += 1;
  syncRunState();
  if (file.size > 750000) {
    showError("Each artifact must be 750 KB or smaller.");
    tile?.removeAttribute("aria-busy");
    updateInputs();
    pendingUploads -= 1;
    syncRunState();
    return;
  }
  try {
    artifacts[key] = { name: file.name, text: (await file.text()).replace(/^\uFEFF/, "") };
    showError();
    updateInputs();
  } catch {
    showError("This file could not be read.");
  } finally {
    tile?.removeAttribute("aria-busy");
    updateInputs();
    pendingUploads -= 1;
    syncRunState();
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
    for (const key of Object.keys(artifacts)) delete artifacts[key];
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
  reviewing = true;
  syncRunState();
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
    reviewing = false;
    syncRunState();
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
  const privacy = data.privacy_radar || { level: "clear", score: 0, summary: { routes: 0 } };
  const verdict = element("div", undefined, "verdict " + data.decision.toLowerCase());
  const lead = element("div");
  lead.append(element("div", "DEPLOYMENT RECOMMENDATION", "mono"), element("div", data.decision, "decision"), element("p", data.advisory));
  const score = element("div", undefined, "score");
  score.append(element("strong", data.score), document.createTextNode(" / 100"), element("small", "RISK SCORE"));
  verdict.append(lead, score);

  const summary = element("div", undefined, "summary");
  summary.append(metric(data.files.length, "Changed files"),
    metric(data.coverage.percent === null ? "—" : data.coverage.percent + "%", "Coverage of added source lines"),
    metric(data.incidents_supplied ? data.incidents.length : "—", "Related incidents"),
    metric(privacy.score + " / 100", "Privacy blast radius"));

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
    ["Privacy radar (" + privacy.summary.routes + ")", () => renderPrivacyRadar(data, body)],
    ["Findings (" + data.findings.length + ")", () => renderFindings(data, body)],
    ["Dependencies (" + data.dependency_changes.length + ")", () => renderDependencies(data, body)],
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
  body.append(element("p", (coverage.supplied ? "Coverage matched " + (coverage.covered + coverage.missed) + " of " + (coverage.covered + coverage.missed + coverage.unknown) + " added source lines" : "No coverage artifact supplied") + " · " + coverage.covered + " covered, " + coverage.missed + " missed, " + coverage.unknown + " unknown."));
  for (const file of data.files) {
    body.append(evidenceRow(file.path, "+" + file.added + " / −" + file.removed + " lines · " + file.covered + " covered · " + file.missed + " missed · " + file.unknown + " unknown", undefined, file.tags.join(" / ")));
  }
  body.append(element("h3", "Related incidents"));
  if (!data.incidents.length) body.append(element("p", data.incidents_supplied ? "No matching incident modules." : "No incident history supplied."));
  for (const incident of data.incidents) body.append(evidenceRow(incident.id, incident.module, undefined, incident.severity));
}

function renderPrivacyRadar(data, body) {
  const radar = data.privacy_radar;
  body.append(element("h3", "Privacy Blast Radius"));
  if (!radar) {
    body.append(element("p", "This report does not include privacy path analysis."));
    return;
  }
  const overview = element("section", undefined, "privacy-overview " + radar.level);
  const heading = element("div", undefined, "privacy-heading");
  heading.append(element("span", radar.level.toUpperCase(), "privacy-level"),
    element("strong", radar.score + " / 100"));
  const copy = radar.release_gate
    ? "Release gate active: static evidence links personal data to a changed dependency chain."
    : radar.sources.length
      ? "Static evidence only. Review the observed data sinks before promotion."
      : "No sensitive-data signals were found in the added code.";
  overview.append(heading, element("p", copy));
  const stats = element("div", undefined, "privacy-stats");
  stats.append(metric(radar.summary.signals, "Data signals"),
    metric(radar.summary.flows, "Observed sinks"),
    metric(radar.summary.linked_transitive, "Linked transitive packages"));
  overview.append(stats);
  body.append(overview);

  if (!radar.sources.length) return;
  body.append(element("h4", "Detected data categories"));
  const categories = element("div", undefined, "privacy-chips");
  for (const category of radar.categories) categories.append(element("span", category, "privacy-chip data"));
  body.append(categories);

  if (radar.routes.length) {
    body.append(element("h4", "Candidate dependency paths"));
    body.append(element("p", "The links below are inferred from imports and calls added in the diff. They show where a release owner should verify the real runtime payload."));
    const routes = element("div", undefined, "privacy-routes");
    for (const route of radar.routes) {
      const card = element("article", undefined, "privacy-route");
      const path = element("div", undefined, "privacy-path");
      for (const category of route.categories) path.append(element("span", category, "privacy-node data"));
      path.append(element("span", "→", "privacy-arrow"), element("span", route.sink, "privacy-node sink"),
        element("span", "→", "privacy-arrow"),
        element("span", route.dependency.name + "@" + route.dependency.version, "privacy-node dependency"));
      for (const item of route.transitive) {
        path.append(element("span", "→", "privacy-arrow"),
          element("span", item.name + "@" + item.version, "privacy-node transitive"));
      }
      const packageSignal = route.dependency.capability === "Unclassified"
        ? "No package-name capability signal"
        : route.dependency.capability + " package-name signal";
      card.append(path,
        element("small", route.file + ":" + route.line + " · " + route.evidence + " · " + route.confidence),
        element("p", packageSignal + ". " + (route.transitive.length
          ? route.transitive.length + " changed transitive package" + (route.transitive.length === 1 ? "" : "s") + " sits behind this import."
          : "No changed transitive package was found behind this import.")));
      routes.append(card);
    }
    body.append(routes);
  } else if (radar.flows.length) {
    body.append(element("h4", "Observed data sinks"));
    for (const flow of radar.flows) {
      body.append(evidenceRow(flow.sink, flow.categories.join(" · ") + " · " + flow.file + ":" + flow.line,
        flow.evidence + ". No changed imported package could be linked to this sink.", flow.sink_kind));
    }
  } else {
    body.append(element("p", "Sensitive fields were found, but this diff does not show them reaching a configured sink."));
  }

  body.append(element("h4", "Release-owner checks"));
  const checks = element("ol", undefined, "privacy-checks");
  checks.append(element("li", "Confirm that only the minimum necessary fields leave the service."),
    element("li", "Verify consent, retention and vendor approval for the destination."),
    element("li", "Approve the direct package and every changed transitive package on the displayed path."));
  body.append(checks);
}

function renderDependencies(data, body) {
  body.append(element("h3", "npm dependency changes"));
  if (!data.dependency_comparison_supplied) {
    body.append(element("p", "Upload both baseline and release package-lock.json files (lockfile versions 2 or 3) to compare the reachable dependency graph."));
    return;
  }
  body.append(element("p", "Local lockfile comparison only. New or updated transitive packages need review; this does not check a vulnerability database."));
  if (!data.dependency_changes.length) {
    body.append(element("p", "No reachable package additions or updates found."));
    return;
  }
  for (const item of data.dependency_changes) {
    const version = item.from_version ? item.from_version + " → " + item.version : item.version;
    const controls = [item.integrity ? "integrity hash present" : "no integrity hash"];
    if (item.install_script) controls.push("install script");
    if (item.link) controls.push("local link");
    const meta = item.change + " · " + item.kind + " · " + version + " · " + controls.join(" · ") + (item.resolved ? " · " + item.resolved : "");
    body.append(evidenceRow(item.name, meta, "Dependency path: " + item.chain.join(" → "), item.kind));
  }
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
