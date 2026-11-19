"use strict";

const find = (selector) => document.querySelector(selector);
let artifacts = {};
const tiles = [...document.querySelectorAll(".upload")];
const defaults = Object.fromEntries(tiles.map((tile) => [tile.dataset.artifact, tile.querySelector("small").textContent]));
const result = find("#result");
const error = find("#form-error");
const run = find("#run");
const clear = find("#clear");
const form = find("#review-form");
const fileStatus = find("#file-status");
const exportButton = find("#export");
const reportState = find("#report-state");
const initial = [...result.children].map((child) => child.cloneNode(true));
let report;
let generation = 0;
let activeScenario = null;
const scenarios = {
  checkout: { supply: "/demo.json", runLabel: "Run checkout demo" },
  moderate: { supply: "/demo-moderate.json", runLabel: "Run moderate-risk demo" },
  payments: { supply: "/demo-payments.json", runLabel: "Run payment retry demo" },
  go: { supply: "/demo-go.json", runLabel: "Run low-risk demo" },
};

const stages = [
  ["prepare", "Prepare release evidence", "Read the patch, coverage, and incident inputs."],
  ["dependencies", "Review dependency vulnerabilities", "Read npm audit results and compare dependency chains."],
  ["network", "Check network exposure", "Review supplied flow metadata for cleartext or unverified transport."],
  ["privacy", "Flag sensitive-data risks", "Check code patterns and potential personal-data routes."],
  ["decision", "Generate release advisory", "Combine findings, coverage, incidents, and release gates."],
];

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

function setReportState(label, tone = "idle") {
  reportState.dataset.tone = tone;
  reportState.replaceChildren(element("i"), document.createTextNode(" " + label));
}

function updateInputs() {
  for (const tile of tiles) {
    const key = tile.dataset.artifact;
    tile.classList.toggle("ready", Boolean(artifacts[key]));
    tile.querySelector("small").textContent = artifacts[key]?.name || defaults[key];
    tile.querySelector(".add").textContent = artifacts[key] ? "✓" : "+";
  }
  const count = Object.keys(artifacts).length;
  find("#evidence-count").textContent = count + " / " + tiles.length;
  fileStatus.textContent = count ? count + " evidence " + (count === 1 ? "file" : "files") + " loaded." : "";
  clear.hidden = count === 0;
  for (const button of document.querySelectorAll(".scenario-card[data-scenario]")) {
    const selected = button.dataset.scenario === activeScenario;
    button.classList.toggle("selected", selected);
    button.setAttribute("aria-pressed", String(selected));
  }
  if (!report && !run.disabled) {
    setReportState(count ? count + " signals ready" : "Waiting for evidence", count ? "ready" : "idle");
  }
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
    activeScenario = null;
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
  artifacts = {};
  activeScenario = null;
  invalidate();
  showError();
  updateInputs();
});

function setControlsBusy(busy) {
  run.disabled = busy;
  for (const button of document.querySelectorAll("[data-scenario]")) button.disabled = busy;
  form.setAttribute("aria-busy", String(busy));
}

async function loadScenario(key) {
  if (run.disabled) return false;
  const revision = generation;
  setControlsBusy(true);
  try {
    const response = await fetch(scenarios[key].supply);
    if (!response.ok) throw new Error("The demo files could not be loaded. Try again.");
    const next = await response.json();
    if (revision !== generation) return false;
    artifacts = next;
    activeScenario = key;
    invalidate();
    showError();
    updateInputs();
    return true;
  } catch (err) {
    if (revision === generation) showError(err.message);
    return false;
  } finally {
    setControlsBusy(false);
    updateInputs();
  }
}

document.addEventListener("click", async (event) => {
  const button = event.target.closest("button[data-scenario]");
  if (!button || !await loadScenario(button.dataset.scenario)) return;
  if (button.hasAttribute("data-run-scenario")) {
    form.requestSubmit();
  } else {
    run.focus();
  }
});

function scenarioActions() {
  const section = element("section", undefined, "scenario-footer");
  section.append(element("h3", "Try another scenario"));
  const actions = element("div", undefined, "scenario-actions");
  for (const [key, scenario] of Object.entries(scenarios)) {
    if (key === activeScenario) continue;
    const button = element("button", scenario.runLabel, "example");
    button.type = "button";
    button.dataset.scenario = key;
    button.setAttribute("data-run-scenario", "");
    actions.append(button);
  }
  section.append(actions);
  return section;
}

function workflowView(isDemo) {
  const panel = element("section", undefined, "workflow");
  const status = element("span", "Starting assessment", "workflow-status");
  status.setAttribute("role", "status");
  const heading = element("div", undefined, "workflow-heading");
  heading.append(element("h3", "Assessment workflow"), status);
  panel.append(heading);
  if (isDemo) panel.append(element("p", "Demo playback · synthetic evidence", "workflow-demo"));
  const progress = element("div", undefined, "workflow-progress");
  const progressLabel = element("span", "0 of " + stages.length + " stages processed", "workflow-count");
  const track = element("div", undefined, "workflow-track");
  track.setAttribute("aria-hidden", "true");
  progress.append(track, progressLabel);
  panel.append(progress);
  const list = element("ol", undefined, "workflow-steps");
  const rows = new Map();
  for (const [key, label, guide] of stages) {
    const row = element("li", undefined, "workflow-step");
    const name = element("strong", label);
    const detail = element("p", guide);
    const text = element("div");
    const badge = element("span", "Queued", "workflow-badge");
    const dot = element("i", undefined, "workflow-dot");
    dot.setAttribute("aria-hidden", "true");
    text.append(name, detail);
    row.append(dot, text, badge);
    const segment = element("span");
    track.append(segment);
    rows.set(key, { row, detail, badge, label, segment });
    list.append(row);
  }
  panel.append(list);
  return { panel, list, rows, status, progressLabel };
}

async function runWorkflow(workflow, revision, pace) {
  const response = await fetch("/api/assess/stream", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(Object.fromEntries(Object.entries(artifacts).map(([key, input]) => [key, input.text]))),
  });
  if (!response.ok) {
    const data = await response.json();
    throw new Error(data.error || "The assessment failed.");
  }
  const reader = response.body.pipeThrough(new TextDecoderStream()).getReader();
  let pending = "";
  try {
    while (revision === generation) {
      const { done, value } = await reader.read();
      if (done) break;
      pending += value;
      const lines = pending.split("\n");
      pending = lines.pop();
      for (const line of lines) {
        if (revision !== generation) return;
        if (!line) continue;
        const event = JSON.parse(line);
        if (event.type === "error") throw new Error(event.message);
        if (event.type === "result") return event.report;
        const step = workflow.rows.get(event.stage);
        if (event.type !== "step" || !step) continue;
        step.row.dataset.state = event.state;
        step.segment.dataset.state = event.state;
        step.badge.textContent = { running: "Running", done: "Complete", skipped: "Skipped" }[event.state];
        if (event.detail) step.detail.textContent = event.detail;
        if (event.state === "done" || event.state === "skipped") {
          const checked = workflow.list.querySelectorAll('[data-state="done"], [data-state="skipped"]').length;
          workflow.progressLabel.textContent = checked + " of " + stages.length + " stages processed";
        }
        if (event.state === "running") {
          workflow.status.textContent = step.label;
          if (pace) await new Promise((resolve) => setTimeout(resolve, 520));
        }
      }
    }
    if (revision === generation) throw new Error("The assessment ended before a report arrived. Run it again.");
  } finally {
    await reader.cancel().catch(() => {});
  }
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (run.disabled) return;
  if (!artifacts.patch?.text.trim()) {
    showError("Upload a code diff or load a demo, then run the assessment.");
    return;
  }
  showError();
  invalidate();
  setReportState("Reviewing evidence", "running");
  const revision = generation;
  const workflow = workflowView(activeScenario !== null);
  const pace = activeScenario !== null && !matchMedia("(prefers-reduced-motion: reduce)").matches;
  result.replaceChildren(workflow.panel);
  const panelTop = workflow.panel.getBoundingClientRect().top;
  if (panelTop < 0 || panelTop > innerHeight * .8) {
    workflow.panel.scrollIntoView({ block: "start" });
  }
  setControlsBusy(true);
  run.firstChild.textContent = "Reviewing evidence ";
  try {
    const data = await runWorkflow(workflow, revision, pace);
    if (revision === generation) {
      report = data;
      renderReport(data);
      const trace = element("details", undefined, "workflow-trace");
      trace.append(element("summary", "View assessment workflow"), workflow.list);
      result.append(trace, scenarioActions());
    }
  } catch (err) {
    if (revision === generation) {
      workflow.status.textContent = "Assessment stopped";
      const active = workflow.list.querySelector('[data-state="running"]');
      if (active) {
        active.dataset.state = "failed";
        active.querySelector(".workflow-badge").textContent = "Stopped";
        const current = [...workflow.rows.values()].find((step) => step.row === active);
        current.segment.dataset.state = "failed";
      }
      const message = err.message || "Could not reach the assessment server.";
      workflow.panel.append(element("p", message, "error"));
      showError(message);
      setReportState("Review interrupted", "alert");
    }
  } finally {
    setControlsBusy(false);
    run.firstChild.textContent = "Run assessment ";
  }
});

function metric(value, label, detail) {
  const node = element("div", undefined, "metric");
  node.append(element("strong", value), element("small", label));
  if (detail) node.append(element("span", detail));
  return node;
}

function signalCard(label, value, detail, tone) {
  const card = element("article", undefined, "signal-card");
  card.dataset.tone = tone;
  card.append(element("small", label), element("strong", value), element("span", detail));
  return card;
}

function evidenceRow(title, meta, action, tag) {
  const row = element("div", undefined, "row");
  if (tag) row.append(element("div", tag, "severity " + tag.toLowerCase()));
  row.append(element("strong", title), element("small", meta));
  if (action) row.append(element("p", action));
  return row;
}

function renderReport(data) {
  const findingCount = data.finding_count ?? data.findings.length;
  const transitiveChanges = data.dependency_changes?.transitive ?? 0;
  const privacyRoutes = data.privacy_routes?.length ?? 0;
  const elevatedFindings = data.findings.filter((finding) => ["critical", "high"].includes(finding.severity)).length;
  const decisionKey = data.decision.toLowerCase();
  const posture = {
    hold: ["Promotion paused", "Resolve or explicitly accept release gates before promotion."],
    canary: ["Constrained rollout", "Start small and compare health signals against the baseline."],
    go: ["Standard rollout", "Proceed with ordinary monitoring and rollback ownership."],
  }[decisionKey] ?? ["Manual review", "Review the supplied evidence with the release owner."];

  const verdict = element("div", undefined, "verdict " + data.decision.toLowerCase());
  const lead = element("div", undefined, "verdict-lead");
  const eyebrow = element("div", undefined, "verdict-eyebrow");
  eyebrow.append(element("span", "Deployment recommendation"), element("span", posture[0], "posture"));
  const context = element("div", undefined, "decision-context");
  context.append(
    element("span", data.blockers.length ? data.blockers.length + " release " + (data.blockers.length === 1 ? "gate" : "gates") : "No hard release gates"),
    element("span", posture[1])
  );
  lead.append(eyebrow, element("div", data.decision, "decision"), element("p", data.advisory), context);
  const score = element("div", undefined, "score");
  score.style.setProperty("--score", Math.max(0, Math.min(100, data.score)) + "%");
  const scoreInner = element("div", undefined, "score-inner");
  scoreInner.append(element("strong", data.score), element("small", "risk score"));
  score.append(scoreInner);
  verdict.append(lead, score);

  const summary = element("div", undefined, "summary");
  summary.append(
    metric(data.files.length, "Changed files", "Patch scope"),
    metric(data.coverage.percent === null ? "—" : data.coverage.percent + "%", "Observed line coverage", data.coverage.supplied ? "Coverage supplied" : "No coverage file"),
    metric(findingCount, "Actionable findings", elevatedFindings ? elevatedFindings + " elevated" : "No elevated findings"),
    metric(transitiveChanges, "Transitive updates", privacyRoutes + " privacy " + (privacyRoutes === 1 ? "route" : "routes"))
  );

  const signals = element("section", undefined, "signal-strip");
  const signalHeading = element("div", undefined, "signal-strip-heading");
  signalHeading.append(element("span", "Evidence pulse", "mono"), element("small", "A quick read before you open the detail."));
  const signalGrid = element("div", undefined, "signal-grid");
  signalGrid.append(
    signalCard("Release call", data.decision, posture[0], decisionKey),
    signalCard("Supply chain", transitiveChanges + " transitive", data.dependency_changes ? "Compared from lockfiles" : "No lockfile diff supplied", transitiveChanges ? "attention" : "quiet"),
    signalCard("Privacy sniff", privacyRoutes + " candidates", privacyRoutes ? "Trace runtime payload + destination" : "No candidate routes", privacyRoutes ? "attention" : "quiet"),
    signalCard("Attention", elevatedFindings ? elevatedFindings + " elevated" : "No elevated", elevatedFindings ? "Critical or high findings" : "No critical or high findings", elevatedFindings ? "alert" : "calm")
  );
  signals.append(signalHeading, signalGrid);

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
    ["Security evidence", () => renderSecurity(data, body)],
    ["Privacy routes", () => renderPrivacy(data, body)],
    ["Findings (" + (data.finding_count ?? data.findings.length) + ")", () => renderFindings(data, body)],
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
  result.replaceChildren(verdict, summary, signals, tabs, body);
  exportButton.hidden = false;
  setReportState(data.decision + " · " + data.score + " score", decisionKey);
}

function renderOverview(data, body) {
  const intro = element("div", undefined, "tab-intro");
  intro.append(
    element("span", "Risk pulse", "mono"),
    element("h3", "What is shaping this call"),
    element("p", "The score is a transparent total of change impact, test evidence, incident history, and the security signals you supplied.")
  );
  body.append(intro);
  if (data.blockers.length) {
    const blockers = element("div", undefined, "blockers");
    blockers.append(element("span", "Release gates", "severity critical"), element("strong", data.blockers.length + " item" + (data.blockers.length === 1 ? "" : "s") + " need release-owner attention"));
    for (const gate of data.blockers) blockers.append(element("p", gate));
    body.append(blockers);
  }
  body.append(element("h3", "Score composition"));
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
}

function renderFiles(data, body) {
  const coverage = data.coverage;
  const coveragePanel = element("section", undefined, "coverage-panel");
  const coverageLead = element("div");
  coverageLead.append(element("span", "Change evidence", "mono"), element("h3", "Changed files and coverage"), element("p", "Added source lines only. Coverage tracks what the supplied report can actually prove."));
  const coverageScore = element("div", undefined, "coverage-score");
  coverageScore.append(element("strong", coverage.percent === null ? "—" : coverage.percent + "%"), element("small", "observed coverage"));
  coveragePanel.append(coverageLead, coverageScore);
  const coverageBreakdown = element("div", undefined, "coverage-breakdown");
  coverageBreakdown.append(
    element("span", coverage.covered + " covered"),
    element("span", coverage.missed + " missed"),
    element("span", coverage.unknown + " unknown")
  );
  body.append(coveragePanel, coverageBreakdown);
  for (const file of data.files) {
    body.append(evidenceRow(file.path, "+" + file.added + " / −" + file.removed + " lines · " + file.covered + " covered · " + file.missed + " missed · " + file.unknown + " unknown", undefined, file.tags.join(" / ")));
  }
  body.append(element("h3", "Related incidents"));
  if (!data.incidents.length) body.append(element("p", data.incidents_supplied ? "No matching incident modules." : "No incident history supplied."));
  for (const incident of data.incidents) body.append(evidenceRow(incident.id, incident.module, undefined, incident.severity));
}

function renderFindings(data, body) {
  body.append(element("h3", "Findings and remediation"));
  if (!data.findings.length) {
    body.append(element("p", "No findings matched the configured change, privacy and security rules."));
    return;
  }
  if (data.finding_count > data.findings.length) {
    body.append(element("p", "Showing the " + data.findings.length + " highest-priority findings."));
  }
  const filters = element("div", undefined, "finding-filters");
  filters.setAttribute("role", "group");
  filters.setAttribute("aria-label", "Filter findings by severity");
  const list = element("ul", undefined, "finding-list");
  const rows = [];
  for (const finding of data.findings) {
    const row = element("li", undefined, "finding");
    const heading = element("div", undefined, "finding-title");
    heading.append(element("span", finding.severity, "severity " + finding.severity), element("strong", finding.title));
    const evidence = element("div");
    evidence.append(element("small", finding.area));
    if (finding.file) evidence.append(element("code", finding.file + (finding.line ? ":" + finding.line : "")));
    if (finding.detail) evidence.append(element("p", finding.detail));
    const action = element("div");
    action.append(element("small", "Next step"), element("p", finding.action));
    row.append(heading, evidence, action);
    list.append(row);
    rows.push({ row, severity: finding.severity });
  }
  for (const severity of ["all", "critical", "high", "medium", "low"]) {
    const count = rows.filter((entry) => severity === "all" || entry.severity === severity).length;
    if (count === 0) continue;
    const button = element("button", severity[0].toUpperCase() + severity.slice(1) + " (" + count + ")");
    button.type = "button";
    button.setAttribute("aria-pressed", String(severity === "all"));
    button.addEventListener("click", () => {
      for (const filter of filters.children) filter.setAttribute("aria-pressed", String(filter === button));
      for (const entry of rows) entry.row.hidden = severity !== "all" && entry.severity !== severity;
    });
    filters.append(button);
  }
  body.append(filters, list);
}

function renderDependencyMap(changes, auditFindings, body) {
  const paths = changes.filter((entry) => entry.kind === "transitive" && entry.chain.length > 1);
  if (!paths.length) return;

  const section = element("section", undefined, "dependency-map");
  const header = element("div", undefined, "dependency-map-heading");
  const title = element("h3", "Transitive dependency path");
  const mode = element("button", "Flat view", "example");
  mode.type = "button";
  const viewport = element("div", undefined, "dependency-viewport");
  viewport.tabIndex = 0;
  viewport.setAttribute("role", "region");
  viewport.setAttribute("aria-label", "Scrollable dependency path");
  const graph = element("ol", undefined, "dependency-graph");
  graph.setAttribute("aria-label", "Package chain from direct to changed transitive dependency");
  viewport.append(graph);
  header.append(title, mode);
  section.append(header);

  function showPath(path) {
    graph.replaceChildren(...path.chain.map((name, index) => {
      const node = element("li", undefined, "dependency-node");
      const last = index === path.chain.length - 1;
      const role = name === "…" ? "Omitted hops" : index === 0 ? "Direct dependency" : last ?
        (path.change === "added" ? "Added transitive" : "Changed transitive") : "Transitive dependency";
      const face = element("div", undefined, "dependency-face");
      face.append(element("small", role), element("strong", name));
      if (last && path.version) face.append(element("small", "Version " + path.version));
      const auditFinding = last && auditFindings.find((finding) => finding.file === path.name);
      if (auditFinding) {
        face.append(element("span", auditFinding.severity + " · npm audit", "severity " + auditFinding.severity));
      }
      node.classList.toggle("dependency-target", last);
      node.append(face);
      return node;
    }));
    viewport.scrollLeft = 0;
  }

  if (paths.length > 1) {
    const picker = element("select", undefined, "dependency-select");
    picker.setAttribute("aria-label", "Select changed transitive package");
    paths.forEach((path, index) => {
      const option = element("option", path.chain.join(" → "));
      option.value = index;
      picker.append(option);
    });
    picker.addEventListener("change", () => showPath(paths[Number(picker.value)]));
    section.append(picker);
  }
  mode.addEventListener("click", () => {
    const flat = section.classList.toggle("flat");
    mode.textContent = flat ? "3D view" : "Flat view";
  });
  showPath(paths[0]);
  section.append(viewport);
  body.append(section);
}

function renderSecurity(data, body) {
  const auditFindings = data.findings.filter((item) => item.title.startsWith("npm audit flags"));
  const intro = element("div", undefined, "tab-intro");
  intro.append(
    element("span", "Security evidence", "mono"),
    element("h3", "What crosses the release boundary"),
    element("p", "Review network metadata, imported audit results, and the package paths introduced by this release.")
  );
  body.append(intro);
  const sections = element("div", undefined, "security-sections");
  const network = element("section", undefined, "security-section");
  const dependencies = element("section", undefined, "security-section");
  network.append(element("h3", "Network exposure"));
  if (data.network) {
    const { reviewed, cleartext, protected: protectedCount, unknown_transport, flagged } = data.network;
    network.append(
      element("strong", flagged + " flagged of " + reviewed + " classified flows", "evidence-result"),
      element("p", cleartext + " cleartext · " + protectedCount + " protected · " + unknown_transport + " unverified")
    );
  } else {
    network.append(element("p", "No network flow metadata supplied."));
  }
  dependencies.append(element("h3", "Dependency vulnerabilities"));
  sections.append(network, dependencies);
  body.append(sections);
  if (!data.npm_audit) {
    dependencies.append(element("p", "No npm audit report supplied."));
  } else {
    dependencies.append(
      element("strong", data.npm_audit.transitive + " transitive · " + data.npm_audit.direct + " direct", "evidence-result"),
      element("p", "Packages flagged in the imported npm audit report.")
    );
    for (const finding of auditFindings) {
      body.append(evidenceRow(finding.file, finding.detail, finding.action, finding.severity));
    }
  }
  body.append(element("h3", "Lockfile changes"));
  if (!data.dependency_changes) {
    body.append(element("p", "No lockfile comparison supplied."));
    return;
  }
  const locks = data.dependency_changes;
  body.append(element("p", locks.transitive + " transitive · " + locks.direct + " direct changes"));
  renderDependencyMap(locks.changes, auditFindings, body);
  for (const item of locks.changes) {
    body.append(evidenceRow(item.name + (item.version ? " @" + item.version : ""), item.change + " · " + item.chain.join(" → "),
      item.source + " · Integrity metadata " + (item.integrity_present ? "present" : "absent"), item.kind));
  }
}

function renderPrivacy(data, body) {
  const intro = element("div", undefined, "tab-intro privacy-intro");
  intro.append(
    element("span", "Privacy sniff", "mono"),
    element("h3", "Potential personal-data routes"),
    element("p", "Candidate traces combine changed source patterns with the lockfile graph. They are prompts for runtime validation, not a claim that a payload was sent.")
  );
  body.append(intro);
  if (!data.privacy_routes?.length) {
    const clean = element("div", undefined, "privacy-empty");
    clean.append(element("span", "No candidate traces found", "evidence-result"), element("p", "No changed source pattern connected to a changed package path in the supplied evidence."));
    body.append(clean);
    return;
  }
  const routes = element("div", undefined, "route-list");
  for (const route of data.privacy_routes) {
    const candidate = element("article", undefined, "route");
    const heading = element("div", undefined, "route-heading");
    heading.append(
      element("span", "Candidate route", "severity"),
      element("strong", "Verify the payload and destination at runtime"),
      element("small", route.file + ":" + route.line + " · " + route.sink)
    );
    const trace = element("div", undefined, "route-trace");
    const source = element("div", undefined, "route-stop source");
    source.append(element("small", "Changed source"), element("strong", "Sensitive field pattern"));
    const sink = element("div", undefined, "route-stop sink");
    sink.append(element("small", "Observed sink"), element("strong", route.sink));
    trace.append(source, sink);
    const chainLabel = element("span", "Dependency path", "route-label");
    const chain = element("div", undefined, "route-chain");
    const packages = route.chain.map((name) => element("span", name, "route-package"));
    chain.replaceChildren(...packages.flatMap((item, index) =>
      index === 0 ? [item] : [element("span", " → ", "route-arrow"), item]));
    const guidance = element("p", "Check data minimization, consent, destination controls, and whether the changed package should be approved for this release.", "route-guidance");
    candidate.append(heading, trace, chainLabel, chain, guidance);
    routes.append(candidate);
  }
  body.append(routes);
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
