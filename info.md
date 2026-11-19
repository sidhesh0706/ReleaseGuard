# ReleaseGuard: Complete Technical and Product Guide

## Purpose of this document

This is the detailed guide to ReleaseGuard as it exists in the current main
branch. It explains the application from the perspective of a release owner,
a developer, a security reviewer, and a future contributor.

ReleaseGuard is a local deployment-review workspace. It accepts a code diff and
optional evidence artifacts, then returns a deployment recommendation:

    GO
    CANARY
    HOLD

The recommendation is backed by an explainable report. The report shows changed
files, coverage evidence, incident history, security findings, network-flow
evidence, npm audit evidence, lockfile changes, privacy-route candidates, and
a rollback checklist.

The project is intentionally lightweight:

- Python standard library only.
- Static HTML, CSS, and JavaScript frontend.
- No database.
- No external API calls during assessment.
- No execution of submitted source code.
- No package installation or npm command execution.

This file is much more detailed than README.md. Use README.md for quick setup
and this file when you need the exact behavior, limits, rationale, and
extension points.

---

## Contents

1. Product overview
2. The release-review problem
3. Core principles
4. End-to-end flow
5. Architecture
6. Repository layout
7. Local setup and run options
8. Evidence artifacts
9. Patch parsing
10. Coverage evidence
11. Incident evidence
12. Defensive network-flow evidence
13. npm audit evidence
14. npm lockfile comparison
15. Privacy routes through transitive dependencies
16. Security rules and static checks
17. Risk scoring and release decisions
18. HTTP API
19. Browser interface
20. Demo walkthrough
21. Data handling and privacy boundaries
22. Test strategy
23. Limitations and interpretation guidance
24. Troubleshooting
25. Contribution guide
26. Future directions
27. FAQ
28. Source map

---

## 1. Product overview

ReleaseGuard helps answer a practical pre-production question:

    Given what changed in this release, what should we verify before it goes
    to everyone?

It is not intended to replace code review, testing, deployment monitoring,
software composition analysis, a vulnerability scanner, or a privacy program.
It gives a release owner a compact place to reason about signals that are often
spread across pull requests, test reports, incident trackers, lockfiles, audit
reports, and telemetry configuration.

### Typical users

- A developer preparing a release candidate.
- A release manager deciding whether to promote a build.
- A security reviewer looking for focused evidence.
- A privacy reviewer checking whether a new telemetry path is plausible.
- A hackathon judge or demo audience evaluating an explainable safety feature.
- A contributor building a stronger CI or policy workflow on top of the
  prototype.

### Main outputs

Every assessment returns:

- A decision: GO, CANARY, or HOLD.
- An overall risk score from 0 to 100.
- Scores by risk dimension.
- Changed file inventory and test-evidence counts.
- Related incident matches.
- Security and privacy findings with next actions.
- Network-flow summary, when supplied.
- npm audit summary, when supplied.
- Direct and transitive package changes, when lockfiles are supplied.
- Candidate privacy routes through changed dependency chains.
- An operational rollback checklist.

---

## 2. The release-review problem

Release quality is rarely determined by one signal.

A code diff may look small while changing a payment path. Test coverage may
exist but omit new logic. A dependency update may pull in a different nested
package. A privacy-sensitive field may be passed to telemetry. A package audit
may flag a transitive vulnerability. A network-flow report may reveal that
personal data was classified on an unverified connection.

Looking at those signals separately makes it hard to decide what matters.
ReleaseGuard combines them into one report while preserving the evidence behind
each conclusion.

### Example scenario

Imagine a patch that:

1. Adds a customer email to a JavaScript payload.
2. Calls telemetry.track with that payload.
3. Updates a nested package beneath the telemetry dependency.
4. Includes an npm audit finding for a transitive package.
5. Includes network metadata showing personal data over HTTP.

The right release discussion is no longer just:

    Did package-lock.json change?

It becomes:

    Is the email required in telemetry?
    Does this flow have approved transport and destination controls?
    Which direct dependency leads to the changed nested package?
    Does the audit report need remediation before promotion?
    Should this release use a canary or be held?

ReleaseGuard is built to make that discussion quick, visible, and grounded in
locally supplied evidence.

---

## 3. Core principles

### 3.1 Local-first analysis

The application serves on loopback by default. It processes submitted text in
memory and makes no external calls during an assessment.

This is important for code diffs, incident history, audit reports, and network
metadata that may be sensitive in a real release environment.

### 3.2 Deterministic and explainable

The analysis uses explicit parsers, regex rules, graph traversal, and score
weights. There is no model-generated reasoning in the assessment itself.

Each finding has:

- An area.
- A severity.
- A title.
- A safe file/line reference where appropriate.
- Optional safe detail text.
- A remediation action.

### 3.3 Evidence is not certainty

ReleaseGuard distinguishes observed evidence from an inference.

For example:

- A field name in an added line is observed static evidence.
- A telemetry-like sink call in an added line is observed static evidence.
- A package import in an added line is observed static evidence.
- A dependency path in a lockfile is observed static evidence.
- A claim that a payload reaches a nested package at runtime is not proven.

Privacy-route results are therefore called candidates. The interface tells the
release owner to validate the payload and destination at runtime.

### 3.4 The app avoids raw secrets and raw data values

Reports include safe labels, paths, line numbers, classifications, and package
names. They avoid returning original source lines, matched secret values, raw
email values, lockfile integrity strings, or resolved registry URLs.

### 3.5 Release ownership remains human

GO, CANARY, and HOLD are recommendations. The release owner makes the final
deployment decision and can apply the organization's exception process.

---

## 4. End-to-end release-review flow

    Developer or release owner
               |
               v
    Upload evidence from the candidate release
               |
    +----------+----------+-----------+-----------+
    |          |          |           |           |
    v          v          v           v           v
   Diff     Coverage   Incidents   Network      npm audit
                                      metadata
               |
               +-------------------------------+
                                               |
                                  Optional lockfile pair
                                               |
                                  Baseline package-lock
                                               |
                                  Release package-lock
                                               |
                                               v
                              Deterministic assessment engine
                                               |
          +----------------+-------------------+----------------+
          |                |                   |                |
          v                v                   v                v
       Change tags      Rule checks      Evidence review   Dependency graph
          |                |                   |                |
          +----------------+-------------------+----------------+
                                               |
                                               v
                                  Risk score and advisory
                                               |
                                               v
                       Browser report and downloadable JSON advisory

The supplied diff is always treated as data. The application does not run code
from the diff, execute package scripts, or invoke npm.

---

## 5. Architecture

ReleaseGuard has four logical layers.

### 5.1 Presentation layer

The web directory contains a static browser interface:

- index.html provides semantic structure and upload controls.
- app.js owns upload state, API calls, report rendering, tab behavior, and JSON
  export.
- style.css owns the responsive layout and visual presentation.
- demo.json provides a synthetic evidence bundle.

### 5.2 API boundary

server.py runs a small local ThreadingHTTPServer. It:

- Serves the browser assets.
- Exposes the health endpoint.
- Validates JSON request shape and request size.
- Enforces per-artifact size limits.
- Calls engine.assess.
- Sends conservative response headers.

### 5.3 Core assessment engine

engine.py handles:

- Unified diff parsing.
- Coverage parsing.
- Incident CSV parsing.
- Changed-file classification.
- Rule matching.
- Score calculation.
- Decision selection.
- Rollback checklist construction.
- Integration of evidence-module findings.

### 5.4 Evidence modules

Two modules keep focused evidence logic separate from the general engine.

security_evidence.py handles:

- Sanitized network-flow metadata.
- Imported npm audit reports.

dependency_evidence.py handles:

- npm package-lock v2/v3 validation.
- Dependency graph construction.
- Direct and transitive change calculation.
- Package source and integrity classification.
- Candidate privacy routes from JavaScript or TypeScript source to a changed
  dependency chain.

This separation makes the project easier to extend and easier to test.

---

## 6. Repository layout

    ReleaseGuard/
    |
    +-- README.md
    |   Short setup and feature guide.
    |
    +-- info.md
    |   Detailed reference document.
    |
    +-- engine.py
    |   Core parser, scoring engine, static rules, and report assembler.
    |
    +-- security_evidence.py
    |   Sanitized network-flow and npm-audit evidence parsing.
    |
    +-- dependency_evidence.py
    |   npm lockfile graph comparison and privacy-route candidate logic.
    |
    +-- server.py
    |   Local HTTP API and static file server.
    |
    +-- test_dependency_evidence.py
    |   Regression tests for lockfile and privacy-route behavior.
    |
    +-- .run/
    |   PyCharm run configuration.
    |
    +-- web/
        |
        +-- index.html
        |   Browser page structure and evidence inputs.
        |
        +-- app.js
        |   Browser logic and report rendering.
        |
        +-- style.css
        |   Responsive visual styles.
        |
        +-- demo.json
            Synthetic end-to-end evidence bundle.

### Local development metadata

The .gitignore file excludes typical local Python and IDE state:

- __pycache__
- Python bytecode
- .venv
- .env
- .idea

The .run/ReleaseGuard.run.xml file provides a PyCharm run configuration that
targets server.py and uses a loopback host.

---

## 7. Local setup and run options

### Requirements

- Python 3.10 or later.
- A modern desktop browser.
- No external Python dependencies.

### Run from a shell

    python server.py

Then open:

    http://127.0.0.1:8765

### Environment variables

| Variable | Default | Meaning |
| --- | --- | --- |
| RELEASEGUARD_HOST | 127.0.0.1 | HTTP bind host |
| PORT | 8765 | HTTP bind port |

The default loopback binding is intentional. If an operator changes the host to
an address reachable by other machines, the app still has no built-in
authentication, authorization, or CSRF layer. Add those protections before
placing it on a shared or untrusted network.

### PyCharm workflow

1. Open the ReleaseGuard root directory.
2. Select an existing Python interpreter, or create .venv with:

       python -m venv .venv

3. Select the ReleaseGuard run configuration.
4. Run it, or right-click server.py and run the script.
5. Open the local URL printed by the server.

---

## 8. Evidence artifacts

ReleaseGuard supports seven text artifacts.

| Artifact | Required | Format | Primary use |
| --- | --- | --- | --- |
| Code diff | Yes | Unified diff or Git patch | Finds changed lines, paths, tags, and static rules |
| Test coverage | No | LCOV or coverage.py JSON | Matches changed source lines to line evidence |
| Incident history | No | CSV | Matches historical incidents to changed modules |
| Network flow metadata | No | Sanitized CSV | Reviews transport for personal/credential data classifications |
| npm audit report | No | npm audit JSON v2 | Imports direct/transitive vulnerability findings |
| Baseline lockfile | No, paired | npm package-lock v2/v3 | Previous dependency graph |
| Release lockfile | No, paired | npm package-lock v2/v3 | Candidate release dependency graph |

Each artifact must be text and must not exceed 750 KB after UTF-8 encoding.

### Artifact pairing rules

The lockfiles must be supplied as a pair. A baseline without a release
lockfile, or a release without a baseline, produces a validation error.

### Recommended source alignment

For the most reliable review:

- Build coverage from the same revision family as the diff.
- Use repository-relative coverage paths.
- Use incident module paths that match repository layout.
- Generate npm audit evidence from the release revision.
- Use the actual baseline and candidate package-lock files.
- Provide only sanitized network-flow classifications, not raw traffic captures.

---

## 9. Patch parsing

The code diff is the primary required artifact.

### Parsed data

For every changed path, the parser records:

- Normalized path.
- Added line numbers in the new file.
- Added line text held only during assessment.
- Removed line count.

### Supported patch structures

The parser supports common unified-diff and Git-patch patterns:

- diff --git headers.
- Old and new file headers.
- Standard hunk headers.
- New files using /dev/null.
- Quoted path parsing where safe.
- Rename-to and copy-to markers.

### Hunk validation

The parser tracks the old and new line counts from every hunk header. It rejects
a patch if:

- A hunk ends before its declared counts are consumed.
- A hunk consumes too many old or new lines.
- A hunk appears before file headers.
- No changed file is found.
- More than 300 changed files are supplied.

This prevents malformed patch input from creating inaccurate coverage line
mapping or misleading findings.

### Why only added lines are examined

The product focuses on release-introduced behavior. Static rules, privacy route
correlation, and coverage matching all use added lines.

That is a deliberate tradeoff:

- It keeps the report focused.
- It avoids overwhelming results from legacy code.
- It may miss pre-existing risky behavior made reachable by another change.

Use a full codebase scanner alongside ReleaseGuard when that broader coverage
is required.

---

## 10. Coverage evidence

ReleaseGuard supports LCOV and coverage.py JSON with per-line evidence.

### LCOV example

    SF:services/checkout/handler.py
    DA:20,3
    DA:21,0
    end_of_record

Line counts greater than zero are treated as covered. Counts of zero are
treated as missed.

### coverage.py JSON example

    {
      "files": {
        "services/checkout/handler.py": {
          "executed_lines": [20, 22],
          "missing_lines": [21]
        }
      }
    }

### Added source lines

Coverage is calculated only for added, non-comment source lines from supported
source files.

Supported extensions are:

    .py, .js, .jsx, .ts, .tsx, .go, .java, .rb, .rs, .php,
    .cs, .kt, .c, .cpp, .swift

Test-file paths are excluded from changed-source coverage. Blank lines and
comment-only lines are excluded too.

### Evidence states

| State | Meaning |
| --- | --- |
| Covered | The supplied report explicitly records execution |
| Missed | The supplied report explicitly records zero executions |
| Unknown | No matching line evidence is present |

The displayed percentage is based on observed lines only:

    covered / (covered + missed)

When no lines are observed, the percentage is omitted. Unknown lines are shown
separately and add risk because the release lacks matching line evidence.

### Common causes of unknown lines

- Coverage paths use a different root prefix than the patch.
- Coverage came from a different revision.
- The changed source type is unsupported.
- The report contains generated paths rather than source paths.
- The artifact is incomplete.

Unknown does not necessarily mean untested. It means ReleaseGuard cannot
connect supplied evidence to that changed line.

---

## 11. Incident history evidence

Incident history is an optional CSV with exactly these required columns:

    id,module,severity

Example:

    id,module,severity
    INC-104,services/checkout,high
    INC-127,db/migrations,medium

### Validation

- IDs may contain letters, numbers, periods, underscores, and hyphens.
- Module path cannot be blank.
- Severity must be low, medium, high, or critical.

### Matching

The engine normalizes slashes and compares the incident module path against
changed file paths using full path segments. This is safer than a simple
substring search.

Example:

    Incident module: services/checkout
    Changed file:    services/checkout/handler.py
    Match:           yes

### Incident score weights

| Severity | Points |
| --- | ---: |
| Low | 1 |
| Medium | 3 |
| High | 6 |
| Critical | 9 |

An incident match is context, not causation. It tells a release owner that the
changed area has historical operational relevance.

---

## 12. Defensive network-flow evidence

Network-flow evidence is optional. It is meant for sanitized classifications
produced by a team's own monitoring or data-classification workflow.

### Required CSV shape

The CSV must have exactly three columns:

    transport,destination_scope,data_class

Example:

    transport,destination_scope,data_class
    http,external,personal
    https,external,credentials
    unknown,internal,personal

### Allowed transport values

| Class | Values |
| --- | --- |
| Cleartext | http, ftp, telnet |
| Protected | https, tls, sftp, ssh |
| Unknown | unknown |

### Allowed destination scopes

- internal
- external
- unknown

### Allowed data classes

- public
- personal
- credentials
- unknown

### Limits and data minimization

The CSV supports up to 5,000 data records. It should include classifications,
not raw endpoint URLs, raw payloads, account identifiers, or traffic captures.

The report exposes only:

- Category labels.
- Transport classification.
- Destination scope.
- CSV row number.

### Findings generated

| Evidence condition | Area | Severity |
| --- | --- | --- |
| Personal data on HTTP/FTP/Telnet | Privacy | High |
| Credential data on HTTP/FTP/Telnet | Security | Critical |
| Personal data with unknown transport | Privacy | Medium |
| Credential data with unknown transport | Security | Medium |

Protected transports do not produce a network-flow finding in this prototype.
That does not prove the destination is approved or that payload minimization is
correct.

---

## 13. npm audit evidence

ReleaseGuard can import an existing npm audit JSON report. It does not invoke
npm audit itself.

### Supported report

The expected report must:

- Have auditReportVersion equal to 2.
- Not contain an error field.
- Include a vulnerabilities object.
- Contain no more than 5,000 package entries.

### What ReleaseGuard extracts

For each vulnerability entry it reads:

- Package name.
- Severity.
- Whether npm identifies it as a direct dependency.

The application creates a Security finding and counts direct and transitive
findings separately.

### Why imported audit evidence matters

Using a locally supplied report keeps ReleaseGuard's core analysis offline.
However, when a developer generates an npm audit report, npm may send
dependency information to the configured registry. That data exchange is
outside ReleaseGuard.

### Expected action

For every imported npm audit finding:

1. Open the original npm audit report.
2. Identify the dependency chain.
3. Choose an available remediation.
4. Update, override, patch, or remove the dependency as appropriate.
5. Retest the release candidate.

---

## 14. npm lockfile comparison

The lockfile comparison gives release owners a dependency delta instead of a
raw package-lock diff.

### Supported lockfiles

Only npm package-lock versions 2 and 3 are supported.

The parser validates:

- A root packages entry is present.
- Package paths are bounded in length.
- Package count does not exceed 5,000.
- Resolved graph edges do not exceed 25,000.
- Package names are valid npm package names.
- Source metadata types are valid.
- Link and install-script fields are booleans when present.

### Graph construction

The parser reads installed package entries under node_modules. It gathers root
dependencies from:

- dependencies
- optionalDependencies
- peerDependencies
- devDependencies

Nested graph edges come from:

- dependencies
- optionalDependencies
- peerDependencies

The resolver follows npm-style node_modules fallback behavior. A nested package
can be resolved at its local node_modules location or at an appropriate parent
location when hoisting applies.

### Reachability

ReleaseGuard compares only packages reachable from root dependencies in the
release lockfile. This keeps the report focused on installed release graph
changes.

### Change detection

A reachable package is categorized as:

- Added when it was not reachable in the baseline graph.
- Updated when package metadata differs from the baseline graph.

The comparison watches:

- Resolved source string.
- Integrity string.
- Version string.
- hasInstallScript value.
- link value.

### Direct and transitive labels

| Kind | Meaning |
| --- | --- |
| Direct | Reached directly from the root dependency declarations |
| Transitive | Reached through at least one other package |

The returned chain exposes package names only. It does not include raw registry
URLs or integrity hashes.

### Source categories

Instead of showing raw resolved URLs, each package receives a safe source
category:

| Category | Meaning |
| --- | --- |
| HTTPS | Resolved source is an HTTPS URL without embedded credentials |
| Source requires review | Source is missing, non-HTTPS, malformed, or contains credentials |
| Unspecified | No source string is available |

### Lockfile findings

ReleaseGuard produces findings for changed reachable packages when:

- A non-linked package source requires review.
- A non-linked package lacks integrity metadata.
- A changed package declares an install script.

### Deliberate exclusions

The current comparison does not report:

- Removed packages.
- Unreachable package entries.
- npm workspace-specific behavior.
- Package source contents.
- Registry ownership or maintainer changes.
- CVEs unless an npm audit report is supplied separately.

---

## 15. Privacy routes through transitive dependencies

This is the feature that connects privacy sniffing with transitive dependency
control.

### The question answered

The feature does not merely ask whether a sensitive-looking field appears in
the diff. It asks:

    Does a changed JavaScript or TypeScript line appear to send a
    sensitive-looking value through an imported package, where that package
    has a changed transitive dependency path?

When the answer is yes, the app presents a candidate route for review.

### Supported source languages for route correlation

Privacy-route correlation is limited to changed files with these suffixes:

    .js, .jsx, .ts, .tsx, .mjs, .cjs

This is narrower than the general static-rule source set because the route
logic currently understands JavaScript and TypeScript import/call patterns.

### Sensitive field signals

The route matcher looks for selected field-name patterns such as:

| Category group | Examples |
| --- | --- |
| Email | email, emailAddress, email_address |
| Identifiers | customer_id, user_id, device_id, session_id |
| Phone | phone, phoneNumber, phone_number |
| Government identifiers | Aadhaar, SSN, passportNumber, national_id |
| Personal dates | date_of_birth |

These are field-name patterns. They do not prove that the actual runtime value
is personal data, and the report does not display raw matched values.

### Supported import patterns

The matcher recognizes:

    import telemetry from "@demo/telemetry";
    import * as telemetry from "@demo/telemetry";
    const telemetry = require("@demo/telemetry");

It maps the locally bound name, such as telemetry, to the root imported package
when that package appears as a direct dependency in the release lockfile.

The current matcher does not perform complete JavaScript module resolution or
support every named-import variation.

### Supported sink methods

The matcher watches calls using a bound import name followed by one of:

    track
    capture
    identify
    send
    post
    log
    setItem

Examples:

    telemetry.track(payload);
    client.capture({ email: customer.email });
    analytics.identify(userId);

The method name is a static hint. It is not proof of a remote network request,
telemetry delivery, or data storage behavior.

### Simple variable tracking

The matcher supports a limited contiguous-lines data-flow pattern:

    const payload = { email: customer.email };
    telemetry.track(payload);

The first line marks payload as a sensitive variable. The second line uses
payload at a candidate sink.

If a gap occurs between added source line numbers, the tracked variable set is
cleared. This avoids carrying a simple inference across unrelated hunks or
separated code blocks.

Reassignment also clears the variable's sensitive state:

    let payload = { email: customer.email };
    payload = { status: "ok" };
    telemetry.track(payload);

This pattern does not create a candidate route.

### Route construction

For a candidate route, ReleaseGuard:

1. Finds a qualifying JavaScript/TypeScript import in added code.
2. Finds a sensitive field directly in sink arguments, or a simple sensitive
   variable passed to the sink.
3. Confirms the import refers to a direct release dependency.
4. Walks the release dependency graph below that direct package.
5. Selects changed transitive descendants.
6. Emits safe chain labels for up to five descendants per package binding.

Example:

    customer.email
        ->
    telemetry.track(payload)
        ->
    @demo/telemetry
        ->
    demo-replay

The report displays:

- Changed source file.
- Changed source line.
- Sink method name.
- Named dependency chain.

### Limits

To bound work and report size:

- At most 32 distinct package bindings at candidate sinks are correlated.
- At most five changed descendant chains are emitted per imported package.
- At most 100 candidate privacy routes are returned.
- Long package chains are shortened after 16 elements.

### Finding behavior

Each candidate route creates a High privacy finding:

    Possible personal-data route through a changed dependency chain

The remediation asks the release owner to:

1. Verify the payload at runtime.
2. Verify the destination at runtime.
3. Review the named dependency chain.
4. Apply data minimization and approved-vendor controls where required.

### What a privacy route does not prove

It does not prove:

- That the sink call succeeded.
- That the package sent data to the internet.
- That a transitive package received the payload.
- That consent exists or does not exist.
- That the destination is approved or unapproved.
- That a data breach happened.

It is an explainable release-review candidate generated from source and
lockfile evidence.

---

## 16. Static security and privacy checks

In addition to evidence modules, engine.py runs static checks against added
lines.

### Security rules

| Rule | Severity | Expected action |
| --- | --- | --- |
| Potential secret in added code | Critical | Remove it and rotate if it was real |
| TLS verification disabled | High | Restore certificate validation |
| Public network ingress | High | Restrict source ranges |
| Unsafe dynamic execution | High | Replace with constrained behavior |
| Wildcard CORS policy | Medium | Restrict origins |

### Privacy rules

| Rule | Severity | Expected action |
| --- | --- | --- |
| Potential personal data in logs | High | Redact fields and review retention/access |
| Email-like value in added code | Medium | Confirm synthetic fixture or remove it |
| Sensitive field added | Medium | Review purpose, retention, access, and deletion |
| Candidate privacy route | High | Verify payload/destination and review dependency chain |

### Static-rule scope

Rules look only at added lines. This keeps the report about newly introduced
release behavior, but it means pre-existing code can be outside the result.

### Finding ordering

Before output, findings are sorted by severity:

1. Critical
2. High
3. Medium
4. Low

The response stores the untruncated finding count and returns at most 600 of
the highest-priority findings.

---

## 17. Risk scoring and release decisions

### Dimension caps

| Dimension | Maximum points |
| --- | ---: |
| Change impact | 30 |
| Test evidence | 25 |
| Incident history | 15 |
| Security | 20 |
| Privacy | 10 |
| Total | 100 |

The overall score is the sum of capped dimensions.

### Change-impact tags

| Tag | Point weight |
| --- | ---: |
| Migration | 9 |
| Dependency | 5 |
| Configuration | 5 |
| Critical path | 9 |
| Destructive migration | 14 |

Eight or more changed files add another five change-impact points.

### Supplemental evidence scoring

Network metadata, npm audit findings, lockfile control findings, and privacy
route findings enter the same Security or Privacy scoring dimensions as static
rules.

| Severity | Points |
| --- | ---: |
| Critical | 20 |
| High | 10 |
| Medium | 5 |
| Low | 1 |

### Decision policy

| Decision | Condition |
| --- | --- |
| HOLD | Explicit blocker or total score at least 45 |
| CANARY | Score from 15 to 44, unknown coverage, or high/critical finding without HOLD |
| GO | No HOLD/CANARY condition applies |

### Explicit blockers

The current blockers include:

- Potential secret in added code.
- Destructive schema change.
- Critical supplemental evidence such as cleartext credentials from network-flow
  metadata.

### Recommendation semantics

| Recommendation | Suggested release behavior |
| --- | --- |
| GO | Use normal deployment process and monitor standard health metrics |
| CANARY | Start small, define abort thresholds, compare to baseline |
| HOLD | Pause promotion until evidence is resolved or explicitly accepted |

The report always includes a rollout and rollback checklist because the
recommendation is only one part of safe deployment practice.

---

## 18. HTTP API

### Health check

Request:

    GET /api/health

Response:

    {"status": "ok"}

### Assessment endpoint

Request:

    POST /api/assess
    Content-Type: application/json

Request body fields:

| Field | Required | Description |
| --- | --- | --- |
| patch | Yes | Unified diff or Git patch text |
| coverage | No | LCOV or coverage.py JSON |
| incidents | No | Incident CSV |
| network_flows | No | Sanitized transport/destination/data-class CSV |
| npm_audit | No | npm audit JSON report version 2 |
| baseline_lock | No, paired | Baseline npm package-lock v2/v3 |
| release_lock | No, paired | Release npm package-lock v2/v3 |

Example shape:

    {
      "patch": "diff --git a/app.js b/app.js ...",
      "coverage": "",
      "incidents": "",
      "network_flows": "",
      "npm_audit": "",
      "baseline_lock": "",
      "release_lock": ""
    }

### Success response fields

| Field | Description |
| --- | --- |
| decision | GO, CANARY, or HOLD |
| score | Overall risk score |
| advisory | Human-readable deployment advice |
| dimensions | Capped score by risk dimension |
| files | Changed-file inventory |
| coverage | Covered/missed/unknown changed source evidence |
| incidents | Matching incident records |
| network | Network-flow summary or null |
| npm_audit | npm-audit summary or null |
| dependency_changes | Direct/transitive lockfile change summary or null |
| privacy_routes | Candidate source-to-dependency paths |
| findings | Returned findings, sorted by severity |
| finding_count | Total findings before truncation |
| blockers | Explicit HOLD reasons |
| checklist | Rollback and recovery actions |

### Error responses

| Status | Meaning |
| --- | --- |
| 400 | Malformed JSON or an evidence field is not text |
| 404 | Unknown endpoint or static page |
| 413 | Request is empty, too large, or an artifact exceeds 750 KB |
| 415 | Content type is not application/json |
| 422 | Artifact syntax/validation error |

### Response security headers

The server sets:

- Cache-Control: no-store
- X-Content-Type-Options: nosniff
- Referrer-Policy: no-referrer
- A restrictive Content-Security-Policy for local assets

---

## 19. Browser interface

### Evidence upload panel

The evidence panel exposes seven upload slots:

1. Code diff.
2. Test coverage.
3. Incident history.
4. Network flow metadata.
5. npm audit report.
6. Baseline lockfile.
7. Release lockfile.

The lockfile pair is grouped inside a collapsible Compare npm lockfiles control.

Uploads can be selected with the file picker or dropped onto the corresponding
card. The UI tracks supplied artifacts and allows the report to be cleared.

### Report tabs

After a successful assessment, the report includes:

| Tab | Contents |
| --- | --- |
| Risk summary | Score dimensions and explicit release gates |
| Changed files | Changed files, coverage counts, and incident matches |
| Findings | Remediation-oriented static and imported evidence findings |
| Security evidence | Network metadata, npm audit summary, and lockfile controls |
| Privacy routes | Candidate source-to-transitive-dependency routes |
| Rollback | Operational recovery checklist |

### Security evidence tab

The Security evidence tab has three sections:

1. Network exposure: cleartext, protected, unknown, and flagged counts.
2. Dependency vulnerabilities: direct/transitive totals from imported npm audit.
3. Lockfile changes: direct/transitive change totals and safe package metadata.

### Privacy routes tab

The Privacy routes tab does not claim runtime certainty. It presents:

- Package chain.
- Changed source file and line.
- Sink method.
- A concise reminder to validate payload and destination at runtime.

### Accessibility behavior

The web interface includes:

- Semantic upload controls.
- Visible focus styles.
- Accessible labels.
- Tab list and tab-panel behavior.
- Keyboard navigation among tabs.
- Live report updates.
- Reduced-motion support for the decorative hero animation.

---

## 20. Demo walkthrough

The bundled demo is synthetic and intentionally exercises every evidence type.

### Demo artifacts

| Artifact | Demo purpose |
| --- | --- |
| Patch | Adds logging, a TLS-disabled gateway call, migration, dependency declaration, and JS telemetry payload |
| Coverage | Shows covered and missed lines |
| Incidents | Shows historical checkout and migration incidents |
| Network flows | Includes personal data over HTTP and unknown transport |
| npm audit | Includes a high-severity transitive finding |
| Baseline lockfile | Shows telemetry with demo-replay version 1.0.0 |
| Release lockfile | Shows demo-replay version 1.0.1 |

### Privacy-route portion of demo

The JavaScript portion follows this simple pattern:

    import telemetry from "@demo/telemetry";
    const payload = { email: customer.email };
    telemetry.track(payload);

The lockfile comparison shows a changed transitive package beneath
@demo/telemetry:

    @demo/telemetry
        ->
    demo-replay

The Privacy routes tab therefore displays a candidate path with the sink method
track and the changed dependency chain.

### Expected decision

The demo returns HOLD because it intentionally includes several serious signals,
including destructive migration behavior, security/privacy evidence, and a high
overall score.

### Suggested live demo sequence

1. Select Load checkout demo.
2. Select Run assessment.
3. Show the HOLD recommendation and score dimensions.
4. Open Security evidence and describe imported network and npm audit signals.
5. Open Privacy routes and describe the candidate package chain.
6. Open Findings to show concrete remediation.
7. Open Rollback to show operational readiness.

---

## 21. Data handling and privacy boundaries

### Local processing

ReleaseGuard:

- Binds to loopback by default.
- Receives artifacts in JSON.
- Processes artifacts in memory for the request.
- Does not persist raw evidence to a database.
- Does not fetch package metadata.
- Does not perform outbound API calls.
- Does not execute a patch or install dependencies.

### Report minimization

Reports include:

- File labels.
- Line numbers.
- Severity labels.
- Package names and safe dependency chains.
- Source categories such as HTTPS or Source requires review.
- Classification-based network evidence.

Reports omit:

- Raw source lines.
- Secret values.
- Email values.
- Resolved registry URLs.
- Integrity hashes.
- Raw network destinations.
- Raw network payloads.

### Important boundary

Local processing reduces unnecessary external exposure. It does not automatically
make a deployment workflow compliant with privacy, regulatory, contractual, or
security requirements. Teams still need their own data classification,
authorization, retention, vendor approval, and release-management processes.

---

## 22. Test strategy

The project uses Python's standard-library unittest framework.

Run the suite:

    python -m unittest -v

### Current regression tests

The test_dependency_evidence module covers:

- Changed transitive dependency under an unchanged direct package.
- Shared transitive dependency tracing from the package used at the sink.
- Export behavior that omits registry URLs and integrity hashes.
- Invalid lockfile metadata rejection.
- Sensitive variable reassignment clearing a privacy candidate.
- Bundled demo behavior across all evidence types.

### Additional useful checks

Compile the Python sources:

    python -m py_compile engine.py server.py security_evidence.py dependency_evidence.py test_dependency_evidence.py

Check browser JavaScript:

    node --check web/app.js

Check Git whitespace:

    git diff --check

### Testing principles

The most important tests protect policy boundaries:

- Input validation must fail safely.
- Export must not expose registry URLs or integrity metadata.
- A dependency chain must trace from the package at the candidate sink.
- Reassigning a sensitive variable should not preserve stale taint-like state.
- The bundled demo should demonstrate every supported evidence type.

---

## 23. Limitations and interpretation guidance

### Static-route limitations

Privacy routes are intentionally constrained:

- JavaScript/TypeScript only.
- Default, namespace, and simple CommonJS imports only.
- Selected sink methods only.
- Field-name matching only.
- Simple assignments in contiguous added lines only.
- No cross-file tracking.
- No full control-flow analysis.
- No runtime validation.

### Dependency-comparison limitations

- npm package-lock v2/v3 only.
- Removed packages are outside the comparison.
- Workspaces and unresolved package behavior are outside the comparison.
- Package source code is not inspected.
- Vulnerabilities come only from supplied npm audit evidence.
- Registry URLs and integrity hashes are deliberately omitted from output.

### Network-flow limitations

- The input is a classification CSV, not packet capture.
- Protected transport does not prove destination approval.
- Destination scope is supplied metadata and not independently verified.
- The prototype does not inspect certificates or perform live connectivity.

### General scoring limitations

- Weights are transparent defaults, not a universal risk model.
- Score caps can hide repeated occurrences after a dimension reaches its limit.
- A CANARY recommendation is not a substitute for monitored rollout policy.
- A HOLD recommendation requires a human release decision and remediation plan.

### Correct interpretation

Use ReleaseGuard to prioritize review and to make release reasoning legible.
Do not treat a finding as proof of exploitability, a privacy breach, vendor
behavior, legal non-compliance, or runtime network transmission.

---

## 24. Troubleshooting

### Server does not start

Check Python:

    python --version

If port 8765 is already used, set another port before launch.

### Browser cannot connect

Use the address printed by server.py. The default is:

    http://127.0.0.1:8765

Verify that the server process remains running and that a local firewall has not
blocked the chosen port.

### API returns 422

A 422 response means the supplied text was readable but did not meet parser
rules. Common causes:

- Patch hunk counts are incomplete.
- Coverage does not match LCOV or coverage.py JSON shape.
- Incident CSV is missing required columns.
- Network CSV has unsupported values or extra columns.
- npm audit report is not a successful version-2 report.
- Only one npm lockfile was supplied.
- Lockfile is not package-lock v2/v3 or exceeds limits.

### Many unknown coverage lines

Check whether:

- Coverage paths are repository-relative.
- Coverage and diff come from the same revision family.
- The changed extension is supported.
- The coverage report references generated files instead of source files.

### No lockfile changes appear

Check:

- Both baseline and release lockfiles were supplied.
- Packages are root-reachable in the release graph.
- The changed package differs in source, integrity, version, link, or
  install-script metadata.
- The package was not only removed.

### No privacy route appears

Check:

- The changed source is JavaScript or TypeScript.
- The code uses a supported import style.
- The imported package is a direct package in the release lockfile.
- A supported sink method is called on the imported binding.
- A supported sensitive field appears directly or via a simple variable.
- A changed transitive package exists beneath the direct imported package.

### Privacy route appears but feels unexpected

Review the source and note the scope:

- The result is a candidate, not runtime proof.
- Variable tracking is local and simple.
- Package-chain output describes lockfile structure, not payload delivery.

### npm audit shows findings that are not actionable

Use the original audit report as the source of advisory detail. ReleaseGuard
imports the severity and direct/transitive classification to keep the report
small and offline.

---

## 25. Contribution guide

### Before changing assessment policy

1. Identify which evidence type and decision behavior changes.
2. Add a regression test.
3. Preserve safe export behavior.
4. Update README.md.
5. Update this file.
6. Verify the synthetic demo remains valid or adjust it deliberately.

### Adding a network-flow rule

Consider:

- Does it operate only on sanitized classifications?
- Can the result be described without endpoint/payload disclosure?
- Does it have an appropriate severity?
- Does the summary remain bounded at 5,000 records?

### Adding an npm audit interpretation

Consider:

- Does it use a stable npm audit report schema?
- Is the report imported rather than fetched?
- Are direct and transitive distinctions retained?
- Does the output avoid copying advisory content unnecessarily?

### Adding a privacy route pattern

Consider:

- Which language and import syntax are supported?
- What field-name pattern is specific enough?
- What sink method indicates meaningful review?
- Could a false positive occur from an unrelated method name?
- Can the result be labelled as a candidate rather than certainty?

### Adding another package ecosystem

Keep the same principles:

- Validate locally supplied lockfile data.
- Bound node and edge counts.
- Use root-reachable graph comparison.
- Avoid raw URLs, credentials, and integrity hashes in reports.
- Preserve direct and transitive path explanation.

---

## 26. Future directions

The following ideas are not implemented in the current branch.

### Dependency ecosystems

- Yarn lockfile comparison.
- pnpm lockfile comparison.
- Python requirements/lockfile comparison.
- Cargo, Go, Maven, Gradle, Composer, and Ruby Bundler support.

### Stronger dependency evidence

- Software bill of materials export.
- Provenance and signature verification.
- Approved registry policy.
- License policy.
- Dependency age and maintenance signals.
- Vulnerability remediation recommendations.

### Privacy controls

- Organization-specific field dictionaries.
- Allowed sink/vendor lists.
- Data-category-to-destination policies.
- Consent metadata review.
- Runtime trace correlation with sanitized evidence.
- Signed privacy exception workflow.

### Static analysis

- JavaScript/TypeScript AST-based route analysis.
- Named-import support.
- Cross-file bindings.
- Cross-function data flow.
- Source-map support.
- Configuration-aware sink discovery.

### Release workflow

- Command-line mode for CI.
- Pull-request annotations.
- Policy-as-code configuration.
- Signed exported reports.
- Canary metric ingestion.
- Approval and exception audit trail.

---

## 27. FAQ

### Does ReleaseGuard execute submitted code?

No. All evidence is parsed as text or structured data.

### Does the app call npm audit?

No. It imports a report that the user provides. Generating an npm audit report
is outside ReleaseGuard and may communicate with a configured npm registry.

### Does a privacy route prove data left the application?

No. It is a static candidate based on source, import, and lockfile structure.
Validate the actual payload and destination at runtime.

### Does a changed transitive dependency always create a security finding?

No. The app lists changed packages and adds security findings for stronger
signals such as a source requiring review, absent integrity metadata, or an
install script.

### Why are raw registry URLs omitted?

URLs can include sensitive internal infrastructure details or embedded
credentials. The report returns safe source categories instead.

### Why are integrity hashes omitted?

They are not needed to explain a release decision and can be noisy or sensitive
to expose in a broadly shared report.

### What makes the demo return HOLD?

The synthetic bundle deliberately combines high-risk code, a destructive
migration, network evidence, npm audit evidence, and a privacy-route candidate.

### Is ReleaseGuard a compliance tool?

No. It is a release-review aid. It can help teams identify evidence that merits
privacy, security, or legal review.

---

## 28. Source map

| File | Primary responsibility |
| --- | --- |
| engine.py | Patch, coverage, incidents, static rules, score, decision, report assembly |
| security_evidence.py | Network metadata and npm audit parsing |
| dependency_evidence.py | Lockfile graph comparison and privacy route candidates |
| server.py | HTTP API, static assets, request limits, headers |
| web/index.html | Upload controls and report shell |
| web/app.js | Browser state, API requests, tab rendering, report export |
| web/style.css | Responsive presentation |
| web/demo.json | Synthetic all-evidence demo |
| test_dependency_evidence.py | Regression tests for evidence integration |
| README.md | Short setup guide |
| info.md | Detailed project reference |

### Main engine functions

| Function | Role |
| --- | --- |
| parse_patch | Validate and parse unified diffs |
| coverage_index | Build changed-line coverage evidence |
| incident_index | Validate and normalize incident CSV |
| classify | Add risk tags to changed files |
| assess | Combine all evidence into the final advisory |

### Security evidence functions

| Function | Role |
| --- | --- |
| review_flows | Validate sanitized network metadata and emit findings |
| review_npm_audit | Validate imported npm audit evidence and emit findings |

### Dependency evidence functions

| Function | Role |
| --- | --- |
| read_lock | Validate and normalize npm package-lock graph input |
| resolve | Resolve nested or hoisted node_modules dependency target |
| reachable | Build parent map from root package nodes |
| dependency_changes | Identify release graph additions and updates |
| candidate_privacy_routes | Link changed source candidates to changed descendants |
| review_dependencies | Build safe dependency summary, privacy routes, and findings |

---

## Closing perspective

ReleaseGuard is most useful when it starts a better release conversation.

    What changed?
    Which changed lines lack evidence?
    Which operational areas have failed before?
    Is personal data potentially reaching a changed dependency chain?
    Is transport appropriately classified?
    Are audit findings direct or transitive?
    What needs to be true before this can safely roll out?
    Who can roll it back?

The project does not manufacture certainty from static inputs. It collects
useful signals, states their limits, and gives a release owner an explainable
reason to proceed, canary, or pause.
