# ReleaseGuard

ReleaseGuard is a local deployment review workspace built by Team LLmborghini for Agent Forge. Give it a code diff and, when available, line coverage and incident history. It returns a GO, CANARY, or HOLD recommendation with the evidence behind the score and a rollback checklist.

## Run locally

Use Python 3.10 or later. The app has no third-party Python dependencies.

```sh
python server.py
```

Open [http://127.0.0.1:8765](http://127.0.0.1:8765) and select **Load checkout demo**, then **Run assessment**. The synthetic release returns **HOLD**. Open **Privacy radar** to see a candidate path from an email field to a changed telemetry package and its transitive session-replay runtime.

## Inputs and decisions

| Input | Format | How it is used |
| --- | --- | --- |
| Code diff | Unified diff or Git patch | Identifies changed paths and added lines, classifies changes, and scans for selected security and privacy signals |
| Test coverage | LCOV or coverage.py JSON | Matches covered and missed lines against new-file line numbers in the diff |
| Incident history | CSV with `id,module,severity` | Matches incident module paths to changed files |
| npm dependency comparison | Baseline and release `package-lock.json` v2/v3 | Compares reachable direct and transitive package changes, artifact integrity/source signals, and their connection to privacy-sensitive code |

Each artifact can be up to 750 KB. Use repository-relative paths in coverage reports from the same revision as the diff. Coverage percentage uses all added source lines as its denominator; the report separates covered, missed and unknown lines. Unknown lines have no matching coverage record.

For npm supply-chain review, optionally provide both the baseline and release `package-lock.json` files. ReleaseGuard compares npm lockfile versions 2 and 3 locally, traces reachable added or updated packages back to direct dependencies, and reports missing integrity hashes, non-HTTPS sources, and changed install scripts. It does not contact a registry or vulnerability feed, so this is dependency change control rather than CVE detection. Review flagged package changes and use a dedicated software composition analysis service for vulnerability and license checks.

## Privacy Blast Radius

Privacy Blast Radius is a static, local correlation feature. It recognizes selected personal-data field names in added code, looks for an added call to a configured sink such as telemetry, network requests, logs or browser storage, then follows an added import into the changed npm dependency graph. The report renders a candidate route such as:

`Email address → Analytics or telemetry → checkout-telemetry → session-replay-runtime`

The first two steps are observed static evidence; the dependency connection is labelled as an inference from the changed import and lockfile. It never claims to prove runtime transmission or inspect package source. A HOLD gate is raised only when personal data reaches a network or telemetry sink through a changed, data-oriented dependency chain. That tells the release owner to verify payload minimization, consent, vendor approval and the full package chain before promotion.

The score combines change impact (30 points), test evidence (25), related incidents (15), security (20), and privacy (10). A release gate or score of at least 45 yields HOLD. A score of 15–44, missing evidence on added source lines, or any high/critical finding yields CANARY when no HOLD condition applies. Other assessments yield GO. The release owner retains the deployment decision.

The security pass flags selected patterns such as potential credentials, disabled TLS verification, and wildcard CORS. The privacy pass flags selected personal-data fields and their candidate routes to telemetry, network, logging and browser-storage sinks. These are static heuristics. Review findings in context and use dedicated scanners for broader coverage.

The default server listens on loopback, processes uploads in memory, and makes no external calls. Reports include file paths and line numbers plus redacted labels where applicable. They omit raw source lines and matched values.

## API

`GET /api/health` returns service status. `POST /api/assess` accepts JSON with a required `patch` string, optional `coverage` and `incidents` strings, and optional `baseline_lock` and `release_lock` strings (both required together). The built-in example bundle is available at `GET /demo.json`.

`server.py` serves the HTTP API and frontend assets. It binds to loopback by default; it has no authentication, so do not expose it to an untrusted network without adding access controls. `engine.py` implements parsing, evidence matching, privacy path correlation, npm lockfile comparison, scoring, and advisory generation. `web/` contains the browser interface and the synthetic demo.

Regression tests use only the Python standard library and can be run with `python -m unittest`.
