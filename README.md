# ReleaseGuard

ReleaseGuard is a local deployment review workspace built by Team LLmborghini for Agent Forge. Give it a code diff and, when available, line coverage and incident history. It returns a GO, CANARY, or HOLD recommendation with the evidence behind the score and a rollback checklist.

## Run locally

Use Python 3.10 or later. The app has no third-party Python dependencies.

```sh
python server.py
```

Open [http://127.0.0.1:8765](http://127.0.0.1:8765) and select **Load checkout demo**, then **Run assessment**. The synthetic release returns **HOLD**. Browse **Changed files**, **Findings**, and **Rollback**, then select **Export report** for the JSON advisory.

### PyCharm

Open the root `ReleaseGuard` folder using **File → Open**. Select the existing interpreter at `.venv/Scripts/python.exe` on Windows or `.venv/bin/python` on macOS and Linux. If you cloned the project elsewhere, create the virtual environment first with `python -m venv .venv`. Select **ReleaseGuard** in the run configuration dropdown and click **Run**. You can also right-click `server.py` and select **Run 'server'**.

## Inputs and decisions

| Input | Format | How it is used |
| --- | --- | --- |
| Code diff | Unified diff or Git patch | Identifies changed paths and added lines, classifies changes, and scans for selected security and privacy signals |
| Test coverage | LCOV or coverage.py JSON | Matches covered and missed lines against new-file line numbers in the diff |
| Incident history | CSV with `id,module,severity` | Matches incident module paths to changed files |
| Network flow metadata | CSV with `transport,destination_scope,data_class` | Flags cleartext or unverified transport on flows classified as personal data or credentials |
| npm audit report | `npm audit --json` report version 2 | Imports scanner findings and distinguishes direct and transitive packages |
| npm lockfile comparison | Baseline and release `package-lock.json` v2/v3 | Traces added or updated packages reachable from root dependencies and reviews source and integrity metadata |

Each input can be up to 750 KB. Use repository-relative paths in coverage reports from the same revision as the diff. Reported coverage uses the added source lines with coverage evidence as its denominator. Added source lines without matching evidence are counted separately.

### Defensive evidence

Provide only classified network flow metadata from your own monitoring workflow. Supported transports are `http`, `ftp`, `telnet`, `https`, `tls`, `sftp`, `ssh`, and `unknown`. Destination scopes are `internal`, `external`, and `unknown`. Data classes are `public`, `personal`, `credentials`, and `unknown`. ReleaseGuard evaluates the declared classifications and exports only category labels and CSV row numbers.

Import an existing npm audit report for the release revision. Use **Security evidence** to see the direct and transitive package totals, then **Findings** for remediation. The bundled demo uses synthetic flow metadata and a synthetic npm advisory. ReleaseGuard analyzes those inputs offline. If you generate an audit report using npm, npm sends dependency information to the configured registry.

Supply both npm lockfiles to enable **Privacy routes**. Candidates link added JavaScript or TypeScript imports and sensitive field references to a supported sink and a changed transitive dependency. The analysis handles default, namespace and simple CommonJS imports with direct field references or simple assignments in contiguous added lines. Validate inferred routes at runtime. Lockfile export includes package names, dependency paths, version labels, and source classifications. It omits resolved URLs and integrity hashes. The comparison covers root-reachable installed packages and reports additions and updates. npm workspaces, unresolved packages, and removed packages are outside this comparison.

The score combines change impact (30 points), test evidence (25), related incidents (15), security (20), and privacy (10). A release gate or score of at least 45 yields HOLD. A score of 15–44, missing evidence on added source lines, or a high-severity finding yields CANARY when no HOLD condition applies. Other assessments yield GO. The release owner retains the deployment decision.

The security pass flags selected patterns such as potential credentials, disabled TLS verification, and wildcard CORS. The privacy pass flags selected personal data fields and logging patterns. These are static heuristics. Review findings in context and use dedicated scanners for broader coverage.

The default server listens on loopback, processes uploads in memory, and makes no external calls. Reports include file paths and line numbers plus redacted labels where applicable. They omit raw source lines and matched values.

## API

`GET /api/health` returns service status. `POST /api/assess` accepts JSON with a required `patch` string, optional `coverage`, `incidents`, `network_flows`, and `npm_audit` strings, and an optional pair of `baseline_lock` and `release_lock` strings. The built-in example bundle is available at `GET /demo.json`.

`server.py` serves the HTTP API and frontend assets. `engine.py` implements parsing, evidence matching, scoring, and advisory generation. `security_evidence.py` reviews network and npm audit evidence. `web/` contains the browser interface and the synthetic demo.
