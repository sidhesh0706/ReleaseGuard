# ReleaseGuard

ReleaseGuard is a local deployment review workspace built by Team LLmborghini for Agent Forge. Give it a code diff and, when available, line coverage and incident history. It returns a GO, CANARY, or HOLD recommendation with the evidence behind the score and a rollback checklist.

## Run locally

Use Python 3.10 or later. The app has no third-party Python dependencies.

```sh
python server.py
```

Open [http://127.0.0.1:8765](http://127.0.0.1:8765) and select **Load checkout demo**, then **Run assessment**. The synthetic release returns **HOLD**. Browse **Changed files**, **Findings**, and **Rollback**, then select **Export report** for the JSON advisory.

## Inputs and decisions

| Input | Format | How it is used |
| --- | --- | --- |
| Code diff | Unified diff or Git patch | Identifies changed paths and added lines, classifies changes, and scans for selected security and privacy signals |
| Test coverage | LCOV or coverage.py JSON | Matches covered and missed lines against new-file line numbers in the diff |
| Incident history | CSV with `id,module,severity` | Matches incident module paths to changed files |

Each input can be up to 750 KB. Use repository-relative paths in coverage reports from the same revision as the diff. Reported coverage uses the added source lines with coverage evidence as its denominator. Added source lines without matching evidence are counted separately.

The score combines change impact (30 points), test evidence (25), related incidents (15), security (20), and privacy (10). A release gate or score of at least 45 yields HOLD. A score of 15–44, or missing evidence on added source lines, yields CANARY when no HOLD condition applies. Other assessments yield GO. The release owner retains the deployment decision.

The security pass flags selected patterns such as potential credentials, disabled TLS verification, and wildcard CORS. The privacy pass flags selected personal data fields and logging patterns. These are static heuristics. Review findings in context and use dedicated scanners for broader coverage.

The default server listens on loopback, processes uploads in memory, and makes no external calls. Reports include file paths and line numbers plus redacted labels where applicable. They omit raw source lines and matched values.

## API

`GET /api/health` returns service status. `POST /api/assess` accepts JSON with a required `patch` string and optional `coverage` and `incidents` strings. The built-in example bundle is available at `GET /demo.json`.

`server.py` serves the HTTP API and frontend assets. `engine.py` implements parsing, evidence matching, scoring, and advisory generation. `web/` contains the browser interface and the synthetic demo.
