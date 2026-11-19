"""Deterministic release assessment. Inputs are data, never executed."""
import csv
import io
import json
import re
import shlex
from pathlib import PurePosixPath

LIMIT = 750_000
SECRET = re.compile(r"""(?i)\b(?:api[_-]?key|access[_-]?token|client[_-]?secret|password)\s*[:=]\s*["']?([A-Za-z0-9_./+!=@-]{8,})|-----BEGIN [A-Z ]*PRIVATE KEY-----""")
EMAIL = re.compile(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}")
TEST_PATH = re.compile(r"(^|/)(tests?|__tests__)/|(?:^|/)test_[^/]+$|[.](test|spec)[.]")
HUNK_HEADER = re.compile(r"^@@ -\d+(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
SOURCE = {".py", ".js", ".jsx", ".ts", ".tsx", ".go", ".java", ".rb", ".rs", ".php", ".cs", ".kt", ".c", ".cpp", ".swift"}
CAPS = {"Change impact": 30, "Test evidence": 25, "Incident history": 15, "Security": 20, "Privacy": 10}


def safe_label(value):
    return EMAIL.sub("[email redacted]", re.sub(r"[\x00-\x1f\x7f]", "", value))[:180]


def normalized(value):
    return value.replace("\\", "/").removeprefix("./")


def path_from_header(value):
    value = value.split("\t", 1)[0]
    if value.startswith('"'):
        try:
            value = shlex.split(value)[0]
        except (ValueError, IndexError):
            raise ValueError("A patch path could not be parsed.") from None
    return normalized(value.removeprefix("b/") if value.startswith("b/") else value.removeprefix("a/"))


def parse_patch(patch):
    files = {}
    path = git_path = None
    previous = None
    line_number = 0
    old_remaining = new_remaining = 0

    def finish_file():
        if git_path:
            files.setdefault(git_path, {"added": [], "removed": 0})

    for line in patch.splitlines():
        if line.startswith("diff --git "):
            finish_file()
            path = git_path = previous = None
            old_remaining = new_remaining = 0
            try:
                fields = shlex.split(line)
                if len(fields) >= 4:
                    git_path = path_from_header(fields[-1])
            except ValueError:
                continue
        elif path and (old_remaining or new_remaining):
            if line.startswith("+"):
                files[path]["added"].append((line_number, line[1:]))
                line_number += 1
                new_remaining -= 1
            elif line.startswith("-"):
                files[path]["removed"] += 1
                old_remaining -= 1
            elif line.startswith(" "):
                line_number += 1
                old_remaining -= 1
                new_remaining -= 1
            elif not line.startswith("\\ No newline at end of file"):
                raise ValueError("A patch hunk does not match its declared line counts.")
            if old_remaining < 0 or new_remaining < 0:
                raise ValueError("A patch hunk does not match its declared line counts.")
        elif header := HUNK_HEADER.match(line):
            if not path:
                raise ValueError("A patch hunk is missing its file headers.")
            old_remaining = int(header[1] or "1")
            line_number = int(header[2])
            new_remaining = int(header[3] or "1")
        elif line.startswith("--- "):
            previous = path_from_header(line[4:])
        elif line.startswith("+++ ") and previous:
            path = path_from_header(line[4:])
            if path == "/dev/null":
                path = previous
            if path != "/dev/null":
                files.setdefault(path, {"added": [], "removed": 0})
            git_path = previous = None
        elif line.startswith(("rename to ", "copy to ")):
            git_path = normalized(line.split(" to ", 1)[1])
    if old_remaining or new_remaining:
        raise ValueError("A patch hunk ended before all declared lines were read.")
    finish_file()
    if not files:
        raise ValueError("Supply a unified diff or Git patch with at least one changed file.")
    if len(files) > 300:
        raise ValueError("Analyze at most 300 changed files per review.")
    return files


def coverage_index(raw):
    if not raw.strip():
        return {}
    try:
        if raw.lstrip().startswith("{"):
            data = json.loads(raw)
            files = data.get("files")
            if not isinstance(files, dict):
                raise ValueError
            result = {}
            for path, row in files.items():
                covered, missed = row["executed_lines"], row["missing_lines"]
                if not all(isinstance(group, list) and all(type(n) is int and n > 0 for n in group) for group in (covered, missed)):
                    raise ValueError
                result[normalized(path)] = (set(covered), set(missed))
            return result
        results = {}
        path, covered, missed = None, set(), set()
        for line in raw.splitlines():
            if line.startswith("SF:"):
                path = normalized(line[3:])
                covered, missed = set(), set()
            elif line.startswith("DA:") and path:
                number, count, *_ = line[3:].split(",")
                (covered if int(count) > 0 else missed).add(int(number))
            elif line == "end_of_record" and path:
                old_covered, old_missed = results.get(path, (set(), set()))
                results[path] = (old_covered | covered, old_missed | missed)
                path = None
        if not results or path:
            raise ValueError
        return results
    except (ValueError, TypeError, AttributeError, KeyError):
        raise ValueError("Coverage must be LCOV or coverage.py JSON with per-line evidence.") from None


def incident_index(raw):
    if not raw.strip():
        return []
    reader = csv.DictReader(io.StringIO(raw), strict=True)
    incidents = []
    try:
        if not reader.fieldnames or not {"id", "module", "severity"} <= set(reader.fieldnames):
            raise ValueError("Incident CSV requires id, module and severity columns.")
        for row in reader:
            severity = (row["severity"] or "").strip().lower()
            if severity not in {"low", "medium", "high", "critical"}:
                raise ValueError("Incident severity must be low, medium, high or critical.")
            module = normalized((row["module"] or "").strip()).strip("/")
            identifier = (row["id"] or "").strip()
            if not module or not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", identifier):
                raise ValueError("Each incident needs a module path and an ID using letters, numbers, dots, underscores or hyphens.")
            incidents.append((identifier, module, severity))
    except csv.Error:
        raise ValueError("The incident CSV contains an invalid row.") from None
    return incidents


def classify(path, added):
    lower = path.lower()
    name = PurePosixPath(lower).name
    tags = []
    if re.search(r"(^|/)(migrations?|schema)(/|[.])", lower) or name.endswith(".sql"):
        tags.append("Migration")
    if name in {"package.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock", "pyproject.toml", "pom.xml", "go.mod", "cargo.toml", "cargo.lock", "uv.lock", "poetry.lock"} or name.startswith("requirements"):
        tags.append("Dependency")
    if lower.startswith((".github/", "infra/", "deploy/", "k8s/")) or name.startswith((".env", "dockerfile")) or name.endswith((".yaml", ".yml", ".tf", ".toml")):
        tags.append("Configuration")
    if re.search(r"(^|[/_.-])(auth|authn|authz|payments?|checkout|billing|identity|permissions?|crypto)([/_.-]|$)", lower):
        tags.append("Critical path")
    if TEST_PATH.search(lower):
        tags.append("Test")
    if any(re.search(r"\b(?:DROP\s+(?:TABLE|COLUMN|SCHEMA)|TRUNCATE\s+TABLE)\b", code, re.I) for _, code in added) and "Migration" in tags:
        tags.append("Destructive migration")
    return tags or ["Application"]


RULES = [
    ("Security", "critical", "Potential secret in added code", SECRET, "Remove the value, rotate it if it was real, and use a secret manager."),
    ("Security", "high", "TLS verification disabled", re.compile(r"\b(?:verify\s*=\s*False|rejectUnauthorized\s*:\s*false|insecure_skip_verify\s*[:=]\s*true)\b", re.I), "Restore certificate verification and configure a trusted CA."),
    ("Security", "high", "Public network ingress", re.compile(r"\b(?:cidr_blocks|cidr_ip|source_ranges|cidr_ipv4)\b.*0\.0\.0\.0/0|\bcidr:\s*0\.0\.0\.0/0", re.I), "Limit ingress to approved sources and verify the affected port and resource."),
    ("Security", "high", "Unsafe dynamic execution", re.compile(r"\bshell\s*=\s*True\b|\beval\s*\(", re.I), "Review input trust and replace dynamic execution with a constrained parser or explicit arguments."),
    ("Security", "medium", "Wildcard CORS policy", re.compile(r"""(?i)\b(?:allow_origins|allowedOrigins|Access-Control-Allow-Origin)["']?\s*[:=]\s*\[?\s*["']\*["']"""), "Restrict production origins to approved clients."),
    ("Privacy", "high", "Potential personal data in logs", re.compile(r"\b(?:logger|logging|console|log)\.(?:info|debug|warn|warning|error|log)\s*\(.*\b(?:email|phone|address|ssn|customer_data|request\.body)\b", re.I), "Log approved metadata or use field-level redaction before emitting logs."),
    ("Privacy", "medium", "Email-like value in added code", EMAIL, "Verify the value is synthetic or replace it with a generated fixture."),
    ("Privacy", "medium", "Sensitive field added", re.compile(r"\b(?:date_of_birth|national_id|passport_number|aadhaar|social_security_number|biometric_data)\b", re.I), "Verify collection purpose, retention, access controls and deletion handling."),
]


def assess(patch, coverage="", incidents=""):
    files = parse_patch(patch)
    index = coverage_index(coverage)
    inventory = incident_index(incidents)
    findings, changed, matched = [], [], {}
    points = dict.fromkeys(CAPS, 0)
    rules_seen = set()
    blockers = set()
    covered_total = missed_total = unknown_total = 0
    for path, delta in files.items():
        added = delta["added"]
        label = safe_label(path)
        tags = classify(path, added)
        for tag, weight in {"Migration": 9, "Dependency": 5, "Configuration": 5, "Critical path": 9, "Destructive migration": 14}.items():
            if tag in tags and tag not in rules_seen:
                points["Change impact"] += weight
                rules_seen.add(tag)
        if "Destructive migration" in tags:
            blockers.add("Destructive migration requires a verified restore plan.")
            findings.append({"area": "Change impact", "severity": "critical", "title": "Destructive schema change", "file": label, "line": None, "action": "Verify a backup restore and plan a compatible forward migration."})
        covered = missed = unknown = 0
        if PurePosixPath(path.lower()).suffix in SOURCE and "Test" not in tags:
            known_hit, known_miss = index.get(path, (set(), set()))
            for number, code in added:
                if not code.strip() or code.lstrip().startswith(("#", "//", "/*", "*")):
                    continue
                if number in known_hit:
                    covered += 1
                elif number in known_miss:
                    missed += 1
                else:
                    unknown += 1
        covered_total += covered
        missed_total += missed
        unknown_total += unknown
        changed.append({"path": label, "tags": tags, "added": len(added), "removed": delta["removed"], "covered": covered, "missed": missed, "unknown": unknown})
        parts = path.split("/")
        for identifier, module, severity in inventory:
            module_parts = module.split("/")
            if any(parts[i:i + len(module_parts)] == module_parts for i in range(len(parts) - len(module_parts) + 1)):
                key = (identifier, module)
                if key not in matched:
                    matched[key] = {"id": identifier, "module": safe_label(module), "severity": severity}
                    points["Incident history"] += {"critical": 9, "high": 6, "medium": 3, "low": 1}[severity]
        for area, severity, title, pattern, action in RULES:
            matching = next((number for number, code in added if pattern.search(code)), None)
            if matching is None:
                continue
            points[area] += {"critical": 20, "high": 10, "medium": 5}[severity]
            if severity == "critical":
                blockers.add(title + " requires review.")
            findings.append({"area": area, "severity": severity, "title": title, "file": label, "line": matching, "action": action})

    observed = covered_total + missed_total
    percent = round(100 * covered_total / observed) if observed else None
    if missed_total:
        points["Test evidence"] += 5 + round(14 * missed_total / observed)
    if unknown_total:
        points["Test evidence"] += 8
    if len(files) >= 8:
        points["Change impact"] += 5
    if len(findings) > 600:
        findings = findings[:600]
    dimensions = [{"label": name, "points": min(points[name], cap), "max": cap} for name, cap in CAPS.items()]
    score = sum(row["points"] for row in dimensions)
    decision = "HOLD" if blockers or score >= 45 else "CANARY" if score >= 15 else "GO"
    if decision == "GO" and unknown_total:
        decision = "CANARY"
    advisories = {
        "HOLD": "Pause promotion until a release owner resolves or explicitly accepts the evidence below.",
        "CANARY": "Release to a small cohort first and compare health metrics with the baseline.",
        "GO": "Proceed through the standard release process and monitor health after promotion.",
    }
    checklist = [
        "Record the last known-good version and confirm the owner who can trigger rollback.",
        "Set abort thresholds for errors, latency and the affected business metric before rollout.",
        "Restore the last known-good build or configuration if an abort threshold is reached.",
        "Verify recovery with smoke tests and confirm metrics return to baseline.",
    ]
    if any("Migration" in item["tags"] for item in changed):
        checklist.insert(2, "Verify backup restoration and schema compatibility before rolling back an application build.")
    if findings:
        checklist.append("Close or assign the listed findings before full promotion.")
    return {"decision": decision, "score": score, "advisory": advisories[decision], "dimensions": dimensions,
            "files": changed, "coverage": {"percent": percent, "covered": covered_total, "missed": missed_total, "unknown": unknown_total, "supplied": bool(coverage.strip())},
            "incidents": list(matched.values()), "incidents_supplied": bool(incidents.strip()),
            "findings": findings, "blockers": sorted(blockers), "checklist": checklist}
