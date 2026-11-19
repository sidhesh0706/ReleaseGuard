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
DATA_CATEGORIES = (
    ("Email address", re.compile(r"\b(?:e[-_]?mail|email_address)\b", re.I)),
    ("Phone number", re.compile(r"\b(?:phone|mobile|telephone|msisdn)\b", re.I)),
    ("Government ID", re.compile(r"\b(?:aadhaar|ssn|social[_-]?security|passport|national[_-]?id)\b", re.I)),
    ("Payment data", re.compile(r"\b(?:card[_-]?(?:number|token)|cvv|iban|bank[_-]?account)\b", re.I)),
    ("Date of birth", re.compile(r"\b(?:date[_-]?of[_-]?birth|dob|birthdate)\b", re.I)),
    ("Location", re.compile(r"\b(?:address|latitude|longitude|postal[_-]?code|zip[_-]?code|geo(?:location)?)\b", re.I)),
    ("Persistent identifier", re.compile(r"\b(?:user[_-]?id|customer[_-]?id|device[_-]?id|session[_-]?id|cookie|ip[_-]?address)\b", re.I)),
)
PRIVACY_SINKS = (
    ("Analytics or telemetry", "external", re.compile(r"\b(?:analytics|telemetry|segment|mixpanel|amplitude|posthog|heap|fullstory|hotjar)\b|\b(?:track|capture|identify)\s*\(", re.I)),
    ("External network request", "external", re.compile(r"\b(?:fetch|axios(?:\.[A-Za-z_]\w*)?|requests\.(?:get|post|put|patch|delete|request)|httpx\.(?:get|post|put|patch|delete|request)|urllib\.\w+|https?\.request)\s*\(", re.I)),
    ("Application log", "log", re.compile(r"\b(?:logger|logging|console|log)\.(?:info|debug|warn|warning|error|log)\s*\(", re.I)),
    ("Browser storage", "storage", re.compile(r"\b(?:localStorage|sessionStorage)\.setItem\s*\(|\bdocument\.cookie\b", re.I)),
)


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

    def require_complete_hunk():
        if old_remaining or new_remaining:
            raise ValueError("A patch hunk ended before all declared lines were read.")

    def finish_file():
        if git_path:
            files.setdefault(git_path, {"added": [], "removed": 0})

    for line in patch.splitlines():
        if line.startswith("diff --git "):
            require_complete_hunk()
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
            require_complete_hunk()
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
    require_complete_hunk()
    finish_file()
    if not files:
        raise ValueError("Supply a unified diff or Git patch with at least one changed file.")
    if len(files) > 300:
        raise ValueError("Analyze at most 300 changed files per review.")
    return files


def npm_lock_index(raw):
    """Read npm package-lock v2/v3 as a local dependency graph."""
    try:
        data = json.loads(raw)
        if not isinstance(data, dict) or data.get("lockfileVersion") not in {2, 3}:
            raise ValueError
        packages = data.get("packages")
        if not isinstance(packages, dict) or "" not in packages:
            raise ValueError
        nodes = {}
        for path, row in packages.items():
            if not isinstance(path, str) or not isinstance(row, dict):
                raise ValueError
            if path == "" or "node_modules/" not in path:
                continue
            name = row.get("name") or path.rsplit("node_modules/", 1)[-1]
            version = row.get("version")
            if not isinstance(name, str) or not isinstance(version, str):
                continue
            nodes[path] = {"name": name, "version": version, "integrity": row.get("integrity"),
                           "resolved": row.get("resolved"), "link": row.get("link") is True,
                           "install_script": row.get("hasInstallScript") is True, "row": row}

        def resolve(parent, name):
            cursor = parent
            while cursor:
                candidate = cursor + "/node_modules/" + name if cursor else "node_modules/" + name
                if candidate in nodes:
                    return candidate
                cursor = cursor.rsplit("/node_modules/", 1)[0] if "/node_modules/" in cursor else ""
            candidate = "node_modules/" + name
            return candidate if candidate in nodes else None

        root = packages[""]
        if not isinstance(root, dict):
            raise ValueError
        direct_names = set()
        for field in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
            value = root.get(field, {})
            if not isinstance(value, dict):
                raise ValueError
            direct_names.update(value)
        paths = {}
        queue = []
        for name in sorted(direct_names):
            node_path = resolve("", name)
            if node_path:
                paths[node_path] = [nodes[node_path]["name"]]
                queue.append(node_path)
        cursor = 0
        while cursor < len(queue):
            parent_path = queue[cursor]
            cursor += 1
            parent_row = nodes[parent_path]["row"]
            child_names = set()
            for field in ("dependencies", "optionalDependencies", "peerDependencies"):
                value = parent_row.get(field, {})
                if isinstance(value, dict):
                    child_names.update(value)
            for name in sorted(child_names):
                child_path = resolve(parent_path, name)
                if child_path and child_path not in paths:
                    paths[child_path] = paths[parent_path] + [nodes[child_path]["name"]]
                    queue.append(child_path)
        return {path: {key: node[key] for key in ("name", "version", "integrity", "resolved", "link", "install_script")}
                | {"chain": paths.get(path, [node["name"]]), "reachable": path in paths}
                for path, node in nodes.items()}
    except (ValueError, TypeError, AttributeError, json.JSONDecodeError):
        raise ValueError("Dependency comparison requires npm package-lock JSON version 2 or 3.") from None


def compare_npm_locks(baseline, release):
    before, after = npm_lock_index(baseline), npm_lock_index(release)
    changes = []
    for path, current in after.items():
        previous = before.get(path)
        if previous is None:
            change = "added"
        elif (previous["version"] != current["version"] or previous["resolved"] != current["resolved"]
              or previous["integrity"] != current["integrity"] or previous["link"] != current["link"]
              or previous["install_script"] != current["install_script"]):
            change = "updated"
        else:
            continue
        if current["reachable"]:
            changes.append({"change": change, "name": current["name"], "version": current["version"],
                            "from_version": previous["version"] if previous else None,
                            "kind": "direct" if len(current["chain"]) == 1 else "transitive",
                            "chain": current["chain"], "integrity": bool(current["integrity"]),
                            "resolved": current["resolved"] or "", "link": current["link"],
                            "install_script": current["install_script"]})
    return changes


def package_key(value):
    return re.sub(r"[^a-z0-9]+", "", value.lower())


def dependency_keys(value):
    value = value.lower().replace("\\", "/")
    candidates = {value}
    if "/" in value:
        candidates.add(value.rsplit("/", 1)[-1])
    if "." in value:
        candidates.add(value.split(".", 1)[0])
    return {package_key(candidate) for candidate in candidates if candidate}


def dependency_capability(name):
    lower = name.lower()
    if re.search(r"(?:session[-_]?replay|replay|fullstory|hotjar)", lower):
        return "Session replay"
    if re.search(r"(?:analytics|telemetry|tracking|tracker|segment|amplitude|mixpanel|posthog|pixel)", lower):
        return "Analytics or telemetry"
    if re.search(r"(?:observability|monitoring|metrics|sentry|datadog|logging)", lower):
        return "Observability"
    return "Unclassified"


def added_import_bindings(added):
    """Map added local import names to their package/module names."""
    bindings = {}

    def add(alias, module):
        if not module.startswith(".") and re.fullmatch(r"[A-Za-z_$][\w$]*", alias):
            bindings[alias] = module

    for _, code in added:
        if match := re.match(r"\s*from\s+([A-Za-z0-9_.-]+)\s+import\s+(.+)$", code):
            module = match[1]
            for item in match[2].split(","):
                local = re.split(r"\s+as\s+", item.strip())[-1].strip()
                add(local, module)
            continue
        if match := re.match(r"\s*import\s+([A-Za-z0-9_.-]+)(?:\s+as\s+([A-Za-z_$][\w$]*))?", code):
            module, alias = match[1], match[2] or match[1].split(".", 1)[0]
            add(alias, module)
            continue
        if match := re.match(r"""\s*import\s+(.+?)\s+from\s+["']([^"']+)["']""", code):
            specifier, module = match[1].strip(), match[2]
            if specifier.startswith("{") and "}" in specifier:
                for item in specifier[1:specifier.index("}")].split(","):
                    local = re.split(r"\s+as\s+", item.strip())[-1].strip()
                    add(local, module)
            elif specifier.startswith("* as "):
                add(specifier.removeprefix("* as ").strip(), module)
            else:
                add(specifier.split(",", 1)[0].strip(), module)
            continue
        if match := re.match(r"""\s*(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*require\(\s*["']([^"']+)["']""", code):
            add(match[1], match[2])
    return bindings


def categories_in(code):
    return {label for label, pattern in DATA_CATEGORIES if pattern.search(code)}


def sink_in(code):
    return next(((label, kind) for label, kind, pattern in PRIVACY_SINKS if pattern.search(code)), None)


def assigned_variable(code):
    match = re.match(r"\s*(?:(?:const|let|var)\s+)?([A-Za-z_$][\w$]*)\s*=(?!=)", code)
    return match[1] if match else None


def referenced_modules(code, bindings):
    return {module for alias, module in bindings.items()
            if re.search(r"(?<![\w$])" + re.escape(alias) + r"(?![\w$])", code)}


def matching_direct_dependencies(module, changes):
    module_keys = dependency_keys(module)
    return [change for change in changes
            if change["kind"] == "direct" and module_keys & dependency_keys(change["name"])]


def dependency_summary(change):
    return {"name": change["name"], "version": change["version"], "change": change["change"],
            "capability": dependency_capability(change["name"]), "integrity": change["integrity"],
            "install_script": change["install_script"]}


def sniff_privacy(files, dependency_changes):
    """Find static personal-data-to-sink evidence and connect it to changed npm paths."""
    sources, internal_flows, routes = [], [], []
    source_seen, route_seen = set(), set()
    categories = set()

    for path in sorted(files):
        added = files[path]["added"]
        bindings = added_import_bindings(added)
        sensitive_variables = {}
        for number, code in added:
            stripped = code.strip()
            if not stripped or stripped.startswith(("#", "//", "/*", "*")):
                continue
            line_categories = categories_in(code)
            categories.update(line_categories)
            for category in line_categories:
                key = (path, number, category)
                if key not in source_seen:
                    source_seen.add(key)
                    sources.append({"category": category, "file": safe_label(path), "line": number})
            if line_categories and (variable := assigned_variable(code)):
                sensitive_variables.setdefault(variable, set()).update(line_categories)

            sink = sink_in(code)
            if not sink:
                continue
            inferred_categories = set()
            for variable, variable_categories in sensitive_variables.items():
                if re.search(r"(?<![\w$])" + re.escape(variable) + r"(?![\w$])", code):
                    inferred_categories.update(variable_categories)
            flow_categories = line_categories | inferred_categories
            if not flow_categories:
                continue
            label, kind = sink
            internal_flows.append({
                "categories": sorted(flow_categories), "sink": label, "sink_kind": kind,
                "file": safe_label(path), "line": number,
                "evidence": "Direct field reference" if line_categories else "Inferred through a changed variable",
                "modules": referenced_modules(code, bindings),
            })

    for flow in internal_flows:
        for module in flow["modules"]:
            for direct in matching_direct_dependencies(module, dependency_changes):
                transitive = [dependency_summary(change) for change in dependency_changes
                              if change["kind"] == "transitive" and change["chain"][0] == direct["name"]]
                key = (flow["file"], flow["line"], direct["name"])
                if key in route_seen:
                    continue
                route_seen.add(key)
                routes.append({
                    "categories": flow["categories"], "sink": flow["sink"], "sink_kind": flow["sink_kind"],
                    "file": flow["file"], "line": flow["line"], "evidence": flow["evidence"],
                    "dependency": dependency_summary(direct), "transitive": transitive,
                    "confidence": "Inferred from a changed import used at the observed data sink.",
                })

    routes.sort(key=lambda route: (route["file"], route["line"], route["dependency"]["name"]))
    linked_transitive = {(item["name"], item["version"]) for route in routes for item in route["transitive"]}
    external_flows = [flow for flow in internal_flows if flow["sink_kind"] == "external"]
    release_gate = any(
        route["sink_kind"] == "external" and route["transitive"]
        and (route["dependency"]["capability"] != "Unclassified"
             or any(item["capability"] != "Unclassified" for item in route["transitive"]))
        for route in routes
    )
    score = len(categories) * 5
    score += sum({"external": 28, "storage": 18, "log": 8}[flow["sink_kind"]] for flow in internal_flows)
    score += 10 * len(routes) + 6 * len(linked_transitive)
    if release_gate:
        score = max(score, 85)
    if release_gate:
        level = "critical"
    elif external_flows:
        level = "high"
    elif internal_flows:
        level = "moderate"
    elif sources:
        level = "contained"
    else:
        level = "clear"
    flows = [{key: value for key, value in flow.items() if key != "modules"} for flow in internal_flows]
    return {
        "level": level, "score": min(score, 100), "categories": sorted(categories), "sources": sources,
        "flows": flows, "routes": routes, "release_gate": release_gate,
        "gate_reason": ("A sensitive-data sink is statically linked to a changed dependency chain with "
                        "a data-oriented package name.") if release_gate else None,
        "summary": {"signals": len(sources), "flows": len(flows), "routes": len(routes),
                    "linked_transitive": len(linked_transitive)},
    }


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


def assess(patch, coverage="", incidents="", baseline_lock="", release_lock=""):
    files = parse_patch(patch)
    index = coverage_index(coverage)
    inventory = incident_index(incidents)
    if bool(baseline_lock.strip()) != bool(release_lock.strip()):
        raise ValueError("Supply both baseline and release npm lockfiles to compare dependencies.")
    dependency_changes = compare_npm_locks(baseline_lock, release_lock) if baseline_lock.strip() else []
    privacy_radar = sniff_privacy(files, dependency_changes)
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

    for flow in privacy_radar["flows"]:
        if flow["sink_kind"] == "external":
            points["Privacy"] += 10
            findings.append({"area": "Privacy", "severity": "high", "title": "Personal data reaches a network or telemetry sink",
                             "file": flow["file"], "line": flow["line"],
                             "action": "Minimize the payload, verify consent and processor approval, and confirm the destination is approved."})
        elif flow["sink_kind"] == "storage":
            points["Privacy"] += 5
            findings.append({"area": "Privacy", "severity": "medium", "title": "Personal data persists in browser storage",
                             "file": flow["file"], "line": flow["line"],
                             "action": "Avoid browser storage for personal data or encrypt, expire and scope it to the active session."})
        elif flow["sink_kind"] == "log":
            points["Privacy"] += 5
            findings.append({"area": "Privacy", "severity": "medium", "title": "Personal data reaches application logs",
                             "file": flow["file"], "line": flow["line"],
                             "action": "Redact the fields before logging and verify retention and access controls."})
    if privacy_radar["release_gate"]:
        blockers.add("A candidate personal-data route reaches a changed transitive dependency chain.")
        findings.append({"area": "Privacy", "severity": "critical",
                         "title": "Privacy blast radius crosses a changed transitive dependency",
                         "file": privacy_radar["routes"][0]["file"], "line": privacy_radar["routes"][0]["line"],
                         "action": "Verify data minimization, consent, vendor approval and the full dependency chain before promotion."})

    for change in dependency_changes:
        if change["install_script"]:
            points["Security"] += 5
            findings.append({"area": "Security", "severity": "medium", "title": "Changed package declares an install script",
                             "file": change["name"] + "@" + change["version"], "line": None,
                             "action": "Review the package lifecycle script and approve its build-time behavior before installation."})
        if not change["integrity"] and not change["link"]:
            points["Security"] += 10
            findings.append({"area": "Security", "severity": "high", "title": "Changed package has no integrity hash",
                             "file": change["name"] + "@" + change["version"], "line": None,
                             "action": "Regenerate the lockfile with integrity metadata and verify the resolved artifact."})
        if change["resolved"] and not change["resolved"].startswith("https://"):
            points["Security"] += 10
            findings.append({"area": "Security", "severity": "high", "title": "Changed package uses a non-HTTPS source",
                             "file": change["name"] + "@" + change["version"], "line": None,
                             "action": "Verify the source is an approved internal registry or replace it with an HTTPS registry source."})

    observed = covered_total + missed_total
    eligible = observed + unknown_total
    percent = round(100 * covered_total / eligible) if eligible else None
    if missed_total:
        points["Test evidence"] += 5 + round(14 * missed_total / observed)
    if unknown_total:
        points["Test evidence"] += 8
    if len(files) >= 8:
        points["Change impact"] += 5
    high_findings = any(item["severity"] in {"high", "critical"} for item in findings)
    if len(findings) > 600:
        findings = findings[:600]
    dimensions = [{"label": name, "points": min(points[name], cap), "max": cap} for name, cap in CAPS.items()]
    score = sum(row["points"] for row in dimensions)
    decision = "HOLD" if blockers or score >= 45 else "CANARY" if score >= 15 or unknown_total or high_findings else "GO"
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
            "files": changed, "coverage": {"percent": percent, "covered": covered_total, "missed": missed_total, "unknown": unknown_total,
                                             "eligible": eligible, "matched": observed, "supplied": bool(coverage.strip())},
            "incidents": list(matched.values()), "incidents_supplied": bool(incidents.strip()),
            "dependency_changes": dependency_changes, "dependency_comparison_supplied": bool(baseline_lock.strip()),
            "privacy_radar": privacy_radar,
            "findings": findings, "blockers": sorted(blockers), "checklist": checklist}
