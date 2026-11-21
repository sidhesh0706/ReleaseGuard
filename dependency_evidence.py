"""Compare npm lockfile evidence and correlate static privacy signals."""
import json
import re
from collections import deque
from itertools import islice
from pathlib import PurePosixPath
from urllib.parse import urlsplit

from security_evidence import EVIDENCE_LIMIT, PACKAGE


FIELDS = ("dependencies", "optionalDependencies", "peerDependencies")
SOURCE_FIELDS = ("resolved", "integrity", "version")
SENSITIVE = re.compile(
    r"\b(email(?:Address|_address)?|(?:customer|user|device|session)[_]?id|phone(?:Number|_number)?|"
    r"aadhaar|ssn|passport(?:Number|_number)?|date[_]?of[_]?birth|national[_]?id)\b", re.I
)
SINK = re.compile(r"\b([a-zA-Z_$][\w$]*)\s*\.\s*(track|capture|identify|send|post|log|setItem)\s*\(")
IMPORT = re.compile(r"""^\s*import\s+(?:\*\s+as\s+)?([\w$]+)\s+from\s+["']([^"']+)["']""")
REQUIRE = re.compile(r"""^\s*(?:const|let|var)\s+([\w$]+)\s*=\s*require\(\s*["']([^"']+)["']""")
ASSIGN = re.compile(r"^\s*(?:(?:const|let|var)\s+)?([\w$]+)\s*=(?!=)")
JS_SUFFIXES = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}


def package_name(value):
    return isinstance(value, str) and len(value) <= 214 and PACKAGE.fullmatch(value)


def declared_names(row, fields):
    result = set()
    for field in fields:
        dependencies = row.get(field, {})
        if not isinstance(dependencies, dict) or not all(package_name(name) for name in dependencies):
            raise ValueError
        result.update(dependencies)
    return result


def installed_name(path):
    prefix = "node_modules/"
    if not path.startswith(prefix):
        return None
    names = path[len(prefix):].split("/node_modules/")
    if not all(package_name(name) for name in names):
        raise ValueError
    return names[-1]


def read_lock(raw):
    """Parse and validate npm package-lock v2/v3 structure and dependency edges."""
    raw = raw.removeprefix("\ufeff")
    try:
        document = json.loads(raw)
        if not isinstance(document, dict) or type(document.get("lockfileVersion")) is not int or document["lockfileVersion"] not in (2, 3):
            raise ValueError
        packages = document.get("packages")
        if not isinstance(packages, dict) or "" not in packages or len(packages) > EVIDENCE_LIMIT:
            raise ValueError
        root = packages[""]
        if not isinstance(root, dict):
            raise ValueError
        nodes = {}
        for path, row in packages.items():
            if not isinstance(row, dict) or len(path) > 1500:
                raise ValueError
            name = installed_name(path)
            if not name:
                continue
            if any(key in row and not isinstance(row[key], str) for key in SOURCE_FIELDS):
                raise ValueError
            if any(key in row and type(row[key]) is not bool for key in ("link", "hasInstallScript")):
                raise ValueError
            declared_names(row, FIELDS)
            if row.get("resolved"):
                urlsplit(row["resolved"])
            nodes[path] = row

        direct = {
            name: "node_modules/" + name
            for name in sorted(declared_names(root, FIELDS + ("devDependencies",)))
            if "node_modules/" + name in nodes
        }
        edges = {}
        edge_count = 0
        for path, row in nodes.items():
            targets = []
            for name in sorted(declared_names(row, FIELDS)):
                target = resolve(path, name, nodes)
                if target:
                    targets.append(target)
            edge_count += len(targets)
            if edge_count > 25_000:
                raise ValueError
            edges[path] = targets
        return nodes, direct, edges
    except (ValueError, TypeError, AttributeError, RecursionError):
        raise ValueError("Supply valid npm package-lock JSON v2/v3 with at most 5,000 entries and 25,000 resolved edges.") from None


def resolve(path, name, nodes):
    while path:
        candidate = path + "/node_modules/" + name
        if candidate in nodes:
            return candidate
        path = path.rpartition("/node_modules/")[0]
    candidate = "node_modules/" + name
    return candidate if candidate in nodes else None


def reachable(roots, edges):
    parents = dict.fromkeys(roots)
    queue = deque(parents)
    while queue:
        path = queue.popleft()
        for child in edges[path]:
            if child not in parents:
                parents[child] = path
                queue.append(child)
    return parents


def chain_for(path, parents):
    chain = []
    while path is not None:
        chain.append(installed_name(path))
        path = parents[path]
    chain.reverse()
    return chain if len(chain) <= 16 else chain[:8] + ["…"] + chain[-8:]


def label_version(value):
    if isinstance(value, str):
        v = value.strip()
        if re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.+-]+)?", v):
            return v[:96]
    return None


def source_category(value):
    if not value or not isinstance(value, str):
        return "Unspecified"
    source = urlsplit(value.strip())
    if source.scheme == "https" and source.hostname and not (source.username or source.password):
        return "HTTPS"
    return "Source requires review"


def dependency_changes(baseline, release):
    old_nodes, old_direct, old_edges = read_lock(baseline)
    nodes, direct, edges = read_lock(release)
    old_reachable = reachable(old_direct.values(), old_edges)
    parents = reachable(direct.values(), edges)
    changes = {}
    for path, parent in parents.items():
        row = nodes[path]
        before = old_nodes.get(path, {})
        if path not in old_reachable:
            change = "added"
        elif any(before.get(field) != row.get(field) for field in SOURCE_FIELDS + ("hasInstallScript", "link")):
            change = "updated"
        else:
            continue
        changes[path] = {
            "name": installed_name(path),
            "version": label_version(row.get("version")),
            "kind": "direct" if parent is None else "transitive",
            "change": change,
            "source": source_category(row.get("resolved")),
            "integrity_present": bool(row.get("integrity", "").strip()),
            "linked": row.get("link", False),
            "install_script": row.get("hasInstallScript", False),
        }
    return changes, direct, edges, parents


def imported_package(specifier):
    segments = specifier.split("/")
    root = "/".join(segments[:2]) if specifier.startswith("@") else segments[0]
    return root if package_name(root) and not root.startswith(".") else None


def candidate_privacy_routes(files, changes, direct, edges, safe_label):
    routes = []
    dependency_paths = {}
    for path, delta in files.items():
        if PurePosixPath(path.lower()).suffix not in JS_SUFFIXES:
            continue
        bindings = {}
        sensitive_variables = set()
        previous_line = None
        for line, code in delta["added"]:
            if previous_line is not None and line != previous_line + 1:
                sensitive_variables.clear()
            previous_line = line
            if code.lstrip().startswith(("//", "/*", "*")):
                continue
            imported = IMPORT.match(code) or REQUIRE.match(code)
            if imported and (package := imported_package(imported[2])) in direct:
                bindings[imported[1]] = package
            assigned = ASSIGN.match(code)
            has_sensitive_field = bool(SENSITIVE.search(code))
            if assigned:
                sensitive_variables.discard(assigned[1])
                if has_sensitive_field:
                    sensitive_variables.add(assigned[1])
            sink = SINK.search(code)
            if not sink or sink[1] not in bindings:
                continue
            sink_arguments = code[sink.end():]
            if not (SENSITIVE.search(sink_arguments) or sensitive_variables.intersection(re.findall(r"[\w$]+", sink_arguments))):
                continue
            package = bindings[sink[1]]
            if package not in dependency_paths:
                if len(dependency_paths) >= 32:
                    raise ValueError("Privacy correlation supports at most 32 distinct package bindings at candidate sinks.")
                parents = reachable([direct[package]], edges)
                descendants = (item for item in changes if item in parents and parents[item] is not None)
                dependency_paths[package] = [chain_for(item, parents) for item in islice(descendants, 5)]
            for chain in dependency_paths[package]:
                routes.append({"file": safe_label(path), "line": line, "sink": sink[2], "chain": chain})
                if len(routes) >= 100:
                    return routes
    return routes


def review_dependencies(baseline, release, files, safe_label):
    if bool(baseline.strip()) != bool(release.strip()):
        raise ValueError("Supply both the baseline and release npm lockfiles.")
    if not baseline.strip():
        return None, [], []
    changes, direct, edges, parents = dependency_changes(baseline, release)
    routes = candidate_privacy_routes(files, changes, direct, edges, safe_label)
    findings = []
    for item in changes.values():
        name = item["name"]
        for applies, severity, title, action in (
            (item["source"] == "Source requires review" and not item["linked"], "high", "Changed package source requires review", "Verify the package comes from an approved HTTPS registry."),
            (not item["integrity_present"] and not item["linked"], "high", "Changed package lacks integrity metadata", "Verify the package artifact and regenerate its integrity metadata."),
            (item["install_script"], "medium", "Changed package declares an install script", "Review lifecycle script behavior before installation."),
        ):
            if applies:
                findings.append({"area": "Security", "severity": severity, "title": title, "file": name,
                                 "line": None, "detail": item["kind"].title() + " dependency",
                                 "action": action})
    for route in routes:
        findings.append({"area": "Privacy", "severity": "high", "title": "Possible personal-data route through a changed dependency chain",
                         "file": route["file"], "line": route["line"], "detail": " → ".join(route["chain"]),
                         "action": "Verify the payload and destination at runtime, then review the named dependency chain."})
    transitive = sum(item["kind"] == "transitive" for item in changes.values())
    preview = [item | {"chain": chain_for(path, parents)} for path, item in islice(changes.items(), 100)]
    summary = {"direct": len(changes) - transitive, "transitive": transitive, "changes": preview}
    return summary, routes, findings
