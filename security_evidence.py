"""Review locally supplied defensive evidence without fetching or executing it."""
import csv
import io
import json
import re


FLOW_FIELDS = {"transport", "destination_scope", "data_class"}
CLEARTEXT = {"http", "ftp", "telnet"}
PROTECTED = {"https", "tls", "sftp", "ssh"}
SCOPES = {"internal", "external", "unknown"}
DATA_CLASSES = {"public", "personal", "credentials", "unknown"}
PACKAGE = re.compile(r"(?:@[a-z0-9_.-]+/)?[a-z0-9_][a-z0-9_.-]*", re.I | re.ASCII)
SEVERITIES = {"info": "low", "low": "low", "moderate": "medium", "high": "high", "critical": "critical"}
EVIDENCE_LIMIT = 5_000


def review_flows(raw):
    if not raw.strip():
        return None, []

    summary = dict.fromkeys(("reviewed", "cleartext", "protected", "unknown_transport", "flagged"), 0)
    findings = []
    try:
        reader = csv.DictReader(io.StringIO(raw, newline=""), strict=True)
        if not reader.fieldnames or len(reader.fieldnames) != len(FLOW_FIELDS) or set(reader.fieldnames) != FLOW_FIELDS:
            raise ValueError("Network CSV requires only transport, destination_scope and data_class columns.")
        for row in reader:
            line = reader.line_num
            if set(row) != FLOW_FIELDS or any(value is None for value in row.values()):
                raise ValueError(f"Network CSV row {line} must contain exactly three values.")
            transport, scope, data_class = (row[key].strip().lower() for key in ("transport", "destination_scope", "data_class"))
            if transport not in CLEARTEXT | PROTECTED | {"unknown"} or scope not in SCOPES or data_class not in DATA_CLASSES:
                raise ValueError(f"Network CSV row {line} contains an unsupported classification.")
            summary["reviewed"] += 1
            if summary["reviewed"] > EVIDENCE_LIMIT:
                raise ValueError("Network CSV may contain at most 5,000 records.")
            transport_class = "cleartext" if transport in CLEARTEXT else "protected" if transport in PROTECTED else "unknown_transport"
            summary[transport_class] += 1
            if data_class not in {"personal", "credentials"} or transport_class == "protected":
                continue
            is_cleartext = transport_class == "cleartext"
            severity = "critical" if data_class == "credentials" and is_cleartext else "high" if is_cleartext else "medium"
            summary["flagged"] += 1
            findings.append({
                "area": "Privacy" if data_class == "personal" else "Security",
                "severity": severity,
                "title": "Sensitive data on cleartext transport" if is_cleartext else "Sensitive data with unverified transport",
                "file": "Network flow metadata",
                "line": line,
                "detail": f"{data_class.title()} · {transport.upper()} · {scope} destination",
                "action": "Verify encryption across the connection and remove unnecessary sensitive fields.",
            })
    except csv.Error:
        raise ValueError("Network evidence must be valid CSV.") from None
    if not summary["reviewed"]:
        raise ValueError("Network evidence must include at least one classified flow.")
    return summary, findings


def review_npm_audit(raw):
    if not raw.strip():
        return None, []

    try:
        data = json.loads(raw)
        if data.get("auditReportVersion") != 2 or "error" in data:
            raise ValueError
        vulnerabilities = data["vulnerabilities"]
        if not isinstance(vulnerabilities, dict) or len(vulnerabilities) > EVIDENCE_LIMIT:
            raise ValueError
        findings = []
        summary = {"direct": 0, "transitive": 0}
        for name, item in vulnerabilities.items():
            if not PACKAGE.fullmatch(name) or len(name) > 214 or type(item["isDirect"]) is not bool:
                raise ValueError
            severity = SEVERITIES[item["severity"]]
            kind = "direct" if item["isDirect"] else "transitive"
            summary[kind] += 1
            findings.append({
                "area": "Security",
                "severity": severity,
                "title": f"npm audit flags a {kind} dependency",
                "file": name,
                "line": None,
                "detail": f"{kind.title()} dependency · imported npm audit evidence",
                "action": "Review the advisory in the original npm audit report, update the dependency chain, and retest.",
            })
    except (ValueError, TypeError, KeyError, AttributeError):
        raise ValueError("Supply a successful npm audit --json report with auditReportVersion 2 and at most 5,000 packages.") from None
    return summary, findings
