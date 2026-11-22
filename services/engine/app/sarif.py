from __future__ import annotations


SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"


def to_sarif(scan: dict) -> dict:
    findings = scan.get("findings", [])
    rules: dict[str, dict] = {}
    results = []
    for finding in findings:
        rule_id = finding["rule_id"]
        rules.setdefault(rule_id, {
            "id": rule_id,
            "name": rule_id,
            "shortDescription": {"text": finding.get("title", rule_id)},
            "fullDescription": {"text": finding.get("remediation", "Review the privacy finding.")},
            "defaultConfiguration": {"level": {
                "critical": "error", "high": "error", "medium": "warning", "low": "note"
            }.get(finding.get("severity", "low"), "warning")},
            "help": {"text": finding.get("remediation", "Review this finding.")},
            "properties": {"dpdpSection": finding.get("dpdp_section")},
        })
        physical = {
            "artifactLocation": {"uri": finding["file"], "uriBaseId": "%SRCROOT%"},
            "region": {"startLine": max(1, int(finding.get("line", 1)))},
        }
        result = {
            "ruleId": rule_id,
            "ruleIndex": list(rules).index(rule_id),
            "level": {"critical": "error", "high": "error", "medium": "warning", "low": "note"}.get(finding.get("severity", "low"), "warning"),
            "message": {"text": f"{finding.get('title', rule_id)} ({finding.get('pii_category', 'personal data')}; {finding.get('dpdp_section', 'DPDP')})"},
            "locations": [{"physicalLocation": physical}],
            "partialFingerprints": {"primaryLocationLineHash": finding.get("id", "")},
            "properties": {"severity": finding.get("severity"), "dpdpSection": finding.get("dpdp_section"), "piiCategory": finding.get("pii_category")},
        }
        results.append(result)
    driver = {"name": "PrivacyLint", "semanticVersion": "0.1.0", "rules": list(rules.values())}
    run = {"tool": {"driver": driver}, "results": results}
    if scan.get("scan_hash"):
        run["properties"] = {"scanHash": scan["scan_hash"], "riskScore": scan.get("score"), "grade": scan.get("grade")}
    return {"$schema": SARIF_SCHEMA, "version": SARIF_VERSION, "runs": [run]}
