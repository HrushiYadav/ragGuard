import json

from ragguard import __version__
from ragguard.finding import Finding


def write_sarif_report(findings: list[Finding], target: str, output_path: str):
    rules = {}
    results = []

    for f in findings:
        rule_id = f"{f.category}/{f.cwe_id or 'unknown'}"
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": f.title.split(":")[0].strip(),
                "shortDescription": {"text": f.title},
                "defaultConfiguration": {
                    "level": {"HIGH": "error", "MEDIUM": "warning", "LOW": "note"}.get(f.severity, "warning"),
                },
                "helpUri": f"https://cwe.mitre.org/data/definitions/{f.cwe_id.split('-')[1]}.html"
                if f.cwe_id else None,
                "properties": {"tags": ["security"]},
            }

        results.append({
            "ruleId": rule_id,
            "level": {"HIGH": "error", "MEDIUM": "warning", "LOW": "note"}.get(f.severity, "warning"),
            "message": {"text": f.description},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.file_path.replace("\\", "/")},
                    "region": {"startLine": f.line_number, "startColumn": 1},
                }
            }],
            "fixes": [{
                "description": {"text": f.remediation},
            }] if f.remediation else [],
        })

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "RAGGuard",
                    "version": __version__,
                    "informationUri": "https://github.com/HrushiYadav/ragGuard",
                    "rules": list(rules.values()),
                }
            },
            "results": results,
        }],
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(sarif, f, indent=2)
