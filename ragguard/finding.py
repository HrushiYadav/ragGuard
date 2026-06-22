from dataclasses import dataclass


@dataclass
class Finding:
    id: str
    severity: str
    category: str
    title: str
    file_path: str
    line_number: int
    code_snippet: str
    description: str
    remediation: str
    cwe_id: str | None = None
