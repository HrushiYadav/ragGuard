import re

from ragguard.finding import Finding
from ragguard.scanners.base import BaseScanner

_PATTERNS = [
    # MongoDB: {"payload." + key: value} where value comes from filters dict without validation
    (
        re.compile(r'''["']payload\.\s*["']\s*\+\s*\w+\s*:\s*\w+'''),
        "Filter value passed directly into MongoDB query without type validation",
        "Reject dict values that could contain MongoDB operators ($ne, $gt, $regex).",
        "CWE-943",
    ),
    # Elasticsearch/OpenSearch: {"term": {f"metadata.{key}": value}}
    (
        re.compile(r'''["']term["']\s*:\s*\{.*f["'].*\{.*\}.*["']\s*:\s*\w+\s*\}'''),
        "Filter value passed directly into Elasticsearch term query",
        "Validate that filter values are scalars, not nested query objects.",
        "CWE-943",
    ),
    # Generic: any dict comprehension building query filters from user input
    (
        re.compile(r'''\.append\(\{.*["']payload\.|\.append\(\{.*["']metadata\.'''),
        "User-controlled value appended to query filter conditions without validation",
        "Validate filter values are scalars before constructing query conditions.",
        "CWE-943",
    ),
]

# Check if a validation function exists nearby
_VALIDATION_PATTERN = re.compile(r"_validate_filter|_sanitize|_escape|isinstance.*dict.*raise")


class NoSQLInjectionScanner(BaseScanner):
    @property
    def name(self) -> str:
        return "NoSQL Operator Injection"

    @property
    def category(self) -> str:
        return "nosql-injection"

    def scan_file(self, file_path: str, content: str, lines: list[str]) -> list[Finding]:
        has_validation = bool(_VALIDATION_PATTERN.search(content))
        if has_validation:
            return []

        findings = []
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            for pattern, desc, remediation, cwe in _PATTERNS:
                if pattern.search(stripped):
                    findings.append(Finding(
                        id="",
                        severity="HIGH",
                        category=self.category,
                        title=f"NoSQL injection: {desc.split('.')[0]}",
                        file_path=file_path,
                        line_number=i,
                        code_snippet=stripped,
                        description=desc,
                        remediation=remediation,
                        cwe_id=cwe,
                    ))
                    break
        return findings
