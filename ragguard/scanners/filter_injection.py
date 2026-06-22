import re

from ragguard.finding import Finding
from ragguard.scanners.base import BaseScanner

# Patterns where user-controlled values are interpolated into filter/query expressions
_PATTERNS = [
    # Milvus/Baidu: f'(metadata["{key}"] == "{value}")'
    (
        re.compile(r'''f['"].*metadata\[.*\{.*\}.*==.*\{.*\}'''),
        "User-controlled value interpolated into metadata filter expression",
        "Validate filter values are primitives and escape quotes before interpolation.",
    ),
    # Valkey/Redis: f'@{key}:{{{value}}}'
    (
        re.compile(r'''f['"].*@\{.*\}:\{\{\{?\w*\}?\}\}'''),
        "User-controlled value interpolated into FT.SEARCH tag query without escaping",
        "Escape Valkey/Redis FT.SEARCH special characters in tag filter values.",
    ),
    # Azure: f"{key} eq '{value}'"
    (
        re.compile(r'''f['"].*\{.*\}\s+eq\s+['\"]?\{.*\}'''),
        "User-controlled value interpolated into OData filter expression",
        "Use parameterized filters or escape single quotes in values.",
    ),
    # Neptune: f'{{equals:{{property: \'{k}\', value: \'{v}\'}}}}'
    (
        re.compile(r'''f['"].*equals.*property.*\{.*\}.*value.*\{.*\}'''),
        "User-controlled value interpolated into graph query filter",
        "Use parameterized queries instead of string interpolation.",
    ),
    # Upstash: f"{k} = {self._stringify(v)}"
    (
        re.compile(r'''f['"].*\{.*\}\s*=\s*\{.*stringify.*\}'''),
        "User-controlled value passed through stringify into filter expression",
        "Validate filter values are safe primitives before interpolation.",
    ),
    # Generic: any f-string building a filter with user value interpolation
    (
        re.compile(r'''f['"].*filter.*\{.*value.*\}|f['"].*\{.*key.*\}.*\{.*value.*\}'''),
        "Possible filter expression injection via f-string interpolation",
        "Validate and escape user-controlled values before building filter expressions.",
    ),
]


class FilterInjectionScanner(BaseScanner):
    @property
    def name(self) -> str:
        return "Filter Expression Injection"

    @property
    def category(self) -> str:
        return "filter-injection"

    def scan_file(self, file_path: str, content: str, lines: list[str]) -> list[Finding]:
        findings = []
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            for pattern, desc, remediation in _PATTERNS:
                if pattern.search(stripped):
                    findings.append(Finding(
                        id="",
                        severity="HIGH",
                        category=self.category,
                        title=f"Filter injection: {desc.split('.')[0]}",
                        file_path=file_path,
                        line_number=i,
                        code_snippet=stripped,
                        description=desc,
                        remediation=remediation,
                        cwe_id="CWE-943",
                    ))
                    break
        return findings
