import re

from ragguard.finding import Finding
from ragguard.scanners.base import BaseScanner

_PATTERNS = [
    # f"INSERT INTO {table} ... VALUES {values}"
    (
        re.compile(r'''f["'].*INSERT\s+INTO\s+.*\{.*\}.*VALUES\s+.*\{.*\}''', re.IGNORECASE),
        "SQL INSERT built via f-string with interpolated values",
        "Use parameterized queries with placeholders instead of f-string interpolation.",
        "CWE-89",
    ),
    # f"DELETE FROM {table} WHERE ..."
    (
        re.compile(r'''f["'].*DELETE\s+FROM\s+.*\{.*\}.*WHERE.*\{.*\}''', re.IGNORECASE),
        "SQL DELETE built via f-string with interpolated values",
        "Use parameterized queries with placeholders instead of f-string interpolation.",
        "CWE-89",
    ),
    # f"SELECT ... FROM {table} WHERE {condition}"
    (
        re.compile(r'''f["'].*SELECT\s+.*FROM\s+.*\{.*\}.*WHERE.*\{.*\}''', re.IGNORECASE),
        "SQL SELECT built via f-string with interpolated values",
        "Use parameterized queries with placeholders instead of f-string interpolation.",
        "CWE-89",
    ),
    # execute(f"...") pattern
    (
        re.compile(r'''\.execute\(\s*f["']'''),
        "SQL query executed via f-string interpolation",
        "Use parameterized queries (execute with %s or ? placeholders).",
        "CWE-89",
    ),
    # f"... SET {col} = {val}" (UPDATE)
    (
        re.compile(r'''f["'].*SET\s+.*\{.*\}\s*=\s*\{.*\}''', re.IGNORECASE),
        "SQL SET clause built via f-string with interpolated values",
        "Use parameterized queries with placeholders instead of f-string interpolation.",
        "CWE-89",
    ),
]


_PARAMETERIZED_RE = re.compile(r"%s|\?")


class SQLInjectionScanner(BaseScanner):
    @property
    def name(self) -> str:
        return "SQL Injection"

    @property
    def category(self) -> str:
        return "sql-injection"

    def scan_file(self, file_path: str, content: str, lines: list[str]) -> list[Finding]:
        findings = []
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            for pattern, desc, remediation, cwe in _PATTERNS:
                if pattern.search(stripped):
                    if _PARAMETERIZED_RE.search(stripped):
                        continue
                    findings.append(Finding(
                        id="",
                        severity="HIGH",
                        category=self.category,
                        title=f"SQL injection: {desc.split('.')[0]}",
                        file_path=file_path,
                        line_number=i,
                        code_snippet=stripped,
                        description=desc,
                        remediation=remediation,
                        cwe_id=cwe,
                    ))
                    break
        return findings
