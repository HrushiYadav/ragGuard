import re

from ragguard.finding import Finding
from ragguard.scanners.base import BaseScanner

_PATTERNS = [
    (
        re.compile(r'''requests\.(?:get|post|put|delete|patch|head)\(\s*f["']'''),
        "HTTP request with f-string URL (potential SSRF)",
    ),
    (
        re.compile(r'''httpx\.(?:get|post|put|delete|patch|head)\(\s*f["']'''),
        "HTTP request with f-string URL (potential SSRF)",
    ),
    (
        re.compile(r'''\.(?:get|post|put|delete|patch)\(\s*f["']'''),
        "HTTP client request with f-string URL (potential SSRF)",
    ),
    (
        re.compile(r'''urlopen\(\s*f["']'''),
        "urlopen with f-string URL (potential SSRF)",
    ),
]


class SSRFScanner(BaseScanner):
    @property
    def name(self) -> str:
        return "SSRF"

    @property
    def category(self) -> str:
        return "ssrf"

    def scan_file(self, file_path: str, content: str, lines: list[str]) -> list[Finding]:
        findings = []
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            for pattern, desc in _PATTERNS:
                if pattern.search(stripped):
                    findings.append(Finding(
                        id="",
                        severity="HIGH",
                        category=self.category,
                        title=f"SSRF: {desc.split('(')[0].strip()}",
                        file_path=file_path,
                        line_number=i,
                        code_snippet=stripped,
                        description=desc,
                        remediation="Validate and allowlist URLs before making server-side requests.",
                        cwe_id="CWE-918",
                    ))
                    break
        return findings
