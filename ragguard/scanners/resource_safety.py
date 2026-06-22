import re

from ragguard.finding import Finding
from ragguard.scanners.base import BaseScanner

_PATTERNS = [
    # pickle.load / pickle.loads on untrusted data
    (
        re.compile(r"pickle\.loads?\("),
        "Deserialization of untrusted data via pickle",
        "Use safe deserialization formats (JSON, msgpack) instead of pickle for untrusted data.",
        "CWE-502",
        "HIGH",
    ),
    # zipfile without size limit
    (
        re.compile(r"zipfile\.ZipFile\("),
        "ZIP file extraction without apparent size validation",
        "Check uncompressed sizes before extraction to prevent zip bomb attacks.",
        "CWE-409",
        "MEDIUM",
    ),
    # tarfile.open
    (
        re.compile(r"tarfile\.open\("),
        "TAR file extraction (potential path traversal and zip bomb)",
        "Validate member paths and sizes before extraction. Use data_filter on Python 3.12+.",
        "CWE-409",
        "MEDIUM",
    ),
    # file.read() without size limit (in upload/import contexts)
    (
        re.compile(r"\.read\(\s*\)"),
        "Unbounded file read (no size limit)",
        "Pass a max size argument to .read(max_bytes) to prevent memory exhaustion.",
        "CWE-400",
        "LOW",
    ),
    # eval() or exec() calls
    (
        re.compile(r"(?<!\.)\beval\s*\(|(?<!\.)\bexec\s*\("),
        "Dynamic code execution via eval/exec",
        "Avoid eval/exec on user-controlled input. Use ast.literal_eval for safe parsing.",
        "CWE-95",
        "HIGH",
    ),
]


class ResourceSafetyScanner(BaseScanner):
    @property
    def name(self) -> str:
        return "Resource Safety"

    @property
    def category(self) -> str:
        return "resource-safety"

    def scan_file(self, file_path: str, content: str, lines: list[str]) -> list[Finding]:
        findings = []
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            for pattern, desc, remediation, cwe, severity in _PATTERNS:
                if pattern.search(stripped):
                    findings.append(Finding(
                        id="",
                        severity=severity,
                        category=self.category,
                        title=f"Resource safety: {desc.split('(')[0].strip()}",
                        file_path=file_path,
                        line_number=i,
                        code_snippet=stripped,
                        description=desc,
                        remediation=remediation,
                        cwe_id=cwe,
                    ))
                    break
        return findings
