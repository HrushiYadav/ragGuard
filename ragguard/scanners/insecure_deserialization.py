import re

from ragguard.finding import Finding
from ragguard.scanners.base import BaseScanner

_PATTERNS = [
    (
        re.compile(r"yaml\.load\("),
        "yaml.load() without SafeLoader allows arbitrary code execution",
        "Use yaml.safe_load() or pass Loader=yaml.SafeLoader.",
    ),
    (
        re.compile(r"yaml\.unsafe_load\("),
        "yaml.unsafe_load() allows arbitrary code execution",
        "Use yaml.safe_load() instead.",
    ),
    (
        re.compile(r"marshal\.loads?\("),
        "marshal deserialization of untrusted data",
        "Avoid marshal for untrusted data. Use JSON or msgpack.",
    ),
    (
        re.compile(r"shelve\.open\("),
        "shelve uses pickle internally and is unsafe for untrusted data",
        "Use a database or JSON-based storage instead of shelve.",
    ),
    (
        re.compile(r"jsonpickle\.decode\("),
        "jsonpickle can execute arbitrary code during deserialization",
        "Use standard json.loads() for untrusted data.",
    ),
]

_SAFE_YAML = re.compile(r"Loader\s*=\s*(?:yaml\.)?(?:Safe|Full|Base)Loader|safe_load")


class InsecureDeserializationScanner(BaseScanner):
    @property
    def name(self) -> str:
        return "Insecure Deserialization"

    @property
    def category(self) -> str:
        return "insecure-deserialization"

    def scan_file(self, file_path: str, content: str, lines: list[str]) -> list[Finding]:
        findings = []
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            for pattern, desc, remediation in _PATTERNS:
                if pattern.search(stripped):
                    if "yaml.load" in stripped and _SAFE_YAML.search(stripped):
                        continue
                    findings.append(Finding(
                        id="",
                        severity="HIGH",
                        category=self.category,
                        title=f"Insecure deserialization: {desc.split('(')[0].strip()}",
                        file_path=file_path,
                        line_number=i,
                        code_snippet=stripped,
                        description=desc,
                        remediation=remediation,
                        cwe_id="CWE-502",
                    ))
                    break
        return findings
