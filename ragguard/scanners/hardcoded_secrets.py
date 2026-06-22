import re

from ragguard.finding import Finding
from ragguard.scanners.base import BaseScanner

_PATTERNS = [
    (re.compile(r'sk-[a-zA-Z0-9]{20,}'), "OpenAI API key"),
    (re.compile(r'AKIA[A-Z0-9]{16}'), "AWS access key ID"),
    (re.compile(r'ghp_[a-zA-Z0-9]{36}'), "GitHub personal access token"),
    (re.compile(r'gho_[a-zA-Z0-9]{36}'), "GitHub OAuth token"),
    (re.compile(r'glpat-[a-zA-Z0-9\-]{20,}'), "GitLab personal access token"),
    (re.compile(r'xox[bpors]-[a-zA-Z0-9\-]{10,}'), "Slack token"),
]

_ASSIGNMENT_PATTERNS = [
    (
        re.compile(r'''(?:password|passwd|pwd)\s*=\s*["']([^"']{3,})["']''', re.IGNORECASE),
        "Hardcoded password",
    ),
    (
        re.compile(r'''(?:api_key|apikey|api_secret)\s*=\s*["']([^"']{8,})["']''', re.IGNORECASE),
        "Hardcoded API key",
    ),
    (
        re.compile(r'''(?:secret_key|secret)\s*=\s*["']([^"']{8,})["']''', re.IGNORECASE),
        "Hardcoded secret",
    ),
]

_SKIP_VALUES = {"none", "null", "true", "false", "test", "example", "changeme", "xxx", "todo", "placeholder"}

_SAFE_CONTEXT = re.compile(r"os\.environ|os\.getenv|environ\.get|Field\(|Optional\[|description=|help=")


class HardcodedSecretsScanner(BaseScanner):
    @property
    def name(self) -> str:
        return "Hardcoded Secrets"

    @property
    def category(self) -> str:
        return "hardcoded-secrets"

    def scan_file(self, file_path: str, content: str, lines: list[str]) -> list[Finding]:
        if "test" in file_path.replace("\\", "/").split("/")[-1].lower():
            return []

        findings = []
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if _SAFE_CONTEXT.search(stripped):
                continue

            for pattern, desc in _PATTERNS:
                if pattern.search(stripped):
                    findings.append(Finding(
                        id="",
                        severity="HIGH",
                        category=self.category,
                        title=f"Hardcoded secret: {desc}",
                        file_path=file_path,
                        line_number=i,
                        code_snippet=stripped,
                        description=f"{desc} found in source code.",
                        remediation="Use environment variables or a secrets manager instead of hardcoding credentials.",
                        cwe_id="CWE-798",
                    ))
                    break
            else:
                for pattern, desc in _ASSIGNMENT_PATTERNS:
                    m = pattern.search(stripped)
                    if m and m.group(1).lower() not in _SKIP_VALUES:
                        findings.append(Finding(
                            id="",
                            severity="HIGH",
                            category=self.category,
                            title=f"Hardcoded secret: {desc}",
                            file_path=file_path,
                            line_number=i,
                            code_snippet=stripped,
                            description=f"{desc} assigned as a string literal.",
                            remediation="Use environment variables or a secrets manager "
                            "instead of hardcoding credentials.",
                            cwe_id="CWE-798",
                        ))
                        break
        return findings
