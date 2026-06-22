import re

from ragguard.finding import Finding
from ragguard.scanners.base import BaseScanner

_FSTRING_PATTERNS = [
    (
        re.compile(r'''os\.system\(\s*f["']'''),
        "os.system() with f-string argument",
    ),
    (
        re.compile(r'''os\.popen\(\s*f["']'''),
        "os.popen() with f-string argument",
    ),
    (
        re.compile(r'''subprocess\.(?:call|run|Popen|check_output|check_call)\(\s*f["']'''),
        "subprocess call with f-string argument",
    ),
]

_SHELL_TRUE = re.compile(r"subprocess\.(?:call|run|Popen|check_output|check_call)\(.*shell\s*=\s*True")


class CommandInjectionScanner(BaseScanner):
    @property
    def name(self) -> str:
        return "Command Injection"

    @property
    def category(self) -> str:
        return "command-injection"

    def scan_file(self, file_path: str, content: str, lines: list[str]) -> list[Finding]:
        if "test" in file_path.replace("\\", "/").split("/")[-1].lower():
            return []

        findings = []
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            for pattern, desc in _FSTRING_PATTERNS:
                if pattern.search(stripped):
                    findings.append(Finding(
                        id="",
                        severity="HIGH",
                        category=self.category,
                        title=f"Command injection: {desc}",
                        file_path=file_path,
                        line_number=i,
                        code_snippet=stripped,
                        description=f"{desc} allows shell metacharacter injection.",
                        remediation="Use subprocess with a list of arguments instead of shell strings.",
                        cwe_id="CWE-78",
                    ))
                    break
            else:
                if _SHELL_TRUE.search(stripped):
                    findings.append(Finding(
                        id="",
                        severity="MEDIUM",
                        category=self.category,
                        title="Command injection: subprocess with shell=True",
                        file_path=file_path,
                        line_number=i,
                        code_snippet=stripped,
                        description="subprocess called with shell=True enables shell injection "
                        "if input is not sanitized.",
                        remediation="Pass arguments as a list and remove shell=True.",
                        cwe_id="CWE-78",
                    ))
        return findings
