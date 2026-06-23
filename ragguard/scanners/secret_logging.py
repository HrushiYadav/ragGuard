import ast
import re

from ragguard.finding import Finding
from ragguard.scanners.base import BaseScanner

_SECRET_NAMES = re.compile(
    r"password|secret|api_key|api_secret|token|private_key|credentials"
    r"|mongo_uri|valkey_url|redis_url|connection_string|conn_str|service_account_json",
    re.IGNORECASE,
)

_LOGGER_METHODS = {"debug", "info", "warning", "error", "critical", "exception", "log"}


def _is_logger_call(node: ast.Call) -> bool:
    if isinstance(node.func, ast.Attribute) and node.func.attr in _LOGGER_METHODS:
        if isinstance(node.func.value, ast.Name) and "log" in node.func.value.id.lower():
            return True
    return False


def _fstring_var_names(node: ast.JoinedStr) -> list[str]:
    names = []
    for val in node.values:
        if isinstance(val, ast.FormattedValue):
            if isinstance(val.value, ast.Name):
                names.append(val.value.id)
            elif isinstance(val.value, ast.Attribute):
                names.append(val.value.attr)
    return names


class SecretLoggingScanner(BaseScanner):
    @property
    def name(self) -> str:
        return "Secret Logging"

    @property
    def category(self) -> str:
        return "secret-logging"

    def scan_file(self, file_path: str, content: str, lines: list[str]) -> list[Finding]:
        try:
            tree = ast.parse(content)
        except SyntaxError:
            return []

        findings = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not _is_logger_call(node):
                continue

            for arg in node.args:
                if not isinstance(arg, ast.JoinedStr):
                    continue
                for var_name in _fstring_var_names(arg):
                    if _SECRET_NAMES.search(var_name):
                        snippet = lines[node.lineno - 1].strip() if node.lineno <= len(lines) else ""
                        findings.append(Finding(
                            id="",
                            severity="MEDIUM",
                            category=self.category,
                            title=f"Possible secret '{var_name}' in log output",
                            file_path=file_path,
                            line_number=node.lineno,
                            code_snippet=snippet,
                            description=f"Logger call references variable '{var_name}' "
                            "which may contain sensitive data.",
                            remediation="Mask or omit secrets from log messages. Use a redaction utility.",
                            cwe_id="CWE-532",
                        ))
                        break
        return findings
