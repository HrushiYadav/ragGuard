import re

from ragguard.finding import Finding
from ragguard.scanners.base import BaseScanner

_SECRET_VARS = re.compile(
    r"\b\w*(?:password|secret|api_key|api_secret|token|private_key|credentials"
    r"|mongo_uri|valkey_url|redis_url|connection_string|conn_str|service_account_json)\b",
    re.IGNORECASE,
)

_LOGGER_CALL = re.compile(r"logger\.\w+\(")

# Connection strings with embedded credentials: scheme://user:pass@host
_CONN_STRING_IN_FSTRING = re.compile(r'''f["'].*://.*\{.*\}.*@|f["'].*\{.*url.*\}''', re.IGNORECASE)


class SecretLoggingScanner(BaseScanner):
    @property
    def name(self) -> str:
        return "Secret Logging"

    @property
    def category(self) -> str:
        return "secret-logging"

    def scan_file(self, file_path: str, content: str, lines: list[str]) -> list[Finding]:
        findings = []
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            if not _LOGGER_CALL.search(stripped):
                continue

            if _SECRET_VARS.search(stripped):
                var_match = _SECRET_VARS.search(stripped)
                var_name = var_match.group(0) if var_match else "secret"
                findings.append(Finding(
                    id="",
                    severity="MEDIUM",
                    category=self.category,
                    title=f"Possible secret '{var_name}' in log output",
                    file_path=file_path,
                    line_number=i,
                    code_snippet=stripped,
                    description=f"Logger call references variable '{var_name}' which may contain sensitive data.",
                    remediation="Mask or omit secrets from log messages. Use a redaction utility.",
                    cwe_id="CWE-532",
                ))
            elif _CONN_STRING_IN_FSTRING.search(stripped):
                findings.append(Finding(
                    id="",
                    severity="MEDIUM",
                    category=self.category,
                    title="Connection string with credentials in log output",
                    file_path=file_path,
                    line_number=i,
                    code_snippet=stripped,
                    description="Logger call includes a connection URL that may contain embedded credentials.",
                    remediation="Redact credentials from connection strings before logging.",
                    cwe_id="CWE-532",
                ))
        return findings
