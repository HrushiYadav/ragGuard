import re

from ragguard.finding import Finding
from ragguard.scanners.base import BaseScanner

_PATTERNS = [
    (
        re.compile(r"verify\s*=\s*False"),
        "TLS certificate verification disabled",
        "Enable TLS verification (remove verify=False) to prevent MITM attacks.",
        "CWE-295",
        "MEDIUM",
    ),
    (
        re.compile(r"ssl\._create_unverified_context"),
        "Unverified SSL context created",
        "Use ssl.create_default_context() instead of _create_unverified_context.",
        "CWE-295",
        "HIGH",
    ),
    (
        re.compile(r"CERT_NONE"),
        "SSL certificate validation set to CERT_NONE",
        "Use ssl.CERT_REQUIRED to validate server certificates.",
        "CWE-295",
        "HIGH",
    ),
    (
        re.compile(r"check_hostname\s*=\s*False"),
        "SSL hostname verification disabled",
        "Keep check_hostname=True to prevent MITM attacks.",
        "CWE-295",
        "MEDIUM",
    ),
]

_HTTP_URL = re.compile(r'''["']http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0|::1|\[::1\])''')


class InsecureTLSScanner(BaseScanner):
    @property
    def name(self) -> str:
        return "Insecure TLS"

    @property
    def category(self) -> str:
        return "insecure-tls"

    def scan_file(self, file_path: str, content: str, lines: list[str]) -> list[Finding]:
        if "test" in file_path.replace("\\", "/").split("/")[-1].lower():
            return []

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
                        title=f"Insecure TLS: {desc}",
                        file_path=file_path,
                        line_number=i,
                        code_snippet=stripped,
                        description=desc,
                        remediation=remediation,
                        cwe_id=cwe,
                    ))
                    break
            else:
                if _HTTP_URL.search(stripped):
                    findings.append(Finding(
                        id="",
                        severity="LOW",
                        category=self.category,
                        title="Insecure TLS: Plaintext HTTP URL",
                        file_path=file_path,
                        line_number=i,
                        code_snippet=stripped,
                        description="HTTP URL used instead of HTTPS, transmitting data in cleartext.",
                        remediation="Use HTTPS URLs for all non-local endpoints.",
                        cwe_id="CWE-319",
                    ))
        return findings
