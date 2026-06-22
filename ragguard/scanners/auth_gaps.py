import re

from ragguard.finding import Finding
from ragguard.scanners.base import BaseScanner

# FastAPI route decorators
_ROUTE_DECORATOR = re.compile(r"@\w+\.(get|post|put|delete|patch)\(")

# Auth-related patterns that indicate authorization is present
_AUTH_PATTERNS = re.compile(
    r"Depends\(.*auth|Depends\(.*verify|Depends\(.*current_user"
    r"|Security\(|HTTPBearer|OAuth2|api_key.*Header"
    r"|@require_auth|@login_required|@authenticated",
    re.IGNORECASE,
)

# Client-controlled ID in request body (IDOR risk)
_IDOR_PATTERN = re.compile(r"(?:body|request|payload|data)\.\w*(?:user_id|org_id|tenant_id)")


class AuthGapsScanner(BaseScanner):
    @property
    def name(self) -> str:
        return "Auth Gaps"

    @property
    def category(self) -> str:
        return "auth-gaps"

    def scan_file(self, file_path: str, content: str, lines: list[str]) -> list[Finding]:
        if "test" in file_path.replace("\\", "/").split("/")[-1].lower():
            return []

        findings = []

        # Check for FastAPI routes without auth
        has_any_auth = bool(_AUTH_PATTERNS.search(content))
        route_lines = []
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if _ROUTE_DECORATOR.search(stripped) and not stripped.startswith("@mock"):
                route_lines.append((i, stripped))

        if route_lines and not has_any_auth:
            for line_num, snippet in route_lines:
                findings.append(Finding(
                    id="",
                    severity="MEDIUM",
                    category=self.category,
                    title="API route without authentication middleware",
                    file_path=file_path,
                    line_number=line_num,
                    code_snippet=snippet,
                    description="This API endpoint has no visible authentication dependency. Any caller can access it.",
                    remediation="Add authentication middleware (e.g., Depends(verify_token)) to protect this endpoint.",
                    cwe_id="CWE-306",
                ))

        # Check for client-controlled user_id (IDOR)
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if _IDOR_PATTERN.search(stripped):
                findings.append(Finding(
                    id="",
                    severity="MEDIUM",
                    category=self.category,
                    title="Client-controlled user/tenant ID (potential IDOR)",
                    file_path=file_path,
                    line_number=i,
                    code_snippet=stripped,
                    description="User/tenant ID is taken from the request body, "
                    "allowing clients to impersonate other users.",
                    remediation="Derive user_id from the authenticated session/token, not from the request body.",
                    cwe_id="CWE-639",
                ))

        return findings
