import ast
import re

from ragguard.finding import Finding
from ragguard.scanners.base import BaseScanner

_ROUTE_METHODS = {"get", "post", "put", "delete", "patch"}

_AUTH_KEYWORDS = re.compile(
    r"auth|verify|current_user|Security|HTTPBearer|OAuth2|api_key|require_auth|login_required|authenticated",
    re.IGNORECASE,
)

_IDOR_PATTERN = re.compile(r"(?:body|request|payload|data)\.\w*(?:user_id|org_id|tenant_id)")


def _is_route_decorator(node: ast.expr) -> bool:
    if isinstance(node, ast.Call):
        node = node.func
    if isinstance(node, ast.Attribute) and node.attr in _ROUTE_METHODS:
        return True
    return False


def _decorator_source(node: ast.expr) -> str:
    return ast.dump(node)


def _has_auth_in_decorators(decorators: list[ast.expr]) -> bool:
    for dec in decorators:
        source = _decorator_source(dec)
        if _AUTH_KEYWORDS.search(source):
            return True
    return False


def _has_auth_in_args(func_node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    for arg in func_node.args.args:
        if arg.annotation and _AUTH_KEYWORDS.search(ast.dump(arg.annotation)):
            return True
    for default in func_node.args.defaults:
        if _AUTH_KEYWORDS.search(ast.dump(default)):
            return True
    for default in func_node.args.kw_defaults:
        if default and _AUTH_KEYWORDS.search(ast.dump(default)):
            return True
    return False


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

        try:
            tree = ast.parse(content)
        except SyntaxError:
            return []

        findings = []

        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue

            route_decorator = None
            for dec in node.decorator_list:
                if _is_route_decorator(dec):
                    route_decorator = dec
                    break

            if route_decorator is None:
                continue

            if not _has_auth_in_decorators(node.decorator_list) and not _has_auth_in_args(node):
                line_num = route_decorator.lineno
                snippet = lines[line_num - 1].strip() if line_num <= len(lines) else ""
                findings.append(Finding(
                    id="",
                    severity="MEDIUM",
                    category=self.category,
                    title="API route without authentication middleware",
                    file_path=file_path,
                    line_number=line_num,
                    code_snippet=snippet,
                    description="This API endpoint has no visible authentication dependency. "
                    "Any caller can access it.",
                    remediation="Add authentication middleware "
                    "(e.g., Depends(verify_token)) to protect this endpoint.",
                    cwe_id="CWE-306",
                ))

        # IDOR check stays regex-based (per-line)
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
                    remediation="Derive user_id from the authenticated session/token, "
                    "not from the request body.",
                    cwe_id="CWE-639",
                ))

        return findings
