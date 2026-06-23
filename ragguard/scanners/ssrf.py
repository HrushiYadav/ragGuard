import ast

from ragguard.finding import Finding
from ragguard.scanners.base import BaseScanner

_HTTP_MODULES = {
    "requests": {"get", "post", "put", "delete", "patch", "head", "request"},
    "httpx": {"get", "post", "put", "delete", "patch", "head", "request"},
    "aiohttp": {"request", "get", "post", "put", "delete", "patch", "head"},
    "urllib": set(),
}

_URLLIB_FUNCS = {"urlopen", "Request"}


def _is_http_call(node: ast.Call) -> bool:
    func = node.func
    if isinstance(func, ast.Attribute):
        if isinstance(func.value, ast.Name) and func.value.id in _HTTP_MODULES:
            return func.attr in _HTTP_MODULES[func.value.id]
        if isinstance(func.value, ast.Attribute):
            if (
                isinstance(func.value.value, ast.Name)
                and func.value.value.id == "urllib"
                and func.value.attr == "request"
                and func.attr in _URLLIB_FUNCS
            ):
                return True
    return False


def _has_fstring_arg(node: ast.Call) -> bool:
    for arg in node.args:
        if isinstance(arg, ast.JoinedStr):
            return True
    for kw in node.keywords:
        if isinstance(kw.value, ast.JoinedStr):
            return True
    return False


class SSRFScanner(BaseScanner):
    @property
    def name(self) -> str:
        return "SSRF"

    @property
    def category(self) -> str:
        return "ssrf"

    def scan_file(self, file_path: str, content: str, lines: list[str]) -> list[Finding]:
        if "test" in file_path.replace("\\", "/").split("/")[-1].lower():
            return []

        try:
            tree = ast.parse(content)
        except SyntaxError:
            return []

        findings = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if _is_http_call(node) and _has_fstring_arg(node):
                snippet = lines[node.lineno - 1].strip() if node.lineno <= len(lines) else ""
                findings.append(Finding(
                    id="",
                    severity="HIGH",
                    category=self.category,
                    title="SSRF: HTTP request with f-string URL",
                    file_path=file_path,
                    line_number=node.lineno,
                    code_snippet=snippet,
                    description="URL constructed from dynamic input passed to HTTP client. "
                    "An attacker could redirect the request to internal services.",
                    remediation="Validate and allowlist URLs before making server-side requests.",
                    cwe_id="CWE-918",
                ))
        return findings
