import ast

from ragguard.finding import Finding
from ragguard.scanners.base import BaseScanner

_DANGEROUS_FUNCS = {
    "os": {"system", "popen"},
    "subprocess": {"call", "run", "Popen", "check_output", "check_call"},
}


def _is_dangerous_call(node: ast.Call) -> tuple[bool, str]:
    func = node.func
    if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
        if func.value.id in _DANGEROUS_FUNCS and func.attr in _DANGEROUS_FUNCS[func.value.id]:
            return True, f"{func.value.id}.{func.attr}"
    return False, ""


def _has_fstring_arg(node: ast.Call) -> bool:
    for arg in node.args:
        if isinstance(arg, ast.JoinedStr):
            return True
    return False


def _has_shell_true(node: ast.Call) -> bool:
    for kw in node.keywords:
        if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
            return True
    return False


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

        try:
            tree = ast.parse(content)
        except SyntaxError:
            return []

        findings = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            is_dangerous, func_name = _is_dangerous_call(node)
            if not is_dangerous:
                continue

            snippet = lines[node.lineno - 1].strip() if node.lineno <= len(lines) else ""

            if _has_fstring_arg(node):
                findings.append(Finding(
                    id="",
                    severity="HIGH",
                    category=self.category,
                    title=f"Command injection: {func_name}() with f-string argument",
                    file_path=file_path,
                    line_number=node.lineno,
                    code_snippet=snippet,
                    description=f"{func_name}() with f-string argument allows shell metacharacter injection.",
                    remediation="Use subprocess with a list of arguments instead of shell strings.",
                    cwe_id="CWE-78",
                ))
            elif func_name.startswith("subprocess.") and _has_shell_true(node):
                findings.append(Finding(
                    id="",
                    severity="MEDIUM",
                    category=self.category,
                    title=f"Command injection: {func_name}() with shell=True",
                    file_path=file_path,
                    line_number=node.lineno,
                    code_snippet=snippet,
                    description=f"{func_name}() called with shell=True enables shell injection "
                    "if input is not sanitized.",
                    remediation="Pass arguments as a list and remove shell=True.",
                    cwe_id="CWE-78",
                ))
        return findings
