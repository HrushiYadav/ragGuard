import ast
import re

from ragguard.finding import Finding
from ragguard.scanners.base import BaseScanner

_SQL_PATTERNS = [
    re.compile(r"\bINSERT\s+INTO\b", re.IGNORECASE),
    re.compile(r"\bSELECT\b.{0,30}\bFROM\b", re.IGNORECASE),
    re.compile(r"\bDELETE\s+FROM\b", re.IGNORECASE),
    re.compile(r"\bUPDATE\b.{0,30}\bSET\b", re.IGNORECASE),
    re.compile(r"\bDROP\s+TABLE\b", re.IGNORECASE),
    re.compile(r"\bCREATE\s+TABLE\b", re.IGNORECASE),
]


def _joinedstr_has_sql(node: ast.JoinedStr) -> bool:
    text_parts = []
    for val in node.values:
        if isinstance(val, ast.Constant) and isinstance(val.value, str):
            text_parts.append(val.value)
        else:
            text_parts.append("{}")
    combined = "".join(text_parts)
    return any(p.search(combined) for p in _SQL_PATTERNS)


def _is_execute_call(node: ast.Call) -> bool:
    if isinstance(node.func, ast.Attribute) and node.func.attr == "execute":
        return True
    return False


class SQLInjectionScanner(BaseScanner):
    @property
    def name(self) -> str:
        return "SQL Injection"

    @property
    def category(self) -> str:
        return "sql-injection"

    def scan_file(self, file_path: str, content: str, lines: list[str]) -> list[Finding]:
        try:
            tree = ast.parse(content)
        except SyntaxError:
            return []

        findings = []
        seen_lines: set[int] = set()

        for node in ast.walk(tree):
            # Detect execute(f"...") calls
            if isinstance(node, ast.Call) and _is_execute_call(node):
                for arg in node.args:
                    if isinstance(arg, ast.JoinedStr) and node.lineno not in seen_lines:
                        seen_lines.add(node.lineno)
                        snippet = lines[node.lineno - 1].strip() if node.lineno <= len(lines) else ""
                        findings.append(Finding(
                            id="",
                            severity="HIGH",
                            category=self.category,
                            title="SQL injection: SQL query built via f-string interpolation",
                            file_path=file_path,
                            line_number=node.lineno,
                            code_snippet=snippet,
                            description="SQL query constructed with f-string interpolation allows injection.",
                            remediation="Use parameterized queries with placeholders "
                            "instead of f-string interpolation.",
                            cwe_id="CWE-89",
                        ))
                        break

            # Detect f-strings with SQL keywords assigned to variables
            if isinstance(node, ast.JoinedStr) and _joinedstr_has_sql(node):
                if node.lineno not in seen_lines:
                    seen_lines.add(node.lineno)
                    snippet = lines[node.lineno - 1].strip() if node.lineno <= len(lines) else ""
                    findings.append(Finding(
                        id="",
                        severity="HIGH",
                        category=self.category,
                        title="SQL injection: SQL query built via f-string interpolation",
                        file_path=file_path,
                        line_number=node.lineno,
                        code_snippet=snippet,
                        description="SQL query constructed with f-string interpolation allows injection.",
                        remediation="Use parameterized queries with placeholders "
                        "instead of f-string interpolation.",
                        cwe_id="CWE-89",
                    ))
        return findings
