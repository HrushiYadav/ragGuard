import os
from pathlib import Path

from ragguard.finding import Finding
from ragguard.scanners.base import BaseScanner


def discover_python_files(root: str) -> list[str]:
    files = []
    for dirpath, _, filenames in os.walk(root):
        if any(skip in dirpath for skip in ("__pycache__", ".git", "node_modules", ".venv", "venv")):
            continue
        for f in filenames:
            if f.endswith(".py"):
                files.append(os.path.join(dirpath, f))
    return sorted(files)


def run_scan(
    target: str,
    scanners: list[BaseScanner],
    severity_filter: str | None = None,
    category_filter: str | None = None,
) -> list[Finding]:
    root = os.path.abspath(target)
    files = discover_python_files(root)
    findings: list[Finding] = []
    counter = 1

    for file_path in files:
        try:
            content = Path(file_path).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        lines = content.splitlines()
        rel_path = os.path.relpath(file_path, root)

        for scanner in scanners:
            if category_filter and scanner.category != category_filter:
                continue

            for finding in scanner.scan_file(rel_path, content, lines):
                if severity_filter and finding.severity.lower() != severity_filter.lower():
                    continue
                finding.id = f"RG-{counter:03d}"
                counter += 1
                findings.append(finding)

    findings.sort(key=lambda f: ({"HIGH": 0, "MEDIUM": 1, "LOW": 2}.get(f.severity, 3), f.file_path, f.line_number))
    return findings
