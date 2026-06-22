# Contributing to RAGGuard

Thanks for your interest in contributing to RAGGuard! This guide covers everything you need to get started.

## Setup

```bash
git clone https://github.com/HrushiYadav/ragGuard.git
cd ragguard
pip install -e .
```

## Running tests

```bash
pytest tests/ -v
```

## Linting

```bash
ruff check ragguard/
```

## Adding a new scanner

RAGGuard uses a plugin-based scanner architecture. Each scanner extends `BaseScanner` and implements three things:

1. `name` property - human-readable name
2. `category` property - kebab-case identifier (e.g. `"sql-injection"`)
3. `scan_file(file_path, content, lines)` - returns a list of `Finding` objects

### Steps

1. Create `ragguard/scanners/your_scanner.py`
2. Extend `BaseScanner` and implement the three required members
3. Add your scanner to `ALL_SCANNERS` in `ragguard/scanners/__init__.py`
4. Create a test fixture at `tests/fixtures/vuln_your_scanner.py` with vulnerable code samples
5. Add test cases in `tests/test_scanners.py`
6. Run `pytest tests/ -v` and `ruff check ragguard/` before submitting

### Scanner template

```python
import re
from ragguard.finding import Finding
from ragguard.scanners.base import BaseScanner

class YourScanner(BaseScanner):
    @property
    def name(self) -> str:
        return "Your Scanner Name"

    @property
    def category(self) -> str:
        return "your-category"

    def scan_file(self, file_path: str, content: str, lines: list[str]) -> list[Finding]:
        findings = []
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            # your detection logic here
        return findings
```

## Pull requests

- One scanner or fix per PR
- Include test fixtures that demonstrate the vulnerability pattern
- Make sure all tests pass and ruff reports no issues
- Keep patterns focused on real-world RAG/LLM codebases

## Reporting issues

Open an issue on GitHub with:
- What you expected
- What happened instead
- Steps to reproduce (if applicable)
