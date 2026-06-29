# RAGGuard

Static security scanner for RAG pipelines. Finds injection vulnerabilities, hardcoded secrets, auth gaps, and more in Python codebases.

Built from real-world security audits of production RAG frameworks.

[![PyPI](https://img.shields.io/pypi/v/ragsec)](https://pypi.org/project/ragsec/)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/pypi/pyversions/ragsec)](https://pypi.org/project/ragsec/)

## Install

```bash
pip install ragsec
```

Or from source:

```bash
git clone https://github.com/HrushiYadav/ragGuard.git
cd ragguard
pip install -e .
```

## Usage

```bash
# Terminal output (default)
ragguard scan ./path/to/codebase

# Generate reports
ragguard scan ./path/to/codebase --output report.md --format markdown
ragguard scan ./path/to/codebase --output report.html --format html
ragguard scan ./path/to/codebase --output report.sarif --format sarif

# Filter by severity or category
ragguard scan ./path/to/codebase --severity high
ragguard scan ./path/to/codebase --category filter-injection
```

## What it detects

11 scanners covering the most common vulnerability patterns in RAG/LLM codebases:

| Scanner | Severity | CWE | What it finds |
|---------|----------|-----|---------------|
| Filter Injection | HIGH | CWE-94 | f-string interpolation in Milvus, Valkey, Azure, Elasticsearch filter expressions |
| NoSQL Injection | HIGH | CWE-943 | Unvalidated dict values in MongoDB/Elasticsearch queries |
| SQL Injection | HIGH | CWE-89 | f-string SQL construction (INSERT, DELETE, SELECT, UPDATE) |
| Hardcoded Secrets | HIGH | CWE-798 | API keys (OpenAI, AWS, GitHub, GitLab, Slack), hardcoded passwords |
| SSRF | HIGH | CWE-918 | User-controlled URLs in requests, httpx, aiohttp, urllib |
| Insecure Deserialization | HIGH | CWE-502 | yaml.load without SafeLoader, marshal, jsonpickle, shelve |
| Command Injection | HIGH | CWE-78 | os.system/popen with f-strings, subprocess with shell=True |
| Secret Logging | MEDIUM | CWE-532 | API keys, passwords, connection strings in logger calls |
| Auth Gaps | MEDIUM | CWE-306 | FastAPI/Flask routes without auth (AST-based), client-controlled user IDs (IDOR) |
| Insecure TLS | MEDIUM | CWE-295 | verify=False, disabled certificate validation, cleartext HTTP |
| Resource Safety | MEDIUM-HIGH | CWE-502 | pickle deserialization, zip bombs, tar extraction, eval/exec |

## Example output

```
RAGGuard scanning ./my-rag-app

RG-001 [HIGH] Filter injection: Possible filter expression injection
  vector_stores/store.py:42
  > conditions.append(f'(metadata["{key}"] == "{value}")')

RG-002 [HIGH] NoSQL injection: Filter value passed into query
  vector_stores/mongo.py:89
  > filter_dict["payload." + key] = value

RG-003 [HIGH] Hardcoded secret: OpenAI API key
  config.py:12
  > OPENAI_KEY = "sk-proj-abc123..."

      Summary
+------------------+
| Severity | Count |
|----------+-------|
| HIGH     |    12 |
| MEDIUM   |     8 |
| LOW      |     5 |
| Total    |    25 |
+------------------+
```

## HTML Report

Generate a styled HTML report for sharing:

```bash
ragguard scan ./my-rag-app --output report.html --format html
```

Dark theme with severity badges, code snippets, and remediation guidance.

## SARIF Output

For CI/CD integration and GitHub Code Scanning:

```bash
ragguard scan ./my-rag-app --output report.sarif --format sarif
```

## Configuration

Create `ragguard.toml` (or `.ragguard.toml`) in your project root:

```toml
[ragguard]
ignore_paths = ["tests/", "migrations/"]
disable_scanners = ["secret-logging"]
min_severity = "MEDIUM"
```

| Option | Description |
|--------|-------------|
| `ignore_paths` | Path substrings to skip |
| `disable_scanners` | Scanner categories to disable |
| `min_severity` | Minimum severity to report (`HIGH`, `MEDIUM`, `LOW`) |

## Inline Suppression

Suppress a specific finding with an inline comment:

```python
api_key = os.environ.get("OPENAI_KEY", "sk-hardcoded")  # ragguard: ignore
```

## Development

```bash
pip install -e .
pytest tests/ -v
ruff check ragguard/
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for details on adding new scanners.

## License

[Apache-2.0](LICENSE)
