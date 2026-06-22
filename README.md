# RAGGuard

Static security scanner for RAG pipelines. Finds injection vulnerabilities, secret logging, auth gaps, and resource safety issues in Python codebases.

Built from real-world security audits of production RAG frameworks.

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

# Filter by severity or category
ragguard scan ./path/to/codebase --severity high
ragguard scan ./path/to/codebase --category filter-injection
```

## What it detects

| Scanner | Severity | What it finds |
|---------|----------|---------------|
| Filter Injection | HIGH | f-string interpolation in Milvus, Valkey, Azure, Elasticsearch filter expressions |
| NoSQL Injection | HIGH | Unvalidated dict values in MongoDB/Elasticsearch queries |
| SQL Injection | HIGH | f-string SQL construction (INSERT, DELETE, SELECT, UPDATE) |
| Secret Logging | MEDIUM | API keys, passwords, connection strings in logger calls |
| Auth Gaps | MEDIUM | FastAPI/Flask routes without auth, client-controlled user IDs (IDOR) |
| Resource Safety | HIGH/MEDIUM/LOW | pickle deserialization, zip bombs, eval/exec, unbounded reads |

## Example output

```
RAGGuard scanning ./my-rag-app

RG-001 [HIGH] Filter injection: Possible filter expression injection
  vector_stores/store.py:42
  > conditions.append(f'(metadata["{key}"] == "{value}")')

RG-002 [HIGH] NoSQL injection: Filter value passed into query
  vector_stores/mongo.py:89
  > filter_dict["payload." + key] = value

      Summary
+------------------+
| Severity | Count |
|----------+-------|
| HIGH     |     5 |
| MEDIUM   |     8 |
| LOW      |     3 |
| Total    |    16 |
+------------------+
```

## HTML Report

Generate a styled HTML report for sharing:

```bash
ragguard scan ./my-rag-app --output report.html --format html
```

Dark theme with severity badges, code snippets, and remediation guidance.

## Development

```bash
pip install -e .
pytest tests/ -v
ruff check ragguard/
```

## License

Apache-2.0
