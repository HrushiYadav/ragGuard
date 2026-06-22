import html
from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Template

from ragguard.finding import Finding

_TEMPLATE_PATH = Path(__file__).parent / "template.html"


def write_html_report(findings: list[Finding], target: str, output_path: str) -> None:
    high = sum(1 for f in findings if f.severity == "HIGH")
    med = sum(1 for f in findings if f.severity == "MEDIUM")
    low = sum(1 for f in findings if f.severity == "LOW")
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    template_str = _TEMPLATE_PATH.read_text(encoding="utf-8")
    template = Template(template_str)

    rendered = template.render(
        target=html.escape(target),
        timestamp=timestamp,
        total=len(findings),
        high=high,
        medium=med,
        low=low,
        findings=findings,
    )

    with open(output_path, "w", encoding="utf-8") as fp:
        fp.write(rendered)
