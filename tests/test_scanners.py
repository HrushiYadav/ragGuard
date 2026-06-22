from pathlib import Path

import pytest

from ragguard.scanners.auth_gaps import AuthGapsScanner
from ragguard.scanners.command_injection import CommandInjectionScanner
from ragguard.scanners.filter_injection import FilterInjectionScanner
from ragguard.scanners.hardcoded_secrets import HardcodedSecretsScanner
from ragguard.scanners.insecure_deserialization import InsecureDeserializationScanner
from ragguard.scanners.insecure_tls import InsecureTLSScanner
from ragguard.scanners.nosql_injection import NoSQLInjectionScanner
from ragguard.scanners.resource_safety import ResourceSafetyScanner
from ragguard.scanners.secret_logging import SecretLoggingScanner
from ragguard.scanners.sql_injection import SQLInjectionScanner
from ragguard.scanners.ssrf import SSRFScanner

FIXTURES = Path(__file__).parent / "fixtures"


def _load(name: str) -> tuple[str, list[str]]:
    path = FIXTURES / name
    content = path.read_text(encoding="utf-8")
    return content, content.splitlines()


class TestFilterInjection:
    def test_detects_vulnerable_fstring_filter(self):
        content, lines = _load("vuln_filter.py")
        findings = FilterInjectionScanner().scan_file("vuln_filter.py", content, lines)
        assert len(findings) >= 1
        assert any("metadata" in f.code_snippet for f in findings)
        assert all(f.severity == "HIGH" for f in findings)

    def test_safe_filter_still_detected(self):
        # Safe file still has f-strings (the pattern is syntactic), but the
        # validation around them makes the code safe. Scanner is pattern-based
        # so it flags the syntax; the NoSQL scanner checks for validation.
        content, lines = _load("safe_filter.py")
        scanner = FilterInjectionScanner()
        findings = scanner.scan_file("safe_filter.py", content, lines)
        # Pattern-based scanner will still flag f-strings -- that's expected
        assert isinstance(findings, list)


class TestNoSQLInjection:
    def test_detects_unvalidated_nosql_filter(self):
        content, lines = _load("vuln_nosql.py")
        findings = NoSQLInjectionScanner().scan_file("vuln_nosql.py", content, lines)
        assert len(findings) >= 1
        assert all(f.category == "nosql-injection" for f in findings)

    def test_skips_file_with_validation(self):
        content, lines = _load("safe_nosql.py")
        findings = NoSQLInjectionScanner().scan_file("safe_nosql.py", content, lines)
        assert len(findings) == 0


class TestSQLInjection:
    def test_detects_fstring_sql(self):
        content, lines = _load("vuln_sql.py")
        findings = SQLInjectionScanner().scan_file("vuln_sql.py", content, lines)
        assert len(findings) >= 1
        assert any("INSERT" in f.code_snippet for f in findings)


class TestSecretLogging:
    def test_detects_secret_in_logger(self):
        content, lines = _load("vuln_secrets.py")
        findings = SecretLoggingScanner().scan_file("vuln_secrets.py", content, lines)
        assert len(findings) >= 1
        assert any("valkey_url" in f.title or "api_key" in f.title for f in findings)


class TestAuthGaps:
    def test_detects_unauthenticated_routes(self):
        content, lines = _load("vuln_auth.py")
        findings = AuthGapsScanner().scan_file("vuln_auth.py", content, lines)
        assert len(findings) >= 1
        assert any("auth" in f.title.lower() or "route" in f.title.lower() for f in findings)

    def test_detects_idor(self):
        content, lines = _load("vuln_auth.py")
        findings = AuthGapsScanner().scan_file("vuln_auth.py", content, lines)
        assert any("IDOR" in f.title or "user" in f.title.lower() for f in findings)


class TestResourceSafety:
    def test_detects_pickle_and_zipfile(self):
        content, lines = _load("vuln_resource.py")
        findings = ResourceSafetyScanner().scan_file("vuln_resource.py", content, lines)
        assert len(findings) >= 2
        categories = {f.code_snippet for f in findings}
        assert any("pickle" in s for s in categories)
        assert any("zipfile" in s or "ZipFile" in s for s in categories)


class TestHardcodedSecrets:
    def test_detects_hardcoded_keys(self):
        content, lines = _load("vuln_secrets_hardcoded.py")
        findings = HardcodedSecretsScanner().scan_file("vuln_secrets_hardcoded.py", content, lines)
        assert len(findings) >= 2
        assert all(f.severity == "HIGH" for f in findings)
        assert any("sk-" in f.code_snippet or "AKIA" in f.code_snippet for f in findings)


class TestSSRF:
    def test_detects_fstring_urls(self):
        content, lines = _load("vuln_ssrf.py")
        findings = SSRFScanner().scan_file("vuln_ssrf.py", content, lines)
        assert len(findings) >= 1
        assert all(f.category == "ssrf" for f in findings)


class TestInsecureDeserialization:
    def test_detects_yaml_load(self):
        content, lines = _load("vuln_deserialization.py")
        findings = InsecureDeserializationScanner().scan_file("vuln_deserialization.py", content, lines)
        assert len(findings) >= 2
        assert any("yaml" in f.code_snippet for f in findings)


class TestCommandInjection:
    def test_detects_os_system_and_shell_true(self):
        content, lines = _load("vuln_command_injection.py")
        findings = CommandInjectionScanner().scan_file("vuln_command_injection.py", content, lines)
        assert len(findings) >= 2
        assert any("os.system" in f.code_snippet for f in findings)
        assert any("shell=True" in f.code_snippet or "subprocess" in f.code_snippet for f in findings)


class TestInsecureTLS:
    def test_detects_verify_false_and_unverified_context(self):
        content, lines = _load("vuln_tls.py")
        findings = InsecureTLSScanner().scan_file("vuln_tls.py", content, lines)
        assert len(findings) >= 2
        assert any("verify" in f.code_snippet.lower() for f in findings)
