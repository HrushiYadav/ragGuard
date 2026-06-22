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

ALL_SCANNERS = [
    FilterInjectionScanner,
    NoSQLInjectionScanner,
    SQLInjectionScanner,
    SecretLoggingScanner,
    AuthGapsScanner,
    ResourceSafetyScanner,
    HardcodedSecretsScanner,
    SSRFScanner,
    InsecureDeserializationScanner,
    CommandInjectionScanner,
    InsecureTLSScanner,
]

__all__ = [
    "ALL_SCANNERS",
    "FilterInjectionScanner",
    "NoSQLInjectionScanner",
    "SQLInjectionScanner",
    "SecretLoggingScanner",
    "AuthGapsScanner",
    "ResourceSafetyScanner",
    "HardcodedSecretsScanner",
    "SSRFScanner",
    "InsecureDeserializationScanner",
    "CommandInjectionScanner",
    "InsecureTLSScanner",
]
