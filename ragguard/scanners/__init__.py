from ragguard.scanners.auth_gaps import AuthGapsScanner
from ragguard.scanners.filter_injection import FilterInjectionScanner
from ragguard.scanners.nosql_injection import NoSQLInjectionScanner
from ragguard.scanners.resource_safety import ResourceSafetyScanner
from ragguard.scanners.secret_logging import SecretLoggingScanner
from ragguard.scanners.sql_injection import SQLInjectionScanner

ALL_SCANNERS = [
    FilterInjectionScanner,
    NoSQLInjectionScanner,
    SQLInjectionScanner,
    SecretLoggingScanner,
    AuthGapsScanner,
    ResourceSafetyScanner,
]

__all__ = [
    "ALL_SCANNERS",
    "FilterInjectionScanner",
    "NoSQLInjectionScanner",
    "SQLInjectionScanner",
    "SecretLoggingScanner",
    "AuthGapsScanner",
    "ResourceSafetyScanner",
]
